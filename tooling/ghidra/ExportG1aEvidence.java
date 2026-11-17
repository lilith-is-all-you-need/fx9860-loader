// Bounded, SHA-bound evidence. Not a proof of complete binary compatibility.
// @category Fx9860
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class ExportG1aEvidence extends HeadlessScript {
    private String hex(long n) { return String.format("%08X",n & 0xffffffffL); }
    private String kind(long n,long end) {
        n&=0xffffffffL;
        if(n==0x80010070L)return "syscall-gate";
        if(n>=0x00300000L && n<end)return "image-address-candidate";
        if(n>=0x08100000L && n<0x08120000L)return "virtual-ram-candidate";
        if((n>=0x88000000L&&n<0x88080000L)||(n>=0xa8000000L&&n<0xa8080000L))return "physical-ram-alias-candidate";
        if(n>=0xff000000L || (n>=0xa4000000L&&n<0xa5000000L))return "hardware-register-candidate";
        if(n==0xa0000000L)return "reset-vector-candidate";
        return null;
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs(); if(args.length!=2)throw new IllegalArgumentException("Expected output JSON and image length");
        Map<String,Object> root=new LinkedHashMap<>();
        int length=Integer.parseInt(args[1]);
        if(length<516 || length>4*1024*1024)throw new IllegalArgumentException("Invalid image length");
        byte[] data=new byte[length];
        if(currentProgram.getMemory().getBytes(toAddr(0x300000L),data)!=length)throw new IllegalStateException("Incomplete image");
        byte[] hash=MessageDigest.getInstance("SHA-256").digest(data);StringBuilder digest=new StringBuilder();
        for(byte b:hash)digest.append(String.format("%02x",b&255));
        root.put("schemaVersion",1);root.put("kind","ghidra-analysis-evidence");root.put("inputSha256",digest.toString());
        root.put("language",currentProgram.getLanguageID().toString());root.put("imageBytes",data.length);
        root.put("imageBase",0x300000);root.put("entry",0x300200);root.put("executableProfile",false);
        List<Object> constants=new ArrayList<>(),control=new ArrayList<>(),functions=new ArrayList<>(),decompiled=new ArrayList<>();
        long end=0x300000L+data.length;int instructions=0,constantCount=0,controlCount=0;
        var iterator=currentProgram.getListing().getInstructions(true);
        while(iterator.hasNext()) {
            monitor.checkCancelled();Instruction ins=iterator.next();instructions++;
            for(int op=0;op<ins.getNumOperands();op++)for(Object obj:ins.getOpObjects(op))if(obj instanceof Scalar scalar) {
                long value=scalar.getUnsignedValue();String k=kind(value,end);
                if(k!=null){constantCount++;if(constants.size()<8192)constants.add(Map.of("instruction",ins.getAddress().toString(),"text",ins.toString(),"value",hex(value),"classification",k));}
            }
            if(ins.getFlowType().isComputed() || ins.getMnemonicString().equalsIgnoreCase("ldc") || ins.getMnemonicString().equalsIgnoreCase("rte")) {
                controlCount++;if(control.size()<4096)control.add(Map.of("address",ins.getAddress().toString(),"instruction",ins.toString(),"computed",ins.getFlowType().isComputed()));
            }
        }
        List<Object> pools=new ArrayList<>();int poolCount=0;
        for(int off=512;off+4<=data.length;off+=4) {
            long n=((data[off]&255L)<<24)|((data[off+1]&255L)<<16)|((data[off+2]&255L)<<8)|(data[off+3]&255L);
            String k=kind(n,end);if(k==null)continue;poolCount++;
            if(pools.size()>=8192)continue;
            Address a=toAddr(0x300000L+off);List<Object> uses=new ArrayList<>();
            for(Reference ref:currentProgram.getReferenceManager().getReferencesTo(a)){
                if(uses.size()>=24)break;
                Instruction ins=currentProgram.getListing().getInstructionAt(ref.getFromAddress());
                uses.add(Map.of("from",ref.getFromAddress().toString(),"type",ref.getReferenceType().toString(),"instruction",ins==null?"":ins.toString()));
            }
            pools.add(Map.of("offset",off,"address",a.toString(),"value",hex(n),"classification",k,"references",uses,
                "warning","Numeric range and recovered references are evidence, not a relocation rule"));
        }
        var funcs=currentProgram.getFunctionManager().getFunctions(true);List<Function> selected=new ArrayList<>();
        while(funcs.hasNext()){
            monitor.checkCancelled();Function f=funcs.next();
            if(functions.size()<4096)functions.add(Map.of("entry",f.getEntryPoint().toString(),"name",f.getName(),"bytes",f.getBody().getNumAddresses()));
            if(selected.size()<24)selected.add(f);
        }
        DecompInterface dec=new DecompInterface();
        try {
            dec.openProgram(currentProgram);
            for(Function f:selected){monitor.checkCancelled();DecompileResults r=dec.decompileFunction(f,3,monitor);
                if(r.decompileCompleted()){
                    String c=r.getDecompiledFunction().getC();decompiled.add(Map.of("entry",f.getEntryPoint().toString(),"name",f.getName(),"c",c.substring(0,Math.min(c.length(),16000)),"truncated",c.length()>16000));
                }else decompiled.add(Map.of("entry",f.getEntryPoint().toString(),"error",r.getErrorMessage()));
            }
        } finally { dec.dispose(); }
        root.put("instructionCount",instructions);root.put("functionCount",currentProgram.getFunctionManager().getFunctionCount());
        root.put("functions",functions);root.put("constantOperands",constants);root.put("constantOperandCount",constantCount);
        root.put("candidateLiteralPools",pools);root.put("candidateLiteralCount",poolCount);
        root.put("controlFlowSites",control);root.put("controlFlowSiteCount",controlCount);root.put("decompilationSamples",decompiled);
        root.put("analysisComplete",!analysisTimeoutOccurred());
        root.put("limits",List.of("Indirect targets and code/data separation can remain unresolved","Only up to 24 functions are decompiled; arrays are bounded","This report never authorizes new relocation or runtime patches"));
        Files.writeString(Path.of(args[0]),new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(root),StandardCharsets.UTF_8);
        println("Evidence exported: "+instructions+" instructions, "+currentProgram.getFunctionManager().getFunctionCount()+" functions.");
    }
}
