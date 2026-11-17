// Establish only the known G1A entry. No guessed pointer relocation.
// @category Fx9860
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class PrepareG1a extends GhidraScript {
    @Override public void run() throws Exception {
        Address base=toAddr(0x00300000L), entry=toAddr(0x00300200L);
        MemoryBlock first=currentProgram.getMemory().getBlock(base);
        if(first==null || !first.contains(entry)) throw new IllegalArgumentException("Missing complete G1A image");
        currentProgram.getMemory().split(first,entry);
        first.setName("g1a_header"); first.setExecute(false); first.setWrite(false);
        MemoryBlock code=currentProgram.getMemory().getBlock(entry);
        code.setName("g1a_image");code.setRead(true);code.setExecute(true);code.setWrite(false);
        currentProgram.getSymbolTable().createLabel(entry,"g1a_entry",SourceType.USER_DEFINED);
        currentProgram.getSymbolTable().addExternalEntryPoint(entry);
        disassemble(entry);createFunction(entry,"g1a_entry");
        println("Prepared G1A at 00300000, entry 00300200; header excluded from execution.");
    }
}
