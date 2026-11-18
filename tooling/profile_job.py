"""Desktop job protocol. Analysis evidence never upgrades an unsupported runtime.

Uses a bounded immutable input snapshot and publishes a new result directory once.
The Ghidra launcher uses Java argv directly, never a shell or a user-named script.
"""
import argparse, copy, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import loader_suite as suite
import bundle_v2
import hook_review

ROOT=Path(__file__).resolve().parents[1]
PAGE=4096

def engine_contract_sha():
 h=hashlib.sha256()
 for relative in ('tooling/profile_job.py','tooling/bundle_v2.py','tooling/loader_suite.py',
                  'tooling/ext_profile.py','tooling/hook_review.py','profiles/registry.json',
                  'probes/storage-loader/tools/prepare.py','probes/mapped-loader/tools/prepare.py',
                  'probes/native-loader/tools/prepare.py','tooling/ghidra/ExportG1aEvidence.java','tooling/ghidra/PrepareG1a.java'):
  h.update(relative.encode('utf-8'));h.update((ROOT/relative).read_bytes().replace(b'\r\n',b'\n'))
 return h.hexdigest()

def verify_reuse(output,data,initial,artifacts,include_loader,deep):
 sums=json.loads((output/'checksums.json').read_text('utf-8'))
 actual={p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()
         and p.name!='checksums.json' and ('ghidra' not in p.relative_to(output).parts or p.name=='evidence.json')}
 if not isinstance(sums,dict) or set(sums)!=actual:
  raise ValueError('Existing result manifest is incomplete / 现有结果校验清单不完整。')
 required={'analysis.json','paging-plan.json','job-result.json','original.bin','阅读说明.txt'}
 if deep:required|={'ghidra/evidence.json','hook-review.json'}
 # Recreate immutable calculator members using today's checked rules. A
 # modified/empty checksum list cannot turn a missing profile into a ready job.
 with tempfile.TemporaryDirectory(prefix='.fxverify-') as temporary:
  expected=Path(temporary);(expected/'original.bin').write_bytes(data)
  fresh=bundle_v2.prepare(data,copy.deepcopy(initial),expected,suite,artifacts,include_loader)
  for name in ('job-result.json','analysis.json'):
   saved_report=json.loads((output/name).read_text('utf-8'))
   for key in ('sha256','backend','status','blockers','programReady','includesLoader'):
    if saved_report.get(key)!=fresh.get(key):
     raise ValueError('Saved result differs from current preparation: '+key)
  for member in expected.rglob('*'):
   if not member.is_file():continue
   name=member.relative_to(expected).as_posix();required.add(name)
   saved=(output/name).resolve()
   if not saved.is_relative_to(output) or not saved.is_file() or saved.read_bytes()!=member.read_bytes():
    raise ValueError('Existing result differs from current preparation: '+name)
 if not required<=set(sums):raise ValueError('Required program files are missing / 缺少必要程序文件。')
 for name,expected in sums.items():
  member=(output/name).resolve()
  if not member.is_relative_to(output) or not member.is_file() or suite.sha(member.read_bytes())!=expected:
   raise ValueError('Existing result was changed; select a new output root / 现有结果已更改，请选新保存位置。')

def emit(phase,message,**fields):
 print(json.dumps({'phase':phase,'message':message,**fields},ensure_ascii=False),flush=True)

def write(path,data):
 path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

def job_diagnostics(report):
 scan=report.get('staticAnalysis',{})
 items=[]
 def add(code,zh,en,next_zh,next_en,**evidence):
  items.append(dict(code=code,reasonZh=zh,reasonEn=en,nextZh=next_zh,nextEn=next_en,evidence=evidence))
 def offsets(values):
  return ', '.join(f'0x{x:X}' for x in values[:8])+(' …' if len(values)>8 else '')
 for blocker in report['blockers']:
  reads=scan.get('romSignatureReads',[])
  if blocker.startswith('unclassified syscall gate literals:') and ('unclassifiedGateLiterals' in scan or reads):
   if reads:
    sites=offsets([r['instructionOffset'] for r in reads])
    pools=offsets(sorted({r['literalOffset'] for r in reads}))
    add('rom-signature-read',
        f'文件偏移 {sites} 的代码通过常量 {pools} 读取系统调用入口的指令字节，并核对固件签名。通用 Loader 只支持已识别的调用方式。',
        f'Code at file offset {sites} uses the literal at {pools} to read instruction bytes at the system call entry and check the firmware signature. This use is outside the generic Loader’s supported call patterns.',
        '在反汇编中复核签名匹配后的固件访问及返回路径。该程序需要经过验证的适配才能打包。',
        'Review the firmware access and return path following the signature check. Packaging requires a validated adapter.',
        reads=reads)
   unknown=sorted(set(scan.get('unclassifiedGateLiterals',[]))-{r['literalOffset'] for r in reads})
   if unknown:
    sites=offsets(unknown)
    add('unknown-gate-use',
        f'文件偏移 {sites} 的值与系统调用入口地址相同，当前规则无法确定它的用途。',
        f'The value at file offset(s) {sites} matches the system call entry address. Its use is unclassified.',
        '在反汇编中检查这些常量的引用，区分调用入口、数据读取和普通数据后，再选择适配方式。',
        'Inspect references to these literals and distinguish calls, reads and ordinary data before selecting an adapter.',
        literalOffsets=unknown)
  elif 'Direct reset/' in blocker and scan.get('unadaptedControlTransfers'):
   transfers=scan['unadaptedControlTransfers']
   starts=offsets([t['instructionOffset'] for t in transfers])
   sites=offsets([t['jumpOffset'] for t in transfers])
   dest=offsets(sorted({t['destination'] for t in transfers}))
   add('direct-reset-transfer',
       f'文件偏移 {starts} 载入地址，{sites} 的指令直接跳到启动 ROM 地址 {dest}。走到这里可能重启计算器，Loader 无法按正常退出流程恢复调用方。',
       f'Code at file offset {starts} loads the address, and the instruction at {sites} jumps directly to boot ROM at {dest}. Taking this path can restart the calculator and bypass return to the caller.',
       '这个版本需要能处理该退出路径的适配，之后再验证退出和 MENU 返回。Ghidra 可帮助定位跳转的调用来源。',
       'This version needs an adapter for this exit path. Use Ghidra to inspect callers, then verify exit and MENU return with the adapter.',
       transfers=transfers)
  elif blocker.startswith('Requires guest-owned'):
   add('extended-runtime-required',
       f'文件共 {report["pages"]} 页，超过系统窗口的 512 页；当前构建未声明受支持的大程序运行库。',
       f'The image has {report["pages"]} pages and exceeds the 512-page OS window. This build has no supported large-program runtime contract.',
       '有源码时可接入大程序运行库并重新构建；已有二进制需要单独的运行时适配。',
       'Integrate the large-program runtime and rebuild from source, or provide a runtime adapter for the existing binary.')
  elif blocker.startswith('no recognized syscall gate'):
   add('no-recognized-gate','当前扫描未识别到可用于通用 Loader 的系统调用入口。',
       'The scan found no recognized system call gateway for the generic Loader.',
       '检查程序是否使用其他调用方式；需要验证该调用约定后才能生成 Profile。',
       'Inspect how the program calls the OS and validate its calling convention before preparing a profile.')
  else:
   add('runtime-review','检查项未通过。'+blocker,blocker,
       '查看 analysis.json 中对应的检查项及选用的 Loader。以该输入的 SHA-256 记录复核结果。',
       'Inspect the corresponding check and selected Loader in analysis.json. Record the review against this input’s SHA-256.')
 ranges = report.get('ramPlacement', {}).get('forbiddenPhysicalRam', [])
 if ranges and not report['blockers']:
  addresses = ', '.join(f'[0x{lo:08X}, 0x{hi:08X})' for lo, hi in ranges)
  add('device-ram-placement', '程序占用的 RAM 范围为 '+addresses+'。',
      'Reserved guest RAM: '+addresses+'.',
      'FlashLd 首先请求一个连续块。遇到重叠时再向 OS 请求其他位置，结果写入 RUN.LOG。',
      'FlashLd requests one contiguous block and asks the OS for alternatives on overlap. See RUN.LOG for the result.',
      forbiddenPhysicalRam=ranges)
 return items

def attach_ghidra_refs(items,evidence):
 """Join only exported references to the actual disputed literals."""
 pools={p['offset']:p for p in evidence.get('candidateLiteralPools',[]) if 'offset' in p}
 flow={s['fileOffset']:s for s in evidence.get('controlFlowSites',[]) if 'fileOffset' in s}
 for d in items:
  detail=d['evidence']
  offsets=set(detail.get('literalOffsets',[]))
  offsets.update(r['literalOffset'] for r in detail.get('reads',[]))
  offsets.update(r['literalOffset'] for r in detail.get('transfers',[]))
  if not offsets:continue
  exported=[{'literalOffset':offset,'references':pools[offset].get('references',[])}
            for offset in sorted(offsets) if offset in pools]
  detail['ghidraLiteralReferences']=exported
  count=sum(len(p['references']) for p in exported)
  if count:
   d['reasonZh']+=f' 本次 Ghidra 报告记录了指向相关常量的 {count} 条引用。'
   d['reasonEn']+=f' Ghidra references to the affected literals: {count}.'
  else:
   d['reasonZh']+=' 本次 Ghidra 导出未覆盖这些常量的引用。'
   d['reasonEn']+=' The Ghidra export has no references to these literals.'
  if detail.get('transfers'):
   jumps=[flow[t['jumpOffset']] for t in detail['transfers'] if t['jumpOffset'] in flow]
   detail['ghidraControlFlow']=[{k:s.get(k) for k in ('fileOffset','instruction','recoveredTargets')} for s in jumps]
   if jumps:
    d['reasonZh']+=f' 对应跳转有 {len(jumps)} 条控制流记录。'
    d['reasonEn']+=f' Matching Ghidra jump sites: {len(jumps)}.'
   else:
    d['reasonZh']+=' 导出数据未覆盖对应跳转的控制流。'
    d['reasonEn']+=' The control-flow export does not cover the corresponding jumps.'

def properties(path):
 result={}
 for line in path.read_text('utf-8').splitlines():
  if '=' in line and not line.lstrip().startswith('#'):
   key,value=line.split('=',1);result[key.strip()]=value.strip()
 return result

def dependency_status(ghidra=None,java=None):
 g=Path(ghidra).resolve() if ghidra else None;j=Path(java).resolve() if java else None
 if j and j.is_dir():j=j/'bin/java.exe'
 result={'available':False,'ghidra':str(g) if g else None,'java':str(j) if j else None,'problems':[]}
 if not g or not (g/'Ghidra/application.properties').is_file() or not (g/'Ghidra/Framework/Utility/lib/Utility.jar').is_file():
  result['problems'].append('请选择完整的 Ghidra 安装目录。')
 else:
  meta=properties(g/'Ghidra/application.properties')
  result['ghidraVersion']=meta.get('application.version','unknown')
  result['minimumJava']=int(meta.get('application.java.min','25'))
 if not j or not j.is_file() or not (j.parent/'javac.exe').is_file():
  result['problems'].append('请选择 JDK 目录；只有 JRE 不足以运行分析脚本。')
 else:
  try:
   p=subprocess.run([str(j),'-version'],capture_output=True,text=True,errors='replace',timeout=15,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
   m=re.search(r'version "(\d+)',p.stdout+p.stderr)
   result['javaMajor']=int(m[1]) if m else 0
   if p.returncode or result['javaMajor']<result.get('minimumJava',25):result['problems'].append('JDK 版本低于所选 Ghidra 的要求。')
  except (OSError,subprocess.TimeoutExpired) as ex:result['problems'].append('无法启动 JDK：'+str(ex))
 result['available']=not result['problems']
 return result

def page_plan(data,report):
 count=(len(data)+PAGE-1)//PAGE
 return {'schemaVersion':1,'kind':'offline-paging-analysis','executableProfile':False,
  'inputSha256':suite.sha(data),'imageBytes':len(data),'pageSize':PAGE,'pageCount':count,
  'virtualBase':0x300000,'entry':0x300200,'osWindowPages':512,'requiresExtendedRefill':count>512,
  'physicalAddressesIncluded':False,'selectedBackend':report['backend'],
  'runtimeAdapter':report.get('requiredRuntime'),'runtimeCandidate':report['status'] in ('candidate','program-ready'),
  'requirements':(['Guest-owned resident page table and exception/refill integration',
                   'Coordinate VBR, interrupts, OS switching, cache, callbacks and private RAM',
                   'Query physical file pages on the calculator; never infer them offline'] if count>512 else
                  ['Query physical file pages on the calculator and maintain the original virtual layout']),
  'pages':[{'index':i,'fileOffset':i*PAGE,'virtualAddress':0x300000+i*PAGE,
            'validBytes':min(PAGE,len(data)-i*PAGE),'outsideOsWindow':i>=512,
            'sha256':suite.sha(data[i*PAGE:(i+1)*PAGE])} for i in range(count)]}

def ghidra_analyze(source,directory,ghidra,java,timeout=600):
 # Ghidra project paths reject apostrophes. Keep the live project in a fresh
 # local temporary folder, then copy the closed project into the user's result.
 # The original input and output can therefore contain Chinese or apostrophes.
 with tempfile.TemporaryDirectory(prefix='fxprofile-') as temporary:
  work=Path(temporary);snapshot=work/'input.g1a';snapshot.write_bytes(source.read_bytes())
  scripts=work/'scripts';shutil.copytree(ROOT/'tooling/ghidra',scripts)
  try:
   result=_ghidra_analyze(snapshot,work/'ghidra',ghidra,java,timeout,scripts)
  except (OSError,ValueError,subprocess.SubprocessError) as error:
   result={'status':'failed','problems':[str(error)]}
   if (work/'ghidra/console.log').is_file():result['log']='ghidra/console.log'
  if (work/'ghidra').exists():shutil.copytree(work/'ghidra',directory,ignore=shutil.ignore_patterns('cache','settings'))
  result['projectPathNote']='Ghidra rejects apostrophes in project paths; copy the project to a simple path before opening it interactively if necessary.'
  return result

def _ghidra_analyze(source,directory,ghidra,java,timeout,scripts):
 deps=dependency_status(ghidra,java)
 if not deps['available']:return {'status':'unavailable',**deps}
 g=Path(deps['ghidra']);directory.mkdir()
 project=directory/'project';project.mkdir()
 # Controlled entry-point setup and export scripts only. User files are data.
 argv=[deps['java'],'-Xmx2G','-XX:ParallelGCThreads=2','-XX:CICompilerCount=2',
       '-Djava.system.class.loader=ghidra.GhidraClassLoader','-Dfile.encoding=UTF-8',
       '-Duser.language=en','-Duser.country=US','-Djava.awt.headless=true','-Xshare:off',
       '--enable-native-access=ALL-UNNAMED','--sun-misc-unsafe-memory-access=allow',
       '-Djavax.xml.accessExternalDTD=','-Djavax.xml.accessExternalSchema=',
       '-Djavax.xml.accessExternalStylesheet=',
       '-Dapplication.settingsdir='+str(directory/'settings'),
       '-Dapplication.cachedir='+str(directory/'cache'),
       '-Dlog4j.configurationFile='+str(scripts/'log4j.xml'),
       '-cp',str(g/'Ghidra/Framework/Utility/lib/Utility.jar'),'ghidra.Ghidra',
       'ghidra.app.util.headless.AnalyzeHeadless',str(project),'G1A',
       '-import',str(source),'-loader','BinaryLoader','-loader-baseAddr','0x00300000',
       '-processor','SuperH4:BE:32:default','-cspec','default',
       '-scriptPath',str(scripts),'-preScript','PrepareG1a.java',
       '-postScript','ExportG1aEvidence.java',str(directory/'evidence.json'),str(source.stat().st_size),
       '-analysisTimeoutPerFile',str(max(1,timeout-90)),'-max-cpu','2',
       '-log',str(directory/'analysis.log'),'-scriptlog',str(directory/'script.log')]
 start=time.monotonic()
 with (directory/'console.log').open('w',encoding='utf-8') as log:
  process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                           creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
  try:code=process.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   if os.name=='nt':subprocess.run(['taskkill.exe','/PID',str(process.pid),'/T','/F'],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
   else:process.kill()
   process.wait();return {'status':'timeout','seconds':round(time.monotonic()-start,1),'log':'ghidra/console.log',**deps}
 evidence=directory/'evidence.json'
 if code or not evidence.is_file():return {'status':'failed','exitCode':code,'log':'ghidra/console.log',**deps}
 result=json.loads(evidence.read_text('utf-8'))
 if result.get('inputSha256')!=suite.sha(source.read_bytes()):raise ValueError('Ghidra evidence does not match the immutable input')
 return {'status':'completed' if result.get('analysisComplete') else 'partial','seconds':round(time.monotonic()-start,1),
         'evidence':'ghidra/evidence.json','project':'ghidra/project/G1A.gpr',
         'functionCount':result.get('functionCount',0),'instructionCount':result.get('instructionCount',0),
         'analysisComplete':result.get('analysisComplete',False),**deps}

def locate_result(base,options,digest):
 """Keep basic and deep reports side by side and retain failed deep attempts."""
 def previous(path):
  job_file=path/'job-result.json'
  return json.loads(job_file.read_text('utf-8')) if job_file.is_file() else {}
 deep=options['deep']
 original=previous(base)
 if deep and not original.get('generationOptions',{}).get('deep'):
  path=base.with_name(base.name+'-deep')
 elif not deep and original and original.get('generationOptions',{}).get('engineContractSha256')!=options['engineContractSha256']:
  path=base.with_name(base.name+'-basic')
 elif not deep and original.get('generationOptions',{}).get('deep'):
  path=base.with_name(base.name+'-basic')
 else:
  path=base
 variant=base.with_name(base.name+('-deep' if deep else '-basic'))
 attempt=1
 while path.exists():
  prior=previous(path)
  if prior.get('sha256')!=digest or 'generationOptions' not in prior:
   raise FileExistsError(f'输出目录已被占用，请选择新的保存位置。 / Choose another output root: {path}')
  if prior['generationOptions']==options:
   if not deep or prior.get('deepAnalysis',{}).get('status')=='completed':
    return path,prior
  elif prior['generationOptions'].get('engineContractSha256')==options['engineContractSha256'] and not deep:
   raise FileExistsError(f'同一文件在此已有其他打包选项的基础报告，请选择新的保存位置。 / A basic report with different packaging options exists: {path}')
  if path==base and path!=variant:
   path=variant
  else:
   attempt+=1;path=variant.with_name(variant.name+'-'+str(attempt))
 return path,None

def generate(source,output=None,backend='auto',artifacts=None,deep=False,ghidra=None,java=None,timeout=600,include_loader=False,output_root=None,review=None):
 source=Path(source).resolve()
 if (output is None)==(output_root is None):raise ValueError('Choose exactly one of output and output_root')
 emit('analyzing','正在检查文件、调用入口和分页边界。')
 data,initial=suite.analyze(source,backend,review)
 ident=bundle_v2.identity(source.name,initial['sha256'])
 output=(Path(output_root)/ident['directoryName'] if output_root is not None else Path(output)).resolve()
 options={'format':2,'backend':backend,'includeLoader':include_loader,'deep':deep,
          'engineContractSha256':engine_contract_sha(),
          'ghidra':str(Path(ghidra).resolve()) if deep and ghidra else None,
          'java':str(Path(java).resolve()) if deep and java else None}
 if review is not None:options['reviewSha256']=suite.sha(json.dumps(review,sort_keys=True).encode('utf8'))
 if deep:options['timeoutSeconds']=timeout
 if include_loader and initial['backend'] in bundle_v2.LOADERS:
  _,options['loaderSha256']=bundle_v2.artifact(artifacts or ROOT/'loader-artifacts',bundle_v2.LOADERS[initial['backend']])
 if output_root is not None:
  output,previous=locate_result(output,options,initial['sha256'])
  if previous and previous.get('programReady')==(initial['status']=='candidate' and initial['backend']!='ram'):
   verify_reuse(output,data,initial,artifacts,include_loader,deep)
   previous['reused']=True;previous['output']=str(output)
   emit('completed','复用相同输入和选项的完整结果。',result=previous);return previous
 if output.exists():
  raise FileExistsError('结果目录已存在且不能安全复用，请选择新的保存位置。')
 output.parent.mkdir(parents=True,exist_ok=True)
 # Calculator IDs fit the OS eight-character directory limit. Detect a short
 # hash collision among packages already produced into this output root.
 if output_root is not None:
  for other in output.parent.glob('*/job-result.json'):
   prior=json.loads(other.read_text('utf-8'))
   if prior.get('identity',{}).get('calculatorId')==ident['calculatorId'] and prior.get('sha256')!=initial['sha256']:
    raise ValueError('Calculator folder identity collision; a reviewed alternative ID is required')
 with tempfile.TemporaryDirectory(prefix='.profile-studio-',dir=output.parent) as temporary:
  stage=Path(temporary);(stage/'input').mkdir();snapshot=stage/'input'/source.name;snapshot.write_bytes(data)
  deep_report={'status':'not-requested'}
  if deep:
   emit('ghidra','正在运行 Ghidra；大文件可能需要数分钟。')
   try:
    deep_report=ghidra_analyze(snapshot,stage/'ghidra',ghidra,java,timeout)
   except (OSError,ValueError,subprocess.SubprocessError) as error:
    deep_report={'status':'failed','problems':[str(error)]}
    if (stage/'ghidra/console.log').is_file():deep_report['log']='ghidra/console.log'
  result=stage/'result'
  emit('preparing','正在生成配套文件和报告。')
  result.mkdir();(result/'original.bin').write_bytes(data)
  report=bundle_v2.prepare(data,initial,result,suite,artifacts,include_loader)
  report['diagnostics']=job_diagnostics(report)
  report['inputName']=source.name;report['deepAnalysis']=deep_report
  if (stage/'ghidra').is_dir():shutil.move(str(stage/'ghidra'),str(result/'ghidra'))
  evidence=result/'ghidra/evidence.json'
  if deep_report['status'] in ('completed','partial') and evidence.is_file():
   try:
    exported=json.loads(evidence.read_text('utf-8'))
    review=hook_review.review(data,exported)
    attach_ghidra_refs(report['diagnostics'],exported)
    write(result/'hook-review.json',review)
   except (ValueError,KeyError,TypeError) as error:
    deep_report.update(status='failed',analysisComplete=False,problems=[str(error)])
  report['pagingPlan']='paging-plan.json';write(result/'analysis.json',report)
  write(result/'paging-plan.json',page_plan(data,report))
  candidate=report['status']=='candidate'
  ready=report.get('programReady',False)
  job={'schemaVersion':2,'inputName':source.name,'sha256':report['sha256'],
       'bytes':report['bytes'],'pages':report['pages'],'backend':report['backend'],
       'status':report['status'],'installableCandidate':candidate,'hardwareValidated':False,
       'programReady':ready,'includesLoader':report.get('includesLoader',False),'identity':ident,
       'generationOptions':options,'reused':False,
       'blockers':report['blockers'],'warnings':report['warnings'],'deepAnalysis':deep_report,'diagnostics':report['diagnostics'],
       'output':str(output),'files':[p.relative_to(result).as_posix() for p in result.iterdir() if p.is_file()]}
  write(result/'job-result.json',job)
  message=('已生成程序目录和 Loader，可供实机测试。' if candidate else '已生成程序目录，配合公共 Loader 使用。' if ready else '已生成分析报告。')
  deep_names={'not-requested':'未启用 / Off','completed':'已完成 / Completed','partial':'部分完成 / Partial',
              'unavailable':'依赖不可用 / Dependencies unavailable','timeout':'超时 / Timed out','failed':'运行失败 / Failed'}
  reasons='\n\n'.join('\n'.join(d[k] for k in ('reasonZh','nextZh','reasonEn','nextEn')) for d in report['diagnostics'])
  analysis_note='Ghidra — '+deep_names[deep_report['status']]
  if deep_report.get('problems'):analysis_note+='\n'+'\n'.join(deep_report['problems'])
  if deep_report.get('log'):analysis_note+='\n'+deep_report['log']
  (result/'阅读说明.txt').write_text(message+'\n'+analysis_note+'\n\n'+reasons+'\n\n'+
    'paging-plan.json 是分页分析文档，不是计算器可执行 profile，也不包含真实物理地址。\n'+
    'Ghidra 的交叉引用和反编译只提供证据，不会自动解决超限程序的运行库、VBR 或内存共存。\n'+
    ('请将 calculator 中全部文件复制到计算器存储根目录，保留 FXAPPS 层级。不要覆盖不同程序的目录。\n'+
     '公共 Loader 可用“导出 Loader”单独取得。首次测试保留完整检查；Fast 模式可能漏检两次启动之间同大小的内容改动。\n' if ready else '')+
    ('Copy calculator contents to the storage root, preserving FXAPPS.\n' if ready else ''),encoding='utf-8-sig')
  # Hash every delivered loader/profile and exported evidence; project cache is
  # excluded because Ghidra updates it when a user opens the project.
  write(result/'checksums.json',{p.relative_to(result).as_posix():suite.sha(p.read_bytes()) for p in result.rglob('*')
   if p.is_file() and p.name!='checksums.json' and ('ghidra' not in p.relative_to(result).parts or p.name=='evidence.json')})
  # Temporary project metadata stores relative project members. Its paths remain
  # useful after the directory is published; logs may retain historical temp paths.
  result.rename(output)
 emit('completed',message,result=job)
 return job

def main():
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
 d=sub.add_parser('dependencies');d.add_argument('--ghidra');d.add_argument('--java')
 g=sub.add_parser('generate');g.add_argument('--input',type=Path,required=True)
 dest=g.add_mutually_exclusive_group(required=True);dest.add_argument('--output',type=Path);dest.add_argument('--output-root',type=Path)
 g.add_argument('--backend',choices=['auto','flash','ram','mapped','extended'],default='auto');g.add_argument('--artifacts',type=Path)
 g.add_argument('--deep',action='store_true');g.add_argument('--ghidra');g.add_argument('--java');g.add_argument('--timeout',type=int,default=600)
 g.add_argument('--review-profile',type=Path,help='SHA-bound review JSON with physical RAM exclusions')
 g.add_argument('--include-loader',action='store_true')
 e=sub.add_parser('export-loader');e.add_argument('--output',type=Path,required=True);e.add_argument('--artifacts',type=Path,default=ROOT/'loader-artifacts')
 e.add_argument('--backend',choices=['flash','mapped','extended','all'],default='flash')
 a=p.parse_args()
 try:
  if a.command=='dependencies':print(json.dumps(dependency_status(a.ghidra,a.java),ensure_ascii=False));return 0
  if a.command=='export-loader':
   r=bundle_v2.export_loaders(a.output,a.artifacts,a.backend);emit('completed','Loader 已导出。',result=r);return 0
  if not 120<=a.timeout<=3600:raise ValueError('分析超时必须在 120 至 3600 秒之间。')
  r=generate(a.input,a.output,a.backend,a.artifacts,a.deep,a.ghidra,a.java,a.timeout,a.include_loader,a.output_root,suite.read_json(a.review_profile) if a.review_profile else None)
  return 0 if r.get('programReady') else 2
 except (OSError,ValueError,KeyError) as ex:emit('error',str(ex));return 1

if __name__=='__main__':raise SystemExit(main())
