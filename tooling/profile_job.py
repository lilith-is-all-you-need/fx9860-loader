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
  bundle_v2.prepare(data,copy.deepcopy(initial),expected,suite,artifacts,include_loader)
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
  result=_ghidra_analyze(snapshot,work/'ghidra',ghidra,java,timeout,scripts)
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
   process.wait();return {'status':'timeout','seconds':round(time.monotonic()-start,1),**deps}
 evidence=directory/'evidence.json'
 if code or not evidence.is_file():return {'status':'failed','exitCode':code,'log':'ghidra/console.log',**deps}
 result=json.loads(evidence.read_text('utf-8'))
 if result.get('inputSha256')!=suite.sha(source.read_bytes()):raise ValueError('Ghidra evidence does not match the immutable input')
 return {'status':'completed' if result.get('analysisComplete') else 'partial','seconds':round(time.monotonic()-start,1),
         'evidence':'ghidra/evidence.json','project':'ghidra/project/G1A.gpr',
         'functionCount':result.get('functionCount',0),'instructionCount':result.get('instructionCount',0),
         'analysisComplete':result.get('analysisComplete',False),**deps}

def generate(source,output=None,backend='auto',artifacts=None,deep=False,ghidra=None,java=None,timeout=600,include_loader=False,output_root=None):
 source=Path(source).resolve()
 if (output is None)==(output_root is None):raise ValueError('Choose exactly one of output and output_root')
 emit('analyzing','正在检查文件、调用入口和分页边界。')
 data,initial=suite.analyze(source,backend)
 ident=bundle_v2.identity(source.name,initial['sha256'])
 output=(Path(output_root)/ident['directoryName'] if output_root is not None else Path(output)).resolve()
 options={'format':2,'backend':backend,'includeLoader':include_loader,'deep':deep,
          'engineContractSha256':engine_contract_sha(),
          'ghidra':str(Path(ghidra).resolve()) if deep and ghidra else None,
          'java':str(Path(java).resolve()) if deep and java else None}
 if include_loader and initial['backend'] in bundle_v2.LOADERS:
  _,options['loaderSha256']=bundle_v2.artifact(artifacts or ROOT/'loader-artifacts',bundle_v2.LOADERS[initial['backend']])
 if output.exists():
  if output_root is not None and (output/'job-result.json').is_file():
   previous=json.loads((output/'job-result.json').read_text('utf-8'))
   if initial['status']=='candidate' and previous.get('sha256')==initial['sha256'] and previous.get('generationOptions')==options and previous.get('programReady'):
    verify_reuse(output,data,initial,artifacts,include_loader,deep)
    previous['reused']=True;previous['output']=str(output)
    emit('completed','复用相同输入和选项的完整结果。',result=previous);return previous
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
   deep_report=ghidra_analyze(snapshot,stage/'ghidra',ghidra,java,timeout)
  result=stage/'result'
  if deep and deep_report['status']!='completed':
   result.mkdir();(result/'original.bin').write_bytes(data)
   report=initial;report['status']='analysis-incomplete'
   report['blockers'].append('Ghidra 分析未完成；查看依赖状态或 ghidra/console.log 后重试。')
  else:
   emit('preparing','正在生成配套文件和报告。')
   result.mkdir();(result/'original.bin').write_bytes(data)
   report=bundle_v2.prepare(data,initial,result,suite,artifacts,include_loader)
  report['inputName']=source.name;report['deepAnalysis']=deep_report
  report['pagingPlan']='paging-plan.json';write(result/'analysis.json',report)
  write(result/'paging-plan.json',page_plan(data,report))
  if (stage/'ghidra').is_dir():shutil.move(str(stage/'ghidra'),str(result/'ghidra'))
  evidence=result/'ghidra/evidence.json'
  if evidence.is_file():
   write(result/'hook-review.json',hook_review.review(data,json.loads(evidence.read_text('utf-8'))))
  candidate=report['status']=='candidate'
  ready=report.get('programReady',False)
  job={'schemaVersion':2,'inputName':source.name,'sha256':report['sha256'],
       'bytes':report['bytes'],'pages':report['pages'],'backend':report['backend'],
       'status':report['status'],'installableCandidate':candidate,'hardwareValidated':False,
       'programReady':ready,'includesLoader':report.get('includesLoader',False),'identity':ident,
       'generationOptions':options,'reused':False,
       'blockers':report['blockers'],'warnings':report['warnings'],'deepAnalysis':deep_report,
       'output':str(output),'files':[p.relative_to(result).as_posix() for p in result.iterdir() if p.is_file()]}
  write(result/'job-result.json',job)
  message=('已生成程序目录和 Loader，可供实机测试。' if candidate else '已生成程序目录，配合公共 Loader 使用。' if ready else '目前只生成分析材料，尚缺运行时适配。')
  (result/'阅读说明.txt').write_text(message+'\n\n'+
    'paging-plan.json 是分页分析文档，不是计算器可执行 profile，也不包含真实物理地址。\n'+
    'Ghidra 的交叉引用和反编译只提供证据，不会自动解决超限程序的运行库、VBR 或内存共存。\n'+
    ('请将 calculator 中全部文件复制到计算器存储根目录，保留 FXAPPS 层级。不要覆盖不同程序的目录。\n'+
     '公共 Loader 可用“导出 Loader”单独取得。首次测试保留完整检查；Fast 模式可能漏检两次启动之间同大小的内容改动。\n' if ready else '')+
    'Program folders are independent of the shared launcher. Copy calculator contents to the storage root, preserving FXAPPS.\n'+
    'Readiness is not a claim of hardware stability. Ghidra evidence alone does not authorize binary hooks.\n'+
    '\n'.join(report['blockers']),encoding='utf-8-sig')
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
 g.add_argument('--include-loader',action='store_true')
 e=sub.add_parser('export-loader');e.add_argument('--output',type=Path,required=True);e.add_argument('--artifacts',type=Path,default=ROOT/'loader-artifacts')
 e.add_argument('--backend',choices=['flash','mapped','extended','all'],default='all')
 a=p.parse_args()
 try:
  if a.command=='dependencies':print(json.dumps(dependency_status(a.ghidra,a.java),ensure_ascii=False));return 0
  if a.command=='export-loader':
   r=bundle_v2.export_loaders(a.output,a.artifacts,a.backend);emit('completed','Loader 已导出。',result=r);return 0
  if not 120<=a.timeout<=3600:raise ValueError('分析超时必须在 120 至 3600 秒之间。')
  r=generate(a.input,a.output,a.backend,a.artifacts,a.deep,a.ghidra,a.java,a.timeout,a.include_loader,a.output_root)
  return 0 if r.get('programReady') else 2
 except (OSError,ValueError,KeyError) as ex:emit('error',str(ex));return 1

if __name__=='__main__':raise SystemExit(main())
