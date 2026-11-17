"""Build an isolated project copy through the documented Fx Studio helper."""
import argparse,json,shutil,subprocess,sys,time
from pathlib import Path
p=argparse.ArgumentParser()
for arg in ('package','state','work','output'):p.add_argument('--'+arg,type=Path,required=True)
p.add_argument('--release-only',action='store_true');a=p.parse_args()
for name in ('package','state','work','output'):setattr(a,name,getattr(a,name).resolve())
helper=Path.home()/'.codex/skills/fxstudio/scripts/fxstudio.py'
source=Path(__file__).resolve().parents[1];a.output.mkdir(parents=True,exist_ok=True)
shutil.copytree(source,a.work,dirs_exist_ok=True,ignore=shutil.ignore_patterns('.fxstudio','build*','project.fxide.json','__pycache__'))
def cli(*args):
    r=subprocess.run([sys.executable,'-X','utf8',str(helper),'--package',str(a.package),'--state',str(a.state),*map(str,args)],capture_output=True,text=True,encoding='utf-8')
    if r.returncode:raise RuntimeError(r.stdout+r.stderr)
    return json.loads(r.stdout)
def call(name,args):
    request=a.output/'request.json';request.write_text(json.dumps(args),encoding='utf-8')
    op=cli('call',name,'--args-file',request)['structuredContent']['operation']
    while op['status'] not in ('succeeded','failed','cancelled'):
        time.sleep(2);op=cli('operation',op['operationId'])['structuredContent']['operation']
    if op['status']!='succeeded':raise RuntimeError(json.dumps(op,ensure_ascii=False))
    return op['result']
for command in ('session.open','build.run','session.close'):
    (a.output/(command+'.schema.json')).write_text(json.dumps(cli('discover',command),indent=2),encoding='utf-8')
sid=call('session.open',{'projectPath':str(a.work)})['sessionId']
results={}
try:
    for configuration in (('Release',) if a.release_only else ('Debug','Release')):
        print('Building',configuration,flush=True)
        results[configuration]=call('build.run',{'sessionId':sid,'configuration':configuration})
        (a.output/'builds.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
        print('Built',configuration,flush=True)
finally:call('session.close',{'sessionId':sid})
