"""Assemble a new portable WinUI desktop directory from explicit local inputs."""
import argparse,hashlib,json,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def copy_build_notices(output):
    assets=ROOT/'desktop/ProfileStudio/obj/project.assets.json'
    if not assets.is_file():raise FileNotFoundError('Publish the desktop project first; NuGet dependency notices require project.assets.json')
    meta=json.loads(assets.read_text('utf-8'));count=0
    for library in meta['libraries'].values():
        relative=library.get('path')
        if not relative:continue
        for folder in meta['packageFolders']:
            package=Path(folder)/relative
            if not package.is_dir():continue
            for source in package.iterdir():
                if source.is_file() and ('license' in source.name.lower() or 'notice' in source.name.lower()) and source.suffix.lower() in ('.txt','.md',''):
                    dest=output/'licenses'/relative/source.name
                    dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest);count+=1
            break
    if count==0:raise ValueError('No dependency notices found')

def assemble(publish,python,artifacts,output,ghidra=None,jdk=None):
    output=Path(output).resolve()
    if output.exists():raise FileExistsError('Choose a new output directory')
    for file in (publish/'ProfileStudio.exe',python/'python.exe',artifacts/'manifest.json'):
        if not file.is_file():raise FileNotFoundError(file)
    shutil.copytree(publish,output)
    shutil.copytree(python,output/'runtime/python',ignore=shutil.ignore_patterns('__pycache__'))
    # The embedded Python path file is deliberately independent of FxStudio.
    for pth in (output/'runtime/python').glob('python*._pth'):
        entries=[p.name for p in pth.parent.glob('python*.zip')]+['.','Lib/site-packages','../../engine/tooling']
        pth.write_text('\n'.join(entries)+'\n',encoding='utf-8')
    engine=output/'engine'
    for name in ['tooling/loader_suite.py','tooling/profile_job.py','profiles/registry.json',
                 'probes/native-loader/tools/prepare.py','probes/storage-loader/tools/prepare.py','probes/mapped-loader/tools/prepare.py']:
        dest=engine/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,dest)
    shutil.copytree(ROOT/'tooling/ghidra',engine/'tooling/ghidra')
    shutil.copytree(artifacts,engine/'loader-artifacts')
    for src in [ghidra,jdk]:
        if src:shutil.copytree(src,output/'dependencies'/src.name)
    shutil.copyfile(ROOT/'LICENSE',output/'LICENSE.txt')
    shutil.copyfile(ROOT/'desktop/ProfileStudio/README.zh-CN.md',output/'使用说明.md')
    shutil.copyfile(ROOT/'desktop/ProfileStudio/THIRD-PARTY.md',output/'THIRD-PARTY.md')
    shutil.copyfile(ROOT/'desktop/ProfileStudio/VALIDATION.json',output/'VALIDATION.json')
    copy_build_notices(output)
    files={p.relative_to(output).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in output.rglob('*') if p.is_file()}
    (output/'package-manifest.json').write_text(json.dumps({'schemaVersion':1,'product':'FX Profile Studio','version':'0.1.0','files':files},indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'output':str(output),'files':len(files)},ensure_ascii=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ['publish','python','artifacts','output']:p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--ghidra',type=Path);p.add_argument('--jdk',type=Path);a=p.parse_args()
    assemble(a.publish,a.python,a.artifacts,a.output,a.ghidra,a.jdk)
