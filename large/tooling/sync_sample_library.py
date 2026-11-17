"""Keep self-contained FxStudio example snapshots equal to the public library."""
from pathlib import Path
import argparse

ROOT=Path(__file__).resolve().parents[1]
def sync(check=False):
    sources=[ROOT/"CMakeLists.txt",ROOT/"src/runtime.c",*sorted((ROOT/"include/fxlarge").glob("*.h"))]
    for sample in ("extended-cas", "mapped-loader", "source-guest"):
        for source in sources:
            target=ROOT/"probes"/sample/"vendor/fxlarge"/source.relative_to(ROOT)
            if check:
                if not target.exists() or target.read_bytes()!=source.read_bytes():
                    raise ValueError(f"sample library snapshot stale: {target}")
            else:
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(source.read_bytes())
if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--check",action="store_true")
    sync(parser.parse_args().check)
