"""Reproduce tests and the stored-scan CLI workflow in an isolated directory."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def run(arguments,expected=0):
    process=subprocess.run([sys.executable,*map(str,arguments)],cwd=ROOT,text=True,capture_output=True)
    if process.returncode!=expected:
        raise RuntimeError(f'Command failed: {arguments}\n{process.stdout}\n{process.stderr}')
    return process.stdout


def main():
    print(run(['-m','unittest','discover','-s','tests','-v']))
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory)
        db=root/'history.sqlite'
        command=['-m','sentryscope']
        unsafe=json.loads(run(command+['scan','examples/unsafe','--project','example','--database',db,'--format','json'],1))
        assert unsafe['complete'] and unsafe['findings']
        clean=json.loads(run(command+['scan','examples/clean','--project','example','--database',db,'--format','json']))
        assert clean['findings']==[] and clean['complete']
        difference=json.loads(run(command+['diff',unsafe['scan_id'],clean['scan_id'],'--database',db]))
        assert difference['complete'] and difference['absent'] and not difference['new']
        run(command+['report',unsafe['scan_id'],'--format','html','--output',root/'report.html','--database',db])
        run(command+['report',unsafe['scan_id'],'--format','sarif','--output',root/'report.sarif','--database',db])
        run(command+['baseline',unsafe['scan_id'],'--output',root/'baseline.json','--database',db])
        run(command+['scan','examples/unsafe','--project','example','--database',db,'--baseline',root/'baseline.json'])
        assert json.loads(run(command+['audit','--verify','--database',db]))['valid']
        run(command+['backup',root/'backup.sqlite','--database',db])
        assert json.loads(run(command+['audit','--verify','--database',root/'backup.sqlite']))['valid']
        print('Tests and end-to-end checks passed.')


if __name__=='__main__':
    main()
