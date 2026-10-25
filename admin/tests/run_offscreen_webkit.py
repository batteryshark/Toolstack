"""Launch exactly one already-built, owned offscreen renderer with a hard deadline."""
import json
import subprocess
import sys
import time
from pathlib import Path

from admin.tests.webkit_fixtures import fixtures


def main():
    binary, output = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest = output/'fixtures.json'
    manifest.write_text(json.dumps(fixtures()))
    start = time.time()
    with (output/'renderer.stdout').open('w') as stdout, (output/'renderer.stderr').open('w') as stderr:
        process = subprocess.Popen([str(binary), str(manifest), str(output)], stdout=stdout, stderr=stderr)
        identity = subprocess.run(['/bin/ps','-p',str(process.pid),'-o','pid=,ppid=,lstart=,command='],capture_output=True,text=True).stdout
        deadline = False
        try:
            process.wait(timeout=118)
        except subprocess.TimeoutExpired:
            deadline = True
            # Popen still owns this unreaped child. No name/pattern signals.
            process.kill()
            process.wait(timeout=1)
    after = subprocess.run(['/bin/ps','-p',str(process.pid),'-o','pid=,ppid=,lstart=,command='],capture_output=True,text=True).stdout
    report = dict(pid=process.pid,start_epoch=start,start_identity=identity,exit_code=process.returncode,
                  elapsed_seconds=time.time()-start,watchdog=deadline,after_identity=after,
                  child_limit='Only direct children observable by parent identity; launchd-managed WebKit XPC services are not claimed owned or signalled.')
    (output/'process.json').write_text(json.dumps(report,indent=2))
    summary = []
    result_path=output/'webkit-results.json'
    if result_path.exists():
        results=json.loads(result_path.read_text())
        recorded_children=[]
        for case in results['results']:
            recorded_children.extend(case.get('direct_children',[]))
            dom=case.get('dom',{})
            html=dom.pop('html',None)
            if html is not None:
                (output/(case['case']+'.html')).write_text(html)
            summary.append({'case':case['case'],'failures':[r['name'] for r in dom.get('results',[]) if not r['ok']],
                            'assertions':len(dom.get('results',[])),'snapshot':case.get('snapshot',case.get('snapshot_error')),
                            'window_visible':case.get('window_visible')})
        result_path.write_text(json.dumps(results,indent=2))
        ids=sorted({line.split()[0] for line in recorded_children if line.split() and line.split()[0].isdigit()})
        if ids:
            after_children=subprocess.run(['/bin/ps','-p',','.join(ids),'-o','pid=,ppid=,lstart=,command='],capture_output=True,text=True).stdout
        else:
            after_children='No direct child PIDs were observed; no assertion about launchd-managed XPC helpers.'
        (output/'child-observations.json').write_text(json.dumps({'recorded':recorded_children,'after':after_children},indent=2))
    (output/'summary.json').write_text(json.dumps(summary,indent=2))
    print(json.dumps({'process':report,'cases':summary},indent=2))
    if process.returncode or len(summary)!=len(fixtures()) or any(c['failures'] for c in summary):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
