"""Optional offscreen evidence using already-installed Chrome; no services or app launch."""
from pathlib import Path
import subprocess
import tempfile
import json

ROOT = Path(__file__).resolve().parent
CHROME = Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
if not CHROME.exists():
    raise SystemExit('No installed renderer; use the standalone SVGs. Do not install one.')
captures = ROOT / 'captures'
captures.mkdir(exist_ok=True)
results = []
with tempfile.TemporaryDirectory(prefix='toolstack-ui-', dir='/private/var/folders/pz/lrml3ths3mg3mf4bb75rmcvc0000gn/T/opencode') as profile:
    base = [str(CHROME), '--headless', '--disable-gpu', '--no-first-run', '--use-mock-keychain', '--password-store=basic',
            '--no-default-browser-check', '--disable-background-networking',
            '--disable-component-update', '--disable-sync', '--hide-scrollbars',
            f'--user-data-dir={profile}', '--window-size=1440,900']
    for direction in 'abc':
        for surface, flow, step in [('web','grant',1), ('shell','add',2), ('mac','recover',0)]:
            name = f'{direction}-{surface}-{flow}-{step}'
            result = subprocess.run(base + [f'--screenshot={captures / (name + ".png")}',
                (ROOT / 'visuals' / (name + '.svg')).as_uri()], capture_output=True, text=True, timeout=25)
            results.append({'frame':name, 'returncode':result.returncode,
                            'png_exists':(captures / (name + '.png')).exists(),
                            'stderr':result.stderr})
    # Exercise initial hash routing and JS at the gallery level, still file-only.
    result = subprocess.run(base + ['--dump-dom', (ROOT/'gallery.html').as_uri()+'#c-mac-add-0'],
                            capture_output=True, text=True, timeout=25)
    (ROOT/'evidence'/'gallery-dom.html').write_text(result.stdout)
    results.append({'gallery_returncode':result.returncode,
                    'gallery_populated': '<div class="viewport" id="viewport"><svg' in result.stdout,
                    'stderr':result.stderr})
(ROOT/'evidence'/'render-results.json').write_text(json.dumps(results, indent=2))
assert all(r.get('returncode',0)==0 and r.get('png_exists',True) for r in results)
assert results[-1]['gallery_populated']
print('9 static PNG renders and gallery hash-route DOM check completed. Not live application checks.')
