"""Bounded real Chrome DOM checks, with fake fetch receipts and no live backend.

Run as a module. Only installed Chrome, isolated profile, owned temporary files.
Evidence distinguishes rendered DOM checks from live service / native testing.
"""
import json
import subprocess
import tempfile
from pathlib import Path

from admin.views.callers import policy_view
from admin.views.tools import tool_editor_view

CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
TEMP = '/private/var/folders/pz/lrml3ths3mg3mf4bb75rmcvc0000gn/T/opencode'
OUT = Path(__file__).parent / 'evidence' / 'clear-desk'

POLICY = r"""
const form=document.querySelector('#policy-form'), select=form.querySelector('select');
const save=form.querySelector('[type=submit]');
const original=document.documentElement.outerHTML;
select.value='allow';select.dispatchEvent(new Event('change',{bubbles:true}));
window.fetch=async()=>({ok:false,status:400,json:async()=>({outcome:'rejected'})});
form.requestSubmit();await new Promise(r=>setTimeout(r,20));
check(select.value==='allow'&&save.disabled,'rejected save retains draft and gates save until comparison');
check(form.textContent.includes('Save rejected'),'rejection visible');
window.fetch=async()=>({ok:true,text:async()=>original});
Array.from(form.querySelectorAll('button')).find(b=>b.textContent==='Reload to compare').click();
await new Promise(r=>setTimeout(r,20));
window.fetch=async()=>{throw Error('lost response');};
form.requestSubmit();await new Promise(r=>setTimeout(r,20));
check(save.disabled&&select.value==='allow','unknown save blocks retry and retains draft');
window.fetch=async()=>({ok:true,text:async()=>original});
Array.from(form.querySelectorAll('button')).find(b=>b.textContent==='Reload to compare').click();
await new Promise(r=>setTimeout(r,20));
check(!save.disabled&&select.value==='allow','comparison retains differing draft');
check(form.textContent.includes('Saved: deny'),'saved effect shown alongside draft');
form.querySelector('a').click();
check(document.querySelector('dialog[open]')!==null,'dirty navigation opens dialog');
check(document.activeElement.textContent==='Stay','safe Stay receives focus');
document.activeElement.click();
check(select.value==='allow','Stay retains draft');
select.focus();check(document.activeElement===select,'policy control focusable');
window.fetch=async()=>({ok:true,json:async()=>({outcome:'saved',target:'writer-demo'})});
form.requestSubmit();await new Promise(r=>setTimeout(r,20));
check(form.textContent.includes('Policy saved'),'acknowledged save receipt');
select.value='review';select.dispatchEvent(new Event('change',{bubbles:true}));
let writes=0;
window.fetch=async()=>{writes++;return {ok:false,status:500,json:async()=>({outcome:'rejected'})};};
form.requestSubmit();form.requestSubmit();await new Promise(r=>setTimeout(r,20));
check(writes===1&&save.disabled,'500 after effect is unknown; duplicate submit sends one write');
const applied=document.documentElement.outerHTML;
window.fetch=async()=>({ok:true,text:async()=>applied});
Array.from(form.querySelectorAll('button')).find(b=>b.textContent==='Reload to compare').click();
await new Promise(r=>setTimeout(r,20));
check(writes===1,'comparison never replays mutation');
"""

EDITOR = r"""
const form=document.querySelector('#tool-form');
form.addEventListener('submit',e=>e.preventDefault());
form.dispatchEvent(new Event('submit',{cancelable:true}));
const data=JSON.parse(document.querySelector('#tool_json').value);
check(!Object.hasOwn(data.operations[0],'approval_fields'),'absent approval_fields remains absent through serialization');
check(Array.isArray(data.operations[1].approval_fields)&&data.operations[1].approval_fields.length===0,'empty approval_fields remains empty through serialization');
check(data.operations[2].approval_fields[0]==='message','explicit approval_fields retained');
document.querySelectorAll('.dup-op')[1].click();
form.dispatchEvent(new Event('submit',{cancelable:true}));
const copied=JSON.parse(document.querySelector('#tool_json').value);
check(copied.operations[2].approval_fields.length===0,'duplicate preserves explicit empty approval_fields');
"""


def instrument(source, checks):
    script = """<script>document.addEventListener('DOMContentLoaded',async()=>{
    const results=[];function check(ok,name){results.push({name,ok:!!ok});}
    try{CHECKS
    check(document.documentElement.scrollWidth<=innerWidth,'no horizontal viewport overflow');
    }catch(e){results.push({name:String(e),ok:false});}
    const report=document.createElement('pre');report.id='browser-proof';report.hidden=true;
    report.textContent=JSON.stringify(results);document.body.append(report);
    document.title=results.every(r=>r.ok)?'PROOF PASS':'PROOF FAIL';
    });</script>""".replace('CHECKS', checks)
    return source.replace('</body>', script + '</body>')


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    policy = policy_view(user='fake-admin', csrf='fake', caller='writer-demo',
        ops_by_tool={'notes-demo': [{'op': 'read_note', 'risk': 'read'}]},
        current={'tools': {'notes-demo': {'read_note': 'deny'}}})
    editor = tool_editor_view(user='fake-admin', csrf='fake', mode='edit',
        dir_value='/fake/notes', tool={'id': 'notes-demo', 'type': 'api', 'port': 4700,
        'operations': [{'name': 'absent'}, {'name': 'empty', 'approval_fields': []},
                       {'name': 'explicit', 'approval_fields': ['message']}]})
    results = []
    with tempfile.TemporaryDirectory(prefix='clear-desk-browser-', dir=TEMP) as temp:
        for name, source, checks in [('policy', policy, POLICY), ('editor', editor, EDITOR)]:
            path = Path(temp) / (name + '.html')
            path.write_text(instrument(source, checks))
            for width in (1440, 1180):
                key = f'{name}-{width}'
                command = [CHROME, '--headless', '--disable-gpu', '--no-first-run', '--use-mock-keychain', '--password-store=basic',
                    '--no-default-browser-check', '--disable-background-networking',
                    '--disable-component-update', '--disable-sync', '--disable-extensions',
                    f'--user-data-dir={temp}/profile', f'--window-size={width},900',
                    '--virtual-time-budget=2000', '--dump-dom',
                    f'--screenshot={OUT / (key + ".png")}', path.as_uri()]
                run = subprocess.run(command, capture_output=True, text=True, timeout=30)
                (OUT / (key + '.html')).write_text(run.stdout)
                (OUT / (key + '.log')).write_text(run.stderr)
                passed = run.returncode == 0 and '<title>PROOF PASS</title>' in run.stdout
                results.append({'case': key, 'passed': passed, 'returncode': run.returncode})
    (OUT / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
    if not all(r['passed'] for r in results):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
