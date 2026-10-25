"""Current production pages plus synthetic interactions; no browser launch here."""
import json
import sys
from pathlib import Path

from admin.tests.clear_desk_browser import POLICY, EDITOR
from admin.views.callers import policy_view
from admin.views.dashboard import _callers_section
from admin.views.layout import page
from admin.views.tools import tools_view, tool_add_view, tool_editor_view
from desktop.app import startup_error

POLICY_MORE = r"""
const compare=Array.from(form.querySelectorAll('button')).find(b=>b.textContent==='Reload to compare');
window.fetch=async()=>{throw Error('comparison failed');};compare.hidden=false;compare.click();
await wait();check(save.disabled,'failed comparison locks Save');
window.fetch=async()=>({ok:true,text:async()=>original.replaceAll('writer-demo','other-target')});
compare.click();await wait();check(save.disabled,'mismatched comparison scope locks Save');
window.fetch=async()=>({ok:true,text:async()=>original});compare.click();await wait();
check(!save.disabled,'fresh successful comparison unlocks explicit save');
select.value='allow';select.dispatchEvent(new Event('change',{bubbles:true}));
const signout=document.querySelector('form[action="/logout"]');let signouts=0;
signout.addEventListener('submit',e=>{if(!e.defaultPrevented)signouts++;e.preventDefault();});
signout.requestSubmit();check(document.activeElement.textContent==='Stay','signout defaults to Stay');
document.activeElement.click();await wait();check(signouts===0&&select.value==='allow','signout Stay retains draft without submitting');
signout.requestSubmit();Array.from(document.querySelector('dialog[open]').querySelectorAll('button')).find(b=>b.textContent==='Discard draft').click();
await wait();check(signouts===1,'signout Discard submits exactly once without capture loop');
"""

CALLER_ROWS = r"""
window.fixtureNavigations=[];
const rows=document.querySelectorAll('[data-caller-policy]'), row=rows[0];
const doubleClick=el=>el.dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));
doubleClick(row.cells[0]);await wait(150);
check(window.fixtureNavigations.join() === 'https://fixture.invalid/callers/writer-demo/policy','row double-click navigates to caller policy');
window.fixtureNavigations=[];
for(const el of row.querySelectorAll('button,a,input,form'))doubleClick(el);
await wait(150);check(window.fixtureNavigations.length===0,'nested row controls never trigger double-click navigation');
row.focus();check(document.activeElement===row && !!row.getAttribute('aria-label'),'caller row focusable and named');
row.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true,cancelable:true}));await wait(150);
check(window.fixtureNavigations.join() === 'https://fixture.invalid/callers/writer-demo/policy','Enter on focused row navigates to caller policy');
window.fixtureNavigations=[];
row.querySelector('button').dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
await wait();check(window.fixtureNavigations.length===0,'nested keyboard action does not navigate');
doubleClick(rows[1].cells[1]);await wait(150);
check(window.fixtureNavigations.join() === 'https://fixture.invalid/callers/revoked-demo/policy','revoked row retains existing policy destination');
"""

CONFIRM = r"""
const form=document.querySelector('form[data-confirm]');let posts=0, resolve;
window.fetch=()=>{posts++;return new Promise(r=>resolve=r);};
form.requestSubmit();let d=document.querySelector('dialog[open]');
check(!!d&&document.activeElement.textContent==='Cancel','confirmation defaults to Cancel');
check(!!d.getAttribute('aria-label'),'confirmation dialog has accessible name');
check(d.textContent.includes('notes-demo'),'confirmation names target');
document.activeElement.click();await wait();check(posts===0&&!document.querySelector('dialog[open]'),'Cancel has no effect');
form.requestSubmit();d=document.querySelector('dialog[open]');
// Synthetic cancel event is not proof of trusted Escape dispatch.
d.dispatchEvent(new Event('cancel',{cancelable:true}));d.close();await wait();
check(posts===0&&!document.querySelector('dialog[open]'),'synthetic Escape-equivalent close has no effect');
form.requestSubmit();d=document.querySelector('dialog[open]');d.querySelectorAll('button')[1].click();
form.requestSubmit();form.requestSubmit();check(posts===1,'accepted confirmation plus duplicate submits sends one POST');
resolve({ok:false,status:500,url:form.action,text:async()=>''});await wait();
form.requestSubmit();check(posts===1,'unknown outcome cannot replay POST');
check(document.body.textContent.includes('Outcome unknown'),'unknown mutation visible');
check(document.querySelector('form[data-confirm] a').getAttribute('href').includes('notes-demo'),'unknown refresh retains target');
"""

UNKNOWN_HTML = r"""
const form=document.querySelector('form[data-mutation]');let posts=0;
window.fetch=async()=>{posts++;return {ok:true,status:200,url:form.action,text:async()=>window.RETURNED_PAGE};};
form.requestSubmit();await wait(150);
check(document.body.textContent.includes('outcome unknown')||document.body.textContent.includes('Outcome unknown'),'returned unknown stage remains visible');
const retry=document.querySelector('form[data-mutation]');
check(!!retry&&retry.querySelector('button').disabled,'200 unknown stage cannot immediately retry without observation');
if(retry)retry.requestSubmit();await wait();check(posts===1,'returned unknown stage sends no duplicate mutation');
const alternate=document.querySelector('form[action$="/restart"]');
alternate.requestSubmit();const dialog=document.querySelector('dialog[open]');
if(dialog)dialog.querySelectorAll('button')[1].click();await wait();
check(posts===1,'unknown target cannot bypass gate via another lifecycle form');
if(dialog)dialog.close();
"""

REPLACEMENT = r"""
let posts=0;
window.fetch=async()=>{posts++;return {ok:true,status:200,url:'https://fixture.invalid/tools?tool=notes-demo',text:async()=>window.RETURNED_PAGE};};
document.querySelector('form[data-mutation]').requestSubmit();await wait(150);
const form=document.querySelector('form[data-confirm]');
check(!!form,'replacement keeps focused recovery form');
form.requestSubmit();check(!!document.querySelector('dialog[open]'),'document.write replacement initializes production scripts');
check(document.activeElement.textContent==='Cancel','replacement dialog has safe focus');
check(posts===1,'opening replacement confirmation does not send effect');
check(document.querySelector('a[href="/tools?tool=notes-demo"]')!==null,'replacement preserves navigation target');
document.querySelector('dialog[open]').close();
"""

def instrument(html, checks, returned=None):
    setup = ('window.RETURNED_PAGE=' + json.dumps(returned).replace('</', '<\\/') + ';') if returned else ''
    script = r"""<script>document.addEventListener('DOMContentLoaded',async()=>{
    const results=[];const check=(ok,name)=>results.push({name,ok:!!ok});
    const wait=(ms=40)=>new Promise(r=>setTimeout(r,ms));
    const checkDialogButtons=dialog=>{
      const buttons=Array.from(dialog.querySelectorAll('button'));
      check(buttons.length===2,'open dialog has two actions');
      const bounds=buttons.map(button=>{
        const r=button.getBoundingClientRect(),s=getComputedStyle(button);
        const outline=s.outlineStyle==='none'?0:parseFloat(s.outlineWidth)+parseFloat(s.outlineOffset);
        return {left:r.left-outline,right:r.right+outline,top:r.top-outline,bottom:r.bottom+outline};
      });
      for(let i=0;i<bounds.length;i++)for(let j=i+1;j<bounds.length;j++){
        const a=bounds[i],b=bounds[j];
        check(Math.max(b.left-a.right,a.left-b.right,b.top-a.bottom,a.top-b.bottom)>=8,
          'open dialog buttons separated by at least 8px including focus outline');
      }
    };
    SETUP
    try { CHECKS }catch(error){check(false,String(error));}
    await wait();
    const visible=Array.from(document.querySelectorAll('button,input,select,a.button,dialog[open]')).filter(e=>{
      if(!e.getClientRects().length)return false;
      for(let p=e.parentElement;p;p=p.parentElement){
        if(p.tagName==='DETAILS'&&!p.open&&!p.querySelector('summary').contains(e))return false;
      }
      return true;
    });
    const rectangles=visible.map(e=>{const r=e.getBoundingClientRect();return {tag:e.tagName,label:(e.textContent||e.name||e.id).slice(0,100),x:r.x,y:r.y,width:r.width,height:r.height};});
    const horizontal=rectangles.filter(r=>r.x < -1 || r.x+r.width > innerWidth+1);
    check(document.documentElement.scrollWidth<=innerWidth,'no horizontal document overflow');
    check(horizontal.length===0,'visible controls fit horizontal viewport');
    const selects=visible.filter(e=>e.tagName==='SELECT');
    for(const select of selects){
      check(select.getBoundingClientRect().height>=38,'select target at least 38px: '+(select.name||select.className));
      if(select.name.startsWith('op__'))check(select.getAttribute('aria-label')==='Effect for writer-demo / notes-demo / read_note','policy effect names caller/tool/operation');
    }
    for(const button of visible.filter(e=>e.matches('button,a.button'))){
      check(button.getBoundingClientRect().height>=38,'button target at least 38px: '+button.textContent.trim());
    }
    // Vertical scrolling is recorded rather than treated as blanket clipping failure.
    const below=rectangles.filter(r=>r.y+r.height>innerHeight);
    const collisions=[];
    const buttons=visible.filter(e=>e.tagName==='BUTTON'&&!e.closest('dialog:not([open])'));
    for(let i=0;i<buttons.length;i++)for(let j=i+1;j<buttons.length;j++){
      const a=buttons[i].getBoundingClientRect(),b=buttons[j].getBoundingClientRect();
      if(Math.min(a.right,b.right)-Math.max(a.left,b.left)>1&&Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top)>1)
        collisions.push([buttons[i].textContent,buttons[j].textContent]);
    }
    // Modal-over-background containment is intentional; only non-modal frames use this check.
    if(!document.querySelector('dialog[open]'))check(collisions.length===0,'no button-button overlap');
    document.querySelectorAll('dialog[open]').forEach(checkDialogButtons);
    window.webkit.messageHandlers.proof.postMessage({results,rectangles,horizontal,below,collisions,
      viewport:{width:innerWidth,height:innerHeight},synthetic:true,html:document.documentElement.outerHTML});
    });</script>""".replace('SETUP', setup).replace('CHECKS', checks)
    return html.replace('</body>', script+'</body>') if '</body>' in html else html.replace('</html>', script+'</html>')


RECOVERY = r"""
const form=document.querySelector('#policy-form'), select=form.querySelector('select'), save=form.querySelector('[type=submit]');
const original=document.documentElement.outerHTML, compare=Array.from(form.querySelectorAll('button')).find(b=>b.textContent==='Reload to compare');
let posts=0, parses=0;
check(!Array.from(form.querySelectorAll('a')).find(a=>a.textContent==='Load current policy page').getClientRects().length,'current-page recovery hidden until scope change');
select.value='allow';select.dispatchEvent(new Event('change',{bubbles:true}));
window.fetch=async(url,options)=>{if(options.method==='POST')posts++;return {ok:true,url:'https://fixture.invalid/login',json:async()=>{parses++;throw Error('HTML');},text:async()=>{parses++;return '<form>login</form>';}};};
form.requestSubmit();await wait();
check(posts===1&&parses===0,'save login redirect detected before JSON parsing');
check(save.disabled&&select.value==='allow'&&form.textContent.includes('Save rejected'),'expired save known rejected and draft retained');
check(document.activeElement===compare,'recovery receives focus');
compare.click();await wait();
check(parses===0&&save.disabled&&form.textContent.includes('Sign in in another tab'),'compare expiry detected before HTML parsing with recovery guidance');
check(!form.textContent.includes('Save outcome unknown'),'expiry alone does not invent unknown mutation');
window.fetch=async()=>({ok:true,text:async()=>original.replaceAll('value="fake"','value="fresh-fake"')});
compare.click();await wait();
check(!save.disabled&&select.value==='allow'&&form.querySelector('[name=_csrf]').value==='fresh-fake','reauth compare refreshes CSRF and retains draft');
check(posts===1,'reauth comparison never replays save');
check(!Array.from(form.querySelectorAll('a')).find(a=>a.textContent==='Load current policy page').getClientRects().length,'current-page recovery hidden after successful comparison');
window.fetch=async()=>{posts++;throw Error('lost receipt');};form.requestSubmit();await wait();
window.fetch=async()=>({ok:true,url:'https://fixture.invalid/login'});compare.click();await wait();
check(save.disabled&&form.textContent.includes('Save outcome unknown'),'compare expiry preserves prior genuine unknown');
window.fetch=async()=>({ok:true,text:async()=>original.replaceAll('op__notes-demo__read_note','op__notes-demo__changed')});compare.click();await wait();
const current=Array.from(form.querySelectorAll('a')).find(a=>a.textContent==='Load current policy page');
check(save.disabled&&select.value==='allow'&&!current.hidden&&form.textContent.includes('Operation set changed'),'permanent scope mismatch offers current page without overwriting draft');
check(document.activeElement===current&&current.href===form.action,'current-policy recovery focused and correctly targeted');
current.click();let d=document.querySelector('dialog[open]');
check(!!d&&!!d.getAttribute('aria-label')&&document.activeElement.textContent==='Stay','current page departure uses named safe Stay dialog');
document.activeElement.click();await wait();check(select.value==='allow'&&posts===2,'Stay preserves draft; no replay');
"""


def recovery_fixtures():
    policy = policy_view(user='fake-admin', csrf='fake', caller='writer-demo',
        ops_by_tool={'notes-demo': [{'op': 'read_note', 'risk': 'read'}]},
        current={'tools': {'notes-demo': {'read_note': 'deny'}}})
    recovery = tools_view(user='fake-admin', csrf='fake', tools=[dict(id='notes-demo',
        port=4700, path='/fake/notes', running=True, alive=False, removable=False)],
        tools_root='/fake', focused=True, broker_port=8765)
    return [dict(name='policy-recovery-1180', html=instrument(policy, RECOVERY), width=1180, height=900),
            dict(name='confirmation-recovery-1180', html=instrument(recovery, CONFIRM), width=1180, height=900)]


def fixtures():
    args = dict(user='fake-admin', csrf='fake')
    policy = policy_view(**args, caller='writer-demo', ops_by_tool={'notes-demo':[{'op':'read_note','risk':'read'}]}, current={'tools':{'notes-demo':{'read_note':'deny'}}})
    failed = policy_view(**args, caller='writer-demo', ops_by_tool={}, current={}, loaded=False, error='Policy could not be loaded. Retry load.')
    editor = tool_editor_view(**args, mode='edit', dir_value='/fake/notes',tool={'id':'notes-demo','type':'api','port':4700,'operations':[{'name':'absent'},{'name':'empty','approval_fields':[]},{'name':'explicit','approval_fields':['message']}]})
    tool = dict(id='notes-demo',port=4700,path='/fake/notes',running=True,alive=False,removable=False)
    recovery = tools_view(**args, tools=[tool],tools_root='/fake',focused=True,broker_port=8765)
    unknown = tools_view(**args, tools=[tool],tools_root='/fake',focused=True,broker_port=8765,error='notes-demo · restart outcome unknown. Refresh state before another action; nothing was replayed.',mutation_outcome='unknown')
    registered = tools_view(**args, tools=[{**tool,'alive':True}],tools_root='/fake',focused=True,broker_port=8765,catalog={'status':'verified','tool_ids':['notes-demo']},banner='notes-demo · Catalog registration verified.')
    added = tools_view(**args, tools=[{**tool,'running':False}],tools_root='/fake',focused=True,broker_port=8765,banner='Added notes-demo. Start executes this trusted local tool. Catalog registration and caller grants remain separate decisions.')
    registration = tools_view(**args, tools=[{**tool,'alive':True}],tools_root='/fake',focused=True,broker_port=8765)
    specs = [
      ('caller-rows',page('Callers',_callers_section([{'name':'writer-demo','revoked_at':None},{'name':'revoked-demo','revoked_at':1}],'fake'),**args),CALLER_ROWS,None),
      ('policy',policy,POLICY+POLICY_MORE,None),
      ('load-failure',failed,"check(document.querySelector('#policy-form [type=submit]').disabled,'failed load locks Save');check(document.body.textContent.includes('Retry load'),'failed load offers Retry');",None),
      ('editor',editor,EDITOR,None),
      ('confirmation',recovery,CONFIRM,None),
      ('returned-unknown',recovery,UNKNOWN_HTML,unknown),
      ('replacement',recovery,REPLACEMENT,recovery),
      ('add',tool_add_view(**args),"check(document.querySelector('[name=source]')!==null,'local host source remains editable');check(document.querySelector('form').method==='post','source action remains functional');",None),
      ('registered',registered,"check(document.body.textContent.includes('Catalog registration verified'),'registration receipt names success');check(!document.querySelector('[name=catalog_target]'),'verified catalog does not offer redundant registration');",None),
      ('added-stopped',added,"check(!document.querySelector('form[action$=\"/start\"] button').disabled,'added tool can be explicitly started');check(document.body.textContent.includes('Registration unknown'),'copy does not imply catalog registration');",None),
      ('register-confirm',registration,"document.querySelector('form[action=\"/broker/restart\"]').requestSubmit();check(document.querySelector('dialog[open]').textContent.includes('127.0.0.1:8765 for notes-demo'),'registration confirmation names broker and target');check(document.querySelector('dialog[open]').textContent.includes('interrupts'),'registration warns of interruption');check(document.activeElement.textContent==='Cancel','registration defaults to Cancel');",None),
    ]
    result=[]
    confirmation = page('Confirmation', '<form data-confirm="Revoke caller notes-demo?" method="post"><button>Revoke caller</button></form>', user=None)
    for width in (1180,360):
        result.append(dict(name=f'confirmation-open-{width}',html=instrument(confirmation,
            "document.querySelector('form[data-confirm]').requestSubmit();check(document.activeElement.textContent==='Cancel','confirmation defaults to Cancel');"),width=width,height=820))
    for width in (1180,620):
        result.append(dict(name=f'draft-open-{width}',html=instrument(policy,
            "const select=document.querySelector('#policy-form select');select.value='allow';document.querySelector('form[action=\"/logout\"]').requestSubmit();check(document.activeElement.textContent==='Stay','draft defaults to Stay');"),width=width,height=820))
    for name,html,checks,returned in specs:
        for width in (1440,1180):
            result.append(dict(name=f'{name}-{width}',html=instrument(html,checks,returned),width=width,height=900))
    result.append(dict(name='shell-startup-620',html=instrument(startup_error('http://127.0.0.1:8780','Admin exited with status 7 before /login responded.'),"check(document.body.textContent.includes('status 7'),'shell observed cause');check(document.querySelector('#retry')!==null,'shell Retry available');let retries=0;window.pywebview={api:{retry:()=>{retries++;}}};document.querySelector('#retry').click();document.querySelector('#retry').click();check(retries===1,'shell Retry button latches synthetic duplicate clicks');"),width=620,height=360))
    return result


if __name__ == '__main__':
    Path(sys.argv[1]).write_text(json.dumps(fixtures()))
