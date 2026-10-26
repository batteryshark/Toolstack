"""600-function production editor, entirely fake and offscreen."""
from admin.views.settings import settings_view


def state():
    return dict(name="writer-demo", caller_id=1, operator="fake-admin", installation="fake-installation", revision="one", csrf="fake",
                enabled=["tool00"], policy={"tools": {"tool00": {"fn01": "review"}}},
                catalog={f"tool{t:02}": [{"op": f"fn{o:02}", "risk": "read", "description": "Fake function"}
                                         for o in range(20)] for t in range(30)})


CHECKS = r"""
const initial=JSON.parse(document.getElementById('caller-settings-state').textContent);
let remote=JSON.parse(JSON.stringify(initial)),posts=0,mode='read';
window.fetch=async(url,options={})=>{
 if(options.method==='POST'){posts++;if(mode==='unknown')throw Error('lost receipt');return {ok:false,status:409,json:async()=>({outcome:'rejected'})};}
 return {ok:true,status:200,json:async()=>remote};
};
const dlg=()=>document.querySelector('.caller-settings'),get=(s)=>dlg().querySelector(s);
const named=(s)=>[...document.querySelectorAll('dialog[open] button')].find(n=>n.textContent===s);
const focus=(s)=>get('[data-focus="'+s+'"]');
const type=q=>{const s=get('input[type=search]');s.value=q;s.dispatchEvent(new Event('input',{bubbles:true}));};
check(!!dlg()&&dlg().getAttribute('aria-label')==='Caller settings for writer-demo','named modal popup');
check(document.activeElement.getAttribute('role')==='tab','focus enters selected tab');
check(get('[role=status]').textContent.includes('600'),'600 functions counted');
check(dlg().querySelectorAll('.settings-group').length===30,'30 collapsed tool groups');
check(dlg().querySelectorAll('.function-row').length===0,'collapsed groups do not create 600 controls');
focus('tool-tool01').click();focus('group-tool01').click();
check(dlg().querySelectorAll('.function-row input:checked').length===20,'whole tool enables all 20 functions');
focus('tab-policy').click();
const pick=focus('effect-tool01.fn01');pick.value='review';pick.dispatchEvent(new Event('change',{bubbles:true}));
check(document.activeElement===get('input[type=search]')||document.activeElement.dataset.focus==='tab-policy','tab switch retains keyboard focus');
type('fn01');check(dlg().querySelectorAll('.function-row').length===30,'search opens matching groups across all tools');
check(focus('effect-tool01.fn01').value==='review','policy edit survives search');
focus('tab-enabled').click();focus('bulk-tool00-false').focus();focus('bulk-tool00-false').click();
check(!focus('enable-tool00.fn01').checked,'None matches disables filtered function');
check(document.activeElement.dataset.focus==='bulk-tool00-false','bulk rerender retains focus');
type('fn02');check(focus('enable-tool00.fn02').checked,'None matches leaves hidden functions unchanged');
type('fn01');focus('tab-policy').click();check(focus('effect-tool01.fn01').value==='review','both tabs share one draft');
const selected=get('[role=tab][aria-selected=true]');selected.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowRight',bubbles:true}));
check(get('[role=tab][aria-selected=true]').id==='settings-tab-enabled','Right arrow wraps tabs');
get('[role=tab][aria-selected=true]').dispatchEvent(new KeyboardEvent('keydown',{key:'End',bubbles:true}));
check(get('[role=tab][aria-selected=true]').id==='settings-tab-policy','End selects last tab');
type('no-such-function');check(dlg().textContent.includes('No matching functions'),'empty search recovery');
named('Clear filters').click();check(get('input[type=search]').value==='','clear filters restores groups');
check(document.activeElement===get('input[type=search]'),'empty recovery focuses search');
remote.revision='two';remote.policy.tools.tool00.fn02='allow';
named('Save changes').click();await wait(100);
check(posts===1&&named('Save changes').disabled,'stale rejection blocks Save without replay');
named('Compare latest').click();await wait(100);
let comparison=document.querySelector('.settings-compare');
check(!!comparison&&comparison.textContent.includes('Your draft')&&comparison.textContent.includes('Latest saved'),'side-by-side comparison');
check(document.activeElement.textContent==='Stay','comparison defaults to Stay');
named('Keep my edits on latest').click();
type('fn02');check(focus('effect-tool00.fn02').value==='allow','explicit rebase keeps remote unedited policy');
type('fn01');check(focus('effect-tool01.fn01').value==='review','explicit rebase retains local policy edit');
focus('tab-enabled').click();check(!focus('enable-tool00.fn01').checked,'explicit rebase retains function exclusion');
mode='unknown';named('Save changes').click();await wait(100);
check(posts===2&&named('Save changes').disabled&&dlg().textContent.includes('Save outcome unknown'),'lost receipt blocks replay');
named('Save changes').click();check(posts===2,'duplicate unknown save sends no request');
dlg().dispatchEvent(new Event('cancel',{cancelable:true}));
check(document.activeElement.textContent==='Stay','Escape dismissal defaults to Stay');
document.activeElement.click();check(!!dlg(),'Stay retains popup');
named('Cancel').click();named('Keep draft and close').click();await wait(100);
check(!dlg(),'explicit keep-draft close');
ToolstackSettings.open(remote);await wait(100);
check(dlg().querySelector('input[type=search]').value==='fn01','durable draft restores shared search on reopen');
check(named('Save changes').disabled&&dlg().textContent.includes('Save outcome unknown'),'durable unknown outcome cannot replay after reopen');
check(!focus('enable-tool00.fn01').checked,'durable draft restores enablement');
named('Compare latest').click();await wait(100);named('Stay').click();
check(posts===2,'comparison never sends a mutation');
named('Cancel').click();named('Discard draft').click();await wait(100);
ToolstackSettings.open(remote);await wait(100);
check(named('Save changes').disabled&&get('input[type=search]').value==='','discard explicitly starts clean');
check(localStorage.length===0,'draft storage cleared after discard');
type('fn01');focus('tab-policy').click();
"""


def settings_fixtures(instrument):
    html = settings_view(user="fake-admin", csrf="fake", caller="writer-demo", state=state())
    result = [dict(name=f"caller-settings-{width}", html=instrument(html, CHECKS), width=width, height=900)
              for width in (1180, 620, 390)]
    result.append(dict(name="caller-settings-save-1180", html=instrument(html, SAVE_CHECKS), width=1180, height=900))
    return result


SAVE_CHECKS = r"""
const initial=JSON.parse(document.getElementById('caller-settings-state').textContent);
const d=()=>document.querySelector('.caller-settings');
const named=s=>[...d().querySelectorAll('button')].find(n=>n.textContent===s);
const control=s=>d().querySelector('[data-focus="'+s+'"]');
const search=d().querySelector('[type=search]');search.value='fn01';search.dispatchEvent(new Event('input'));
const filters=d().querySelectorAll('.settings-filter [type=checkbox]');filters[1].click();
check(d().querySelectorAll('.function-row').length===1,'Needs review shows only Review policies');
control('tab-policy').click();const effect=control('effect-tool00.fn01');effect.focus();effect.value='allow';effect.dispatchEvent(new Event('change'));
check(document.activeElement===search,'filter removing edited row returns focus to search');
check(d().textContent.includes('No matching functions'),'review filter responds to changed policy');
named('Clear filters').click();control('tab-enabled').click();control('tool-tool01').click();
let posts=0,ack;
window.fetch=async(url,options)=>{
 check(options.method==='POST','single combined mutation uses POST');posts++;
 const form=new URLSearchParams(options.body),body=JSON.parse(form.get('settings_json'));
 check(form.get('_csrf')==='fake'&&body.revision==='one','combined Save carries CSRF and loaded revision');
 check(body.enabled.includes('tool01')&&body.tools.tool00.fn01==='allow','combined Save includes both tab edits');
 check(Object.keys(body.tools).length===30&&Object.values(body.tools).reduce((n,x)=>n+Object.keys(x).length,0)===600,'combined Save includes exactly the observed 600-function scope');
 return new Promise(resolve=>{ack=()=>resolve({ok:true,status:200,json:async()=>({outcome:'saved',name:initial.name,policy:body})});});
};
named('Save changes').click();named('Save changes').click();
check(posts===1&&named('Save changes').disabled,'in-flight duplicate Save is latched');
check([...d().querySelectorAll('.settings-list button,input,select')].every(x=>x.disabled),'in-flight edits cannot change the submitted draft');
const entry=JSON.parse(localStorage.getItem(localStorage.key(0)));
check(entry.unknown===true,'interrupted in-flight write is durably blocked before dispatch');
ack();await wait(100);
check(!d()&&localStorage.length===0,'exact combined receipt closes editor and clears durable draft');
check(posts===1,'successful Save never replays');
"""
