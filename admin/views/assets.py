"""Static CSS/JS assets for the admin panel (plain constants, not f-strings,
so their braces need no escaping)."""


_CSS = """
:root{color-scheme:light;--bg:#f6f7f9;--ink:#18202a;--muted:#697483;--line:#d9dee7;--panel:#fff;--accent:#0d6efd;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 22px;background:#172033;color:#fff;}
header h1{font-size:18px;margin:0;font-weight:650;}
main{max-width:1100px;margin:0 auto;padding:22px;}
section{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:16px;}
h2{font-size:16px;margin:0 0 12px;}
h3{font-size:14px;margin:16px 0 8px;color:var(--muted);}
button,input,select{font:inherit;min-height:38px;border-radius:6px;border:1px solid var(--line);padding:6px 9px;background:#fff;}
button{background:#f3f5f8;cursor:pointer;}
button.primary,a.button.primary,#tool-form button[type=submit],.login button[type=submit]{background:var(--accent);border-color:var(--accent);color:#fff;}
button:disabled{opacity:.5;cursor:not-allowed;}
a.button{display:inline-flex;align-items:center;min-height:38px;border-radius:6px;border:1px solid var(--line);padding:6px 9px;background:#f3f5f8;color:var(--ink);text-decoration:none;}
table{width:100%;border-collapse:collapse;}
td,th{border-top:1px solid var(--line);padding:8px;text-align:left;vertical-align:middle;}
code{background:#eef1f5;padding:2px 5px;border-radius:5px;overflow-wrap:anywhere;}
pre{background:#0d1117;color:#e6edf3;padding:12px;border-radius:6px;overflow:auto;max-height:240px;font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;}
.toolbar,.inline-form,header form,.actions,.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
.banner{background:#e9f8ef;border:1px solid #a9dfbc;padding:12px;border-radius:8px;margin-bottom:16px;}
.error{background:#fff0f0;border:1px solid #efb3b3;padding:12px;border-radius:8px;color:#8c1f1f;margin-bottom:16px;}
.muted{color:var(--muted);}
.login{max-width:380px;margin:60px auto;display:grid;gap:12px;}
.login label{display:grid;gap:6px;}
.field{display:grid;gap:6px;margin-bottom:12px;max-width:520px;}
.pill{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;}
.pill.ok{background:#e9f8ef;color:#1c7a3f;}
.pill.bad{background:#ffe8e8;color:#8c1f1f;}
.pill.muted{background:#eef1f5;color:#697483;}
.risk{display:inline-block;border-radius:999px;padding:2px 8px;font-size:12px;background:#eef1f5;color:#333;}
.risk.read{background:#e8f5ff;color:#185d8f;}
.risk.write{background:#fff6df;color:#7a5100;}
.risk.destructive{background:#ffe8e8;color:#8c1f1f;}
.card{border:1px solid var(--line);border-radius:8px;padding:12px;margin:10px 0;background:#fbfcfe;}
.argrow,.headerrow,.rulerow{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:6px 0;}
.argrow input,.headerrow input{min-width:120px;}
.rulerow input,.rulerow select{min-width:130px;}
.rest-sub{display:grid;gap:6px;margin-top:8px;}
details.opcard-acc>summary,details.sub-acc>summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:8px;padding:2px 0;}
details.opcard-acc>summary::-webkit-details-marker,details.sub-acc>summary::-webkit-details-marker{display:none;}
details.opcard-acc>summary::before,details.sub-acc>summary::before{content:'\\25B8';color:var(--muted);transition:transform .1s ease;}
details[open].opcard-acc>summary::before,details[open].sub-acc>summary::before{transform:rotate(90deg);}
details.opcard-acc>summary{font-weight:600;}
.op-title.muted{font-weight:400;}
.op-sub,.acc-count{color:var(--muted);font-weight:400;font-size:12px;}
.sub-acc{border-top:1px dashed var(--line);padding-top:6px;}
.linkish{background:transparent;border:none;color:var(--muted);cursor:pointer;padding:2px 6px;font:inherit;font-size:12px;text-decoration:underline;}
.linkish:hover{color:var(--ink);}
.sechead,.secrow{display:grid;grid-template-columns:1.3fr 1.3fr 1.2fr 70px 80px;gap:8px;align-items:center;margin:6px 0;}
.sechead{font-size:12px;color:var(--muted);font-weight:600;margin:12px 0 2px;}
.secrow input{min-width:0;width:100%;}
.colcenter{justify-self:center;text-align:center;}
.brand{display:flex;align-items:center;gap:18px;}
nav.appnav{display:flex;gap:4px;align-items:center;}
nav.appnav a{color:#c7d0dc;text-decoration:none;padding:6px 12px;border-radius:6px;font-weight:550;}
nav.appnav a:hover{background:rgba(255,255,255,.08);color:#fff;}
nav.appnav a.active{background:rgba(255,255,255,.16);color:#fff;}
.tabs{display:flex;flex-wrap:wrap;gap:4px;border-bottom:1px solid var(--line);margin-bottom:16px;}
.tab-button{background:transparent;border:1px solid transparent;border-bottom:none;border-radius:8px 8px 0 0;padding:8px 16px;color:var(--muted);cursor:pointer;font-weight:550;}
.tab-button:hover{color:var(--ink);}
.tab-button.active{background:var(--panel);border-color:var(--line);color:var(--ink);margin-bottom:-1px;}
.tab-panel.hidden{display:none;}
.filterbar{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;}
.filterbar input[type=search]{flex:1;min-width:200px;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink);}
.filterbar select{padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink);}
select,.filterbar select{-webkit-appearance:none;appearance:none;height:38px;min-height:38px;padding-right:30px;color:var(--ink);background-image:linear-gradient(45deg,transparent 50%,var(--muted) 50%),linear-gradient(135deg,var(--muted) 50%,transparent 50%);background-position:calc(100% - 14px) 16px,calc(100% - 9px) 16px;background-size:5px 5px;background-repeat:no-repeat;}
.audit-latest{background:#fff9df;}
:focus-visible{outline:3px solid #0d6efd;outline-offset:3px;}
[data-caller-policy]{cursor:pointer;}
dialog{max-width:min(520px,90vw);border:1px solid var(--line);border-radius:8px;padding:24px;color:var(--ink);}
dialog .actions{justify-content:flex-end;gap:20px;}
dialog::backdrop{background:#17203366;}
@media(max-width:1000px){main{padding:14px;}section{overflow-x:auto;}header{flex-wrap:wrap;gap:12px;}}
"""


_JS = """
document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('form[data-confirm]').forEach(form=>{
    let accepted=false;
    form.addEventListener('submit',e=>{
      if(accepted)return;e.preventDefault();
      const dialog=document.createElement('dialog'), message=document.createElement('p');
      message.textContent=form.dataset.confirm;dialog.setAttribute('aria-label',form.dataset.confirm);dialog.append(message);
      const cancel=document.createElement('button'), proceed=document.createElement('button');
      cancel.textContent='Cancel';cancel.autofocus=true;
      proceed.textContent=form.dataset.confirm.split('?')[0];
      const actions=document.createElement('div');actions.className='actions';
      actions.append(cancel,proceed);dialog.append(actions);document.body.append(dialog);
      cancel.onclick=()=>dialog.close();
      proceed.onclick=()=>{accepted=true;dialog.close();form.requestSubmit();};
      dialog.addEventListener('close',()=>dialog.remove());dialog.showModal();cancel.focus();
    });
  });
  document.querySelectorAll('form[data-confirm],form[data-mutation]').forEach(form=>{
    let inFlight=false, uncertain=false;
    const scope=form.closest('tr')||form.closest('section')||form;
    if(document.querySelector('[data-mutation-outcome="unknown"]')){
      scope.dataset.mutationUnknown='true';scope.querySelectorAll('button').forEach(b=>b.disabled=true);
    }
    form.addEventListener('submit',async e=>{
      if(e.defaultPrevented)return;
      e.preventDefault();if(inFlight||uncertain||scope.dataset.mutationUnknown==='true')return;
      inFlight=true;
      const body=new URLSearchParams(new FormData(form));
      const buttons=Array.from(form.querySelectorAll('button'));
      buttons.forEach(b=>b.disabled=true);
      const status=document.createElement('p');status.setAttribute('role','status');
      status.textContent='Applying requested change…';form.append(status);
      const controller=new AbortController(), timer=setTimeout(()=>controller.abort(),30000);
      try{
        const response=await fetch(form.action,{method:'POST',body,signal:controller.signal});
        if(!response.ok||new URL(response.url).pathname==='/login')throw Error('No acknowledgement');
        if(response.headers?.get('X-Toolstack-Mutation-Outcome')==='unknown')throw Error('Unknown stage receipt');
        const html=await response.text();
        if(!html.includes('<main>'))throw Error('No acknowledgement');
        const returned=new DOMParser().parseFromString(html,'text/html');
        if(returned.querySelector('[data-mutation-outcome="unknown"]'))throw Error('Unknown stage receipt');
        document.open();document.write(html);document.close();
      }catch(error){
        scope.dataset.mutationUnknown='true';scope.querySelectorAll('button').forEach(b=>b.disabled=true);
        uncertain=true;status.textContent='Outcome unknown. Target and inputs retained. Refresh state before deciding on another action; nothing was replayed.';
        const refresh=document.createElement('a');refresh.className='button';
        const path=new URL(form.action).pathname, target=form.querySelector('[name=catalog_target]');
        refresh.href=target?'/tools?tool='+encodeURIComponent(target.value):
          path.startsWith('/toolyard/tools/')?'/tools?tool='+encodeURIComponent(decodeURIComponent(path.split('/')[3])):
          path.startsWith('/callers/')?'/#callers':path.startsWith('/audit/')?'/#audit':'/tools';
        refresh.textContent='Refresh state';status.after(refresh);
      }finally{clearTimeout(timer);inFlight=false;}
    });
  });
});
document.addEventListener('DOMContentLoaded', function(){
  const form=document.getElementById('policy-form');
  if(!form || form.dataset.loaded!=='true') return;
  const save=form.querySelector('button[type=submit]'), target=form.dataset.target;
  const status=document.createElement('p');status.setAttribute('role','status');
  form.querySelector('section').append(status);
  const compare=document.createElement('button');compare.type='button';compare.textContent='Reload to compare';compare.hidden=true;
  status.after(compare);
  const currentPage=document.createElement('a');currentPage.href=form.action;currentPage.textContent='Load current policy page';currentPage.hidden=true;compare.after(currentPage);
  const fields=()=>Array.from(form.querySelectorAll('select[name^="op__"]'));
  const snapshot=()=>JSON.stringify(fields().map(s=>[s.name,s.value]));
  let baseline=snapshot(), unknown=false, busy=false, blocked=false;
  const sessionMessage='Session expired · Sign in in another tab, then Reload to compare. Draft retained.';
  async function request(url,options,format='text'){
    const controller=new AbortController(), timer=setTimeout(()=>controller.abort(),15000);
    try{const response=await fetch(url,{...options,signal:controller.signal});
      if(response.url && new URL(response.url,location.href).pathname==='/login')throw new Error('Session expired');
      const data=await response[format]();return {response,data};
    }finally{clearTimeout(timer);}
  }
  const dirty=()=>snapshot()!==baseline;
  function state(text){status.textContent=text+' · '+target;}
  form.addEventListener('change',()=>{if(!blocked)state(unknown?'Save outcome unknown · Reload to compare before retrying':(dirty()?'Unsaved changes':'No unsaved changes'));});
  function resume(){if(dirty()&&!busy&&!unknown&&!blocked&&!status.textContent.includes('rejected'))state('Resume policy draft');}
  document.addEventListener('visibilitychange',()=>{if(!document.hidden)resume();});
  window.addEventListener('pageshow',resume);
  window.addEventListener('beforeunload',e=>{if(dirty()||busy||unknown){e.preventDefault();e.returnValue='';}});
  function leaveDraft(proceed){
    const d=document.createElement('dialog'), title=document.createElement('h2');
    title.textContent='Leave policy draft · '+target+'?';d.setAttribute('aria-label',title.textContent);d.append(title);
    const stay=document.createElement('button');stay.textContent='Stay';stay.autofocus=true;
    const discard=document.createElement('button');discard.textContent='Discard draft';
    discard.disabled=busy;
    const actions=document.createElement('div');actions.className='actions';
    actions.append(stay,discard);d.append(actions);document.body.append(d);
    stay.onclick=()=>d.close();discard.onclick=()=>{baseline=snapshot();unknown=false;d.close();proceed();};
    d.addEventListener('close',()=>d.remove());d.showModal();stay.focus();
  }
  document.addEventListener('click',e=>{
    const link=e.target.closest('a[href]');if(!link||(!dirty()&&!unknown&&!busy))return;
    e.preventDefault();leaveDraft(()=>{location.href=link.href;});
  });
  document.addEventListener('submit',e=>{
    if(e.target===form||(!dirty()&&!unknown&&!busy))return;
    e.preventDefault();const destination=e.target;leaveDraft(()=>destination.requestSubmit());
  },true);
  form.addEventListener('submit',async e=>{
    e.preventDefault();if(busy||unknown||blocked)return;
    busy=true;save.disabled=true;state('Saving');
    const body=new URLSearchParams(new FormData(form));
    fields().forEach(s=>s.disabled=true);
    try{
      const {response,data:result}=await request(form.action,{method:'POST',headers:{Accept:'application/json'},body},'json');
      if(response.ok && result.outcome==='saved' && result.target===target){baseline=snapshot();form.querySelectorAll('.saved-effect').forEach(n=>n.remove());state('Policy saved');}
      else if((response.status===400||response.status===403)&&result.outcome==='rejected'){blocked=true;compare.hidden=false;state('Save rejected · Draft retained. '+(result.error||'Reload to compare before saving.'));}
      else throw new Error('No receipt');
    }catch(error){blocked=true;compare.hidden=false;
      if(error.message==='Session expired')state('Save rejected · '+sessionMessage);
      else{unknown=true;state('Save outcome unknown · Draft retained. Reload to compare before retrying');}}
    finally{busy=false;fields().forEach(s=>s.disabled=false);save.disabled=unknown||blocked;save.classList.toggle('primary',!save.disabled);compare.classList.toggle('primary',save.disabled);if(save.disabled)compare.focus();}
  });
  compare.onclick=async()=>{
    if(busy)return;busy=true;save.disabled=true;
    compare.disabled=true;state('Loading saved policy for comparison');
    try{
      const {response,data:html}=await request(form.action,{cache:'no-store'});
      const doc=new DOMParser().parseFromString(html,'text/html');
      const loaded=doc.querySelector('#policy-form[data-loaded="true"]');
      if(!response.ok||!loaded||loaded.dataset.target!==target)throw new Error('Load failed');
      const saved=Array.from(loaded.querySelectorAll('select[name^="op__"]'));
      if(saved.length!==fields().length||fields().some(s=>!saved.some(v=>v.name===s.name)))throw new Error('Operation set changed');
      const matches=fields().every(s=>saved.some(v=>v.name===s.name&&v.value===s.value));
      baseline=JSON.stringify(fields().map(s=>[s.name,saved.find(v=>v.name===s.name).value]));
      form.querySelector('[name=_csrf]').value=loaded.querySelector('[name=_csrf]').value;
      unknown=false;blocked=false;save.disabled=false;compare.hidden=true;currentPage.hidden=true;currentPage.className='';
      if(matches){baseline=snapshot();state('Saved policy matches draft');}
      else{state('Saved policy differs · Draft retained. Review before saving');
        fields().forEach(s=>{let note=s.parentElement.querySelector('.saved-effect');if(!note){note=document.createElement('small');note.className='saved-effect';s.after(note);}note.textContent=' Saved: '+saved.find(v=>v.name===s.name).value;});}
    }catch(error){blocked=true;
      const prior=unknown?'Save outcome unknown · ':'';
      if(error.message==='Session expired')state(prior+sessionMessage);
      else if(error.message==='Operation set changed'){currentPage.hidden=false;currentPage.className='button';state(prior+'Operation set changed · Draft retained. Load the current policy page to review available operations; leaving requires discarding this draft.');}
      else state(prior+'Comparison unavailable · Draft retained. Retry load');
    }finally{busy=false;save.disabled=unknown||blocked;compare.disabled=false;save.classList.toggle('primary',!save.disabled);compare.classList.toggle('primary',save.disabled);if(save.disabled)(currentPage.hidden?compare:currentPage).focus();else save.focus();}
  };
});
function setAll(effect){document.querySelectorAll('select[name^="op__"]').forEach(function(s){s.value=effect;});}
function setTool(tool,effect){document.querySelectorAll('select[name^="op__'+tool+'__"]').forEach(function(s){s.value=effect;});}
function showTab(name){
  document.querySelectorAll('[data-tab-panel]').forEach(function(p){
    p.classList.toggle('hidden', p.getAttribute('data-tab-panel')!==name);});
  document.querySelectorAll('.tab-button').forEach(function(b){
    b.classList.toggle('active', b.getAttribute('data-tab')===name);});
}
document.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('[data-caller-policy]').forEach(function(row){
    row.addEventListener('dblclick', function(event){
      // Nested actions keep their own meaning; never turn a revoke/rotate into navigation.
      if(event.target.closest('a,button,input,select,textarea,form,summary,[role="button"],[role="menu"],[contenteditable]')) return;
      row.querySelector('[data-policy-link]').click();
    });
    row.addEventListener('keydown', function(event){
      if(event.key==='Enter' && event.target===row && !event.repeat){
        event.preventDefault();
        row.querySelector('[data-policy-link]').click();
      }
    });
  });
});
document.addEventListener('DOMContentLoaded', function(){
  var tabs = document.querySelectorAll('.tab-button');
  if(!tabs.length) return;
  tabs.forEach(function(b){b.addEventListener('click', function(){
    var n=b.getAttribute('data-tab'); showTab(n); history.replaceState(null,'','#'+n);});});
  var want=(location.hash||'').replace('#','');
  if(!want || !document.querySelector('[data-tab-panel="'+want+'"]'))
    want=tabs[0].getAttribute('data-tab');
  showTab(want);
});

// Client-side row filter for the Requests + Audit tables: a text box (matches the row text:
// caller, tool.op, event, details) AND an optional outcome/status dropdown (matches data-key).
function filterTable(tableId){
  var box = document.querySelector('[data-filter-for="'+tableId+'"]');
  var sel = document.querySelector('[data-filter-sel="'+tableId+'"]');
  var q = (box ? box.value : '').toLowerCase();
  var key = sel ? sel.value : '';
  document.querySelectorAll('#'+tableId+' tbody tr[data-row]').forEach(function(tr){
    var textOk = tr.textContent.toLowerCase().indexOf(q) >= 0;
    var keyOk = !key || tr.getAttribute('data-key') === key;
    tr.style.display = (textOk && keyOk) ? '' : 'none';
  });
}
document.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('[data-filter-for]').forEach(function(el){
    el.addEventListener('input', function(){filterTable(el.getAttribute('data-filter-for'));});});
  document.querySelectorAll('[data-filter-sel]').forEach(function(el){
    el.addEventListener('change', function(){filterTable(el.getAttribute('data-filter-sel'));});});
});
"""


# Tool editor: builds repeating operation/argument/secret rows from real widgets,
# pre-fills from window.TOOL_INITIAL, and serializes everything into the hidden
# tool_json field on submit, so the operator never types TOML or JSON by hand.
_TOOL_EDITOR_JS = """
(function(){
  var ARG_TYPES = ["string","number","integer","boolean","object","array"];
  var RISK_CHOICES = ["read","write","destructive"];
  var TOOL_TYPES = ["api","mcp","rest"];   // matches admin TOOL_TYPES
  var REST_VERBS = ["GET","POST","PUT","PATCH","DELETE"];
  var REST_BODY_KINDS = ["none","text","binary"];
  var REST_RULE_RESPONSE_TYPES = ["json","xml","form","plaintext"];
  function mk(html){var t=document.createElement('template');t.innerHTML=html.trim();return t.content.firstChild;}
  function opts(values, sel){return values.map(function(v){return '<option'+(v===sel?' selected':'')+'>'+v+'</option>';}).join('');}
  function riskOpts(sel){return RISK_CHOICES.indexOf(sel)<0 ? [sel].concat(RISK_CHOICES) : RISK_CHOICES;}
  function currentSecretNames(){
    return [].map.call(document.querySelectorAll('#secrets .sec-name'), function(n){return n.value.trim();}).filter(Boolean);
  }
  function secretOpts(sel){
    var values = currentSecretNames();
    if (sel && values.indexOf(sel) < 0) values.unshift(sel);
    if (!values.length) values = [""];
    return opts(values, sel||values[0]||"");
  }
  function refreshRuleSecretOptions(){
    [].forEach.call(document.querySelectorAll('.rule-secret'), function(sel){
      var chosen = sel.value || sel.getAttribute('data-selected') || '';
      sel.innerHTML = secretOpts(chosen);
      if (chosen) sel.value = chosen;
    });
  }

  function argRow(a){
    a = a||{};
    var row = mk('<div class="argrow"><input class="arg-name" placeholder="arg name">'
      + '<select class="arg-type">'+opts(ARG_TYPES, a.type||'string')+'</select>'
      + '<label><input type="checkbox" class="arg-req"> required</label>'
      + '<input class="arg-desc" placeholder="description">'
      + '<button type="button" class="rm">remove</button></div>');
    row.querySelector('.arg-name').value = a.name||'';
    row.querySelector('.arg-req').checked = !!a.required;
    row.querySelector('.arg-desc').value = a.description||'';
    row.querySelector('.rm').onclick = function(){row.remove();};
    return row;
  }
  function headerRow(h, onChange){
    var row = mk('<div class="headerrow"><input class="header-name" placeholder="Header-Name">'
      + '<button type="button" class="rm">remove</button></div>');
    row.querySelector('.header-name').value = h||'';
    row.querySelector('.rm').onclick = function(){row.remove(); if(onChange)onChange();};
    return row;
  }
  function ruleRow(r, onChange){
    r = r||{};
    var row = mk('<div class="rulerow">'
      + '<select class="rule-secret"></select>'
      + '<select class="rule-response-type">'+opts(REST_RULE_RESPONSE_TYPES, r.response_type||'json')+'</select>'
      + '<input class="rule-extract-path" placeholder="extract path">'
      + '<input class="rule-match-status" placeholder="2xx or 200">'
      + '<button type="button" class="rm">remove</button></div>');
    row.querySelector('.rule-secret').setAttribute('data-selected', r.secret_name||'');
    row.querySelector('.rule-secret').innerHTML = secretOpts(r.secret_name||'');
    if (r.secret_name) row.querySelector('.rule-secret').value = r.secret_name;
    row.querySelector('.rule-extract-path').value = r.extract_path||'';
    row.querySelector('.rule-match-status').value = r.match_status||'2xx';
    row.querySelector('.rm').onclick = function(){row.remove(); if(onChange)onChange();};
    return row;
  }
  function staticHeaderRow(name, value){
    var row = mk('<div class="static-headerrow"><input class="static-header-name" placeholder="Authorization">'
      + '<input class="static-header-value" placeholder="Bearer {{secret:api_token}}">'
      + '<button type="button" class="rm">remove</button></div>');
    row.querySelector('.static-header-name').value = name||'';
    row.querySelector('.static-header-value').value = value||'';
    row.querySelector('.rm').onclick = function(){row.remove();};
    return row;
  }
  function opCard(o, open){
    o = o||{};
    var card = mk('<div class="card opcard"><details class="opcard-acc"><summary>'
      + '<span class="op-title"></span><span class="op-sub"></span></summary>'
      + '<div class="row">'
      + '<input class="op-name" placeholder="operation name">'
      + '<select class="op-risk">'+opts(riskOpts(o.risk||'read'), o.risk||'read')+'</select>'
      + '<input class="op-desc" placeholder="description">'
      + '<button type="button" class="dup-op">duplicate op</button>'
      + '<button type="button" class="rm rm-op">remove op</button></div>'
      + '<div class="row op-rest">'
      + '<select class="op-verb">'+opts(REST_VERBS, o.verb||'GET')+'</select>'
      + '<input class="op-path" placeholder="/items/{item_id}">'
      + '<select class="op-body-kind">'+opts(REST_BODY_KINDS, o.body_kind||'none')+'</select>'
      + '<input class="op-body-content-type" placeholder="body content type"></div>'
      + '<details class="op-rest rest-sub sub-acc"><summary><strong>Allowed headers</strong><span class="acc-count headers-count"></span></summary>'
      + '<div class="headers"></div>'
      + '<button type="button" class="add-header">add header</button></details>'
      + '<details class="op-rest rest-sub sub-acc"><summary><strong>Operator-owned secret placement</strong></summary>'
      + '<p>Only these templates may reference secrets. Caller headers and bodies must contain no secret placeholders.</p>'
      + '<div class="static-headers"></div><button type="button" class="add-static-header">add operator header</button>'
      + '<label>Allowed secrets (comma-separated)<input class="op-allowed-secrets"></label>'
      + '<label><input type="checkbox" class="op-template-enabled"> Use operator body template (text bodies only)</label>'
      + '<textarea class="op-body-template" placeholder="Operator-authored body"></textarea>'
      + '<label><input type="checkbox" class="op-legacy-substitution"> Legacy caller substitution — move references above, then uncheck to save</label></details>'
      + '<details class="op-rest rest-sub sub-acc"><summary><strong>Response redaction</strong><span class="acc-count redact-count"></span></summary>'
      + '<label class="op-redact"><input type="checkbox" class="op-redact-body"> Redact response body from the caller</label>'
      + '<label class="op-redact"><input type="checkbox" class="op-redact-headers"> Redact response headers from the caller</label></details>'
      + '<details class="op-rest rest-sub sub-acc"><summary><strong>Secret writeback rules</strong><span class="acc-count rules-count"></span></summary>'
      + '<div class="rules"></div>'
      + '<button type="button" class="add-rule">add rule</button></details>'
      + '<div class="args"></div><button type="button" class="add-arg">add argument</button></details></div>');
    card.querySelector('.op-name').value = o.name||'';
    card.querySelector('.op-desc').value = o.description||'';
    card.querySelector('.op-verb').value = o.verb||'GET';
    card.querySelector('.op-path').value = o.path||'';
    card.querySelector('.op-body-kind').value = o.body_kind||'none';
    card.querySelector('.op-body-content-type').value = o.body_content_type||'';
    card.querySelector('.op-legacy-substitution').checked = !!o.body_substitution;
    card.querySelector('.op-allowed-secrets').value = (o.allowed_secrets||[]).join(', ');
    card.querySelector('.op-template-enabled').checked = o.body_template != null;
    card.querySelector('.op-body-template').value = o.body_template||'';
    var staticHeaders = card.querySelector('.static-headers');
    Object.keys(o.headers||{}).forEach(function(name){staticHeaders.appendChild(staticHeaderRow(name, o.headers[name]));});
    card.querySelector('.add-static-header').onclick = function(){staticHeaders.appendChild(staticHeaderRow());};
    if (staticHeaders.children.length || o.body_template != null || o.body_substitution) staticHeaders.closest('details').open = true;
    // Nonvisual metadata: retain absence versus an explicit empty allowlist.
    if (Object.prototype.hasOwnProperty.call(o, 'approval_fields')) card._approval_fields = o.approval_fields;
    card.querySelector('.op-redact-body').checked = !!o.redact_response_body;
    card.querySelector('.op-redact-headers').checked = !!o.redact_response_headers;
    var args = card.querySelector('.args');
    var headers = card.querySelector('.headers');
    var rules = card.querySelector('.rules');
    var headersCount = card.querySelector('.headers-count');
    var rulesCount = card.querySelector('.rules-count');
    function updHeaders(){var n=headers.children.length; headersCount.textContent = n ? ' ('+n+')' : '';}
    function updRules(){var n=rules.children.length; rulesCount.textContent = n ? ' ('+n+')' : '';}
    var redactBody = card.querySelector('.op-redact-body');
    var redactHeaders = card.querySelector('.op-redact-headers');
    var redactCount = card.querySelector('.redact-count');
    function updRedact(){redactCount.textContent = (redactBody.checked || redactHeaders.checked) ? ' (on)' : '';}
    var titleEl = card.querySelector('.op-title');
    var subEl = card.querySelector('.op-sub');
    function updTitle(){
      var name = card.querySelector('.op-name').value.trim();
      titleEl.textContent = name || '(unnamed operation)';
      titleEl.classList.toggle('muted', !name);
      var isRest = document.getElementById('f_type').value === 'rest';
      var path = card.querySelector('.op-path').value.trim();
      subEl.textContent = isRest ? (card.querySelector('.op-verb').value + (path ? ' ' + path : '')) : '';
    }
    card._updTitle = updTitle;
    (o.args||[]).forEach(function(a){args.appendChild(argRow(a));});
    (o.allowed_headers||[]).forEach(function(h){headers.appendChild(headerRow(h, updHeaders));});
    (o.secret_update_rules||[]).forEach(function(r){rules.appendChild(ruleRow(r, updRules));});
    updHeaders(); updRules(); updRedact(); updTitle();
    // Sub-sections start expanded only when they already carry data.
    if (headers.children.length) headers.closest('details').open = true;
    if (rules.children.length) rules.closest('details').open = true;
    if (redactBody.checked || redactHeaders.checked) redactBody.closest('details').open = true;
    card.querySelector('.add-arg').onclick = function(){args.appendChild(argRow());};
    card.querySelector('.add-header').onclick = function(){headers.appendChild(headerRow('', updHeaders)); updHeaders();};
    card.querySelector('.add-rule').onclick = function(){rules.appendChild(ruleRow('', updRules)); refreshRuleSecretOptions(); updRules();};
    card.querySelector('.op-name').addEventListener('input', updTitle);
    card.querySelector('.op-path').addEventListener('input', updTitle);
    card.querySelector('.op-verb').addEventListener('change', updTitle);
    redactBody.addEventListener('change', updRedact);
    redactHeaders.addEventListener('change', updRedact);
    card.querySelector('.dup-op').onclick = function(){
      var copy = serializeOp(card);
      copy.name = copy.name ? copy.name + '_copy' : '';
      card.after(opCard(copy, true));
      syncType();
    };
    card.querySelector('.rm-op').onclick = function(){card.remove();};
    card.querySelector('.opcard-acc').open = (open === undefined) ? !(o.name) : !!open;
    return card;
  }
  function serializeOp(card){
    var headers = [].map.call(card.querySelectorAll('.headerrow .header-name'), function(h){return h.value.trim();}).filter(Boolean);
    var rules = [].map.call(card.querySelectorAll('.rulerow'), function(r){
      return {secret_name: r.querySelector('.rule-secret').value,
              response_type: r.querySelector('.rule-response-type').value,
              extract_path: r.querySelector('.rule-extract-path').value,
              match_status: r.querySelector('.rule-match-status').value};
    }).filter(function(r){return r.secret_name || r.extract_path;});
    var operation = {name: card.querySelector('.op-name').value,
            risk: card.querySelector('.op-risk').value,
            description: card.querySelector('.op-desc').value,
            verb: card.querySelector('.op-verb').value,
            path: card.querySelector('.op-path').value,
            allowed_headers: headers,
            body_kind: card.querySelector('.op-body-kind').value,
            body_content_type: card.querySelector('.op-body-content-type').value,
            body_substitution: card.querySelector('.op-legacy-substitution').checked,
            headers: Object.fromEntries([].map.call(card.querySelectorAll('.static-headerrow'), function(r){
              return [r.querySelector('.static-header-name').value.trim(), r.querySelector('.static-header-value').value];
            }).filter(function(h){return h[0];})),
            allowed_secrets: card.querySelector('.op-allowed-secrets').value.split(',').map(function(s){return s.trim();}).filter(Boolean),
            body_template: card.querySelector('.op-template-enabled').checked ? card.querySelector('.op-body-template').value : null,
            redact_response_body: card.querySelector('.op-redact-body').checked,
            redact_response_headers: card.querySelector('.op-redact-headers').checked,
            secret_update_rules: rules,
            args: [].map.call(card.querySelectorAll('.argrow'), function(r){
              return {name: r.querySelector('.arg-name').value,
                      type: r.querySelector('.arg-type').value,
                      required: r.querySelector('.arg-req').checked,
                      description: r.querySelector('.arg-desc').value};
            })};
    if (Object.prototype.hasOwnProperty.call(card, '_approval_fields')) operation.approval_fields = card._approval_fields;
    return operation;
  }
  function secRow(s){
    s = s||{};
    var row = mk('<div class="secrow"><input class="sec-name" placeholder="e.g. api_key">'
      + '<input class="sec-field" placeholder="e.g. API_KEY">'
      + '<input class="sec-item" placeholder="tool id or path">'
      + '<span class="colcenter"><input type="checkbox" class="sec-writable"></span>'
      + '<button type="button" class="rm">remove</button></div>');
    row.querySelector('.sec-name').value = s.name||'';
    row.querySelector('.sec-field').value = s.field||'';
    row.querySelector('.sec-item').value = s.item||'';
    row.querySelector('.sec-writable').checked = !!s.writable;
    row.querySelector('.sec-name').addEventListener('input', refreshRuleSecretOptions);
    row.querySelector('.rm').onclick = function(){row.remove(); refreshRuleSecretOptions();};
    return row;
  }

  var initial = window.TOOL_INITIAL || {};
  document.getElementById('f_id').value = initial.id||'';
  document.getElementById('f_type').innerHTML = opts(TOOL_TYPES, initial.type||'api');
  document.getElementById('f_command').value = initial.command||'';
  document.getElementById('f_image').value = initial.image||'';
  document.getElementById('f_description').value = initial.description||'';
  document.getElementById('f_base_url').value = initial.base_url||'';
  document.getElementById('f_port').value = initial.port||'';
  var ops = document.getElementById('ops');
  (initial.operations && initial.operations.length ? initial.operations : [{}]).forEach(function(o){ops.appendChild(opCard(o));});
  var secs = document.getElementById('secrets');
  (initial.secrets||[]).forEach(function(s){secs.appendChild(secRow(s));});
  refreshRuleSecretOptions();
  document.getElementById('add-op').onclick = function(){ops.appendChild(opCard()); syncType();};
  document.getElementById('add-secret').onclick = function(){secs.appendChild(secRow()); refreshRuleSecretOptions();};
  function setAllOps(open){[].forEach.call(ops.querySelectorAll('.opcard-acc'), function(d){d.open=open;});}
  document.getElementById('ops-expand').onclick = function(){setAllOps(true);};
  document.getElementById('ops-collapse').onclick = function(){setAllOps(false);};
  var f_type = document.getElementById('f_type');

  function syncType(){
    var isRest = f_type.value === 'rest';
    document.getElementById('rest-fields').hidden = !isRest;
    [].forEach.call(document.querySelectorAll('.op-rest'), function(el){el.style.display = isRest ? '' : 'none';});
    [].forEach.call(document.querySelectorAll('.opcard .args, .opcard .add-arg'), function(el){el.style.display = isRest ? 'none' : '';});
    if (isRest && !document.getElementById('f_command').value) {
      document.getElementById('f_command').value = 'python3 -m toolstack_forwarder';
    }
    [].forEach.call(ops.querySelectorAll('.opcard'), function(c){ if(c._updTitle) c._updTitle(); });
  }
  f_type.addEventListener('change', syncType);
  syncType();

  var parseBtn = document.getElementById('oai-parse');
  if (parseBtn) {
    var parsedSpec = null;
    parseBtn.onclick = function(){
      var err = document.getElementById('oai-error');
      err.hidden = true;
      var body = new URLSearchParams();
      body.append('spec', document.getElementById('oai-spec').value);
      body.append('_csrf', document.querySelector('input[name=_csrf]').value);
      fetch('/tools/parse-openapi', {method: 'POST', body: body})
        .then(function(r){ return r.json().then(function(j){ return {ok: r.ok, j: j}; }); })
        .then(function(res){
          if (!res.ok) { err.textContent = (res.j && res.j.error) || 'parse failed'; err.hidden = false; return; }
          parsedSpec = res.j;
          var box = document.getElementById('oai-ops');
          box.innerHTML = '';
          (parsedSpec.operations || []).forEach(function(op, idx){
            var row = mk('<label class="oai-op"><input type="checkbox" data-i="'+idx+'" checked> '
              + '<code></code> <b></b> <span class="muted"></span></label>');
            row.querySelector('code').textContent = op.verb + ' ' + op.path;
            row.querySelector('b').textContent = ' ' + op.name + ' ';
            row.querySelector('.muted').textContent = op.description || '';
            box.appendChild(row);
          });
          document.getElementById('oai-base').textContent = parsedSpec.base_url ? ('Base URL: ' + parsedSpec.base_url) : 'No server URL in the spec.';
          document.getElementById('oai-results').hidden = false;
        })
        .catch(function(){ err.textContent = 'parse failed'; err.hidden = false; });
    };
    document.getElementById('oai-add').onclick = function(){
      if (!parsedSpec) return;
      f_type.value = 'rest';
      if (parsedSpec.base_url) document.getElementById('f_base_url').value = parsedSpec.base_url;
      document.getElementById('f_command').value = 'python3 -m toolstack_forwarder';
      ops.innerHTML = '';
      [].forEach.call(document.querySelectorAll('#oai-ops input[type=checkbox]:checked'), function(c){
        ops.appendChild(opCard(parsedSpec.operations[+c.getAttribute('data-i')]));
      });
      (parsedSpec.secrets || []).forEach(function(s){
        var exists = [].some.call(secs.querySelectorAll('.sec-name'), function(n){ return n.value === s.name; });
        if (!exists) secs.appendChild(secRow(s));
      });
      syncType();
      document.getElementById('import-openapi').open = false;
    };
  }

  document.getElementById('tool-form').addEventListener('submit', function(){
    var tool = {
      id: document.getElementById('f_id').value,
      type: document.getElementById('f_type').value,
      description: document.getElementById('f_description').value,
      base_url: document.getElementById('f_base_url').value,
      command: document.getElementById('f_command').value,
      image: document.getElementById('f_image').value,
      port: document.getElementById('f_port').value,
      operations: [].map.call(ops.querySelectorAll('.opcard'), serializeOp),
      secrets: [].map.call(secs.querySelectorAll('.secrow'), function(r){
        return {name: r.querySelector('.sec-name').value,
                field: r.querySelector('.sec-field').value,
                item: r.querySelector('.sec-item').value,
                writable: r.querySelector('.sec-writable').checked};
      })
    };
    document.getElementById('tool_json').value = JSON.stringify(tool);
  });
})();
"""
