"""Clear desk caller settings. No framework or additional service."""

CSS = r"""
dialog.caller-settings{width:900px;max-width:calc(100vw - 24px);max-height:calc(100dvh - 24px);padding:0;overflow:hidden;}
.caller-settings .settings-shell{display:flex;flex-direction:column;max-height:calc(100dvh - 30px);padding:20px;gap:12px;}
.caller-settings h2{margin:0;font-size:19px;overflow-wrap:anywhere;}
.settings-tabs{display:flex;gap:6px;border-bottom:1px solid var(--line);}
.settings-tabs button[aria-selected=true]{border-color:var(--accent);color:var(--accent);background:#e3edfc;}
.settings-filter{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
.settings-filter input[type=search]{flex:1;min-width:180px;}
.settings-filter label,.function-row label{display:flex;align-items:center;gap:8px;min-height:38px;}
.settings-list{overflow:auto;min-height:130px;max-height:55dvh;border:1px solid var(--line);border-radius:8px;}
.settings-group{border-bottom:1px solid var(--line);padding:10px;}
.settings-group:last-child{border-bottom:0;}
.settings-group-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
.settings-group-head .summary{flex:1;min-width:160px;color:#526173;}
.function-row{display:flex;gap:12px;align-items:center;padding:6px 10px 6px 30px;}
.function-row .function-name{flex:1;min-width:0;overflow-wrap:anywhere;}
.function-row select{width:125px;flex-shrink:0;}
.settings-footer{display:flex;gap:12px;align-items:center;flex-wrap:wrap;}
.settings-footer [role=status]{flex:1;min-width:150px;margin:0;color:#526173;}
.settings-footer .actions{margin-left:auto;gap:20px;}
.settings-stale{padding:10px;background:#fff6df;border-radius:6px;}
.settings-compare{width:780px;max-height:80dvh;overflow:auto;}
.settings-compare td{overflow-wrap:anywhere;}
@media(max-width:550px){.caller-settings .settings-shell{padding:12px;}.function-row{padding-left:8px;flex-wrap:wrap;}.settings-tabs button{padding:6px;}.settings-group-head{gap:6px;}}
"""

JS = r"""
window.ToolstackSettings=(()=>{
 const clone=x=>JSON.parse(JSON.stringify(x)), same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const effect=(s,t,o)=>s.tools[t]?.[o]||'deny';
 const active=(s,t,o)=>s.enabled.includes(t)&&!s.disabled_functions[t]?.includes(o);
 function values(s){
   const d={enabled:s.enabled.filter(t=>t in s.catalog).sort(),tools:{},disabled_functions:{}};
   Object.keys(s.catalog).sort().forEach(t=>{
     d.tools[t]={};d.disabled_functions[t]=[];
     s.catalog[t].forEach(o=>{d.tools[t][o.op]=s.policy.tools?.[t]?.[o.op]||'deny';
       if(s.policy.disabled_functions?.[t]?.includes(o.op))d.disabled_functions[t].push(o.op);});
   });return d;
 }
 function node(tag,text,attrs={}){const n=document.createElement(tag);if(text!==null)n.textContent=text;
   Object.entries(attrs).forEach(([k,v])=>n.setAttribute(k,v));return n;}
 function button(text,run,attrs={}){const b=node('button',text,{type:'button',...attrs});b.onclick=run;return b;}
 function open(initial,onClose=()=>{}){
   if(document.querySelector('.caller-settings'))return;
   let state=clone(initial),base=values(state),draft=clone(base),unknown=false,blocked=false,busy=false,writing=false,storageOK=true;
   let tab='enabled',query='',enabledOnly=false,reviewOnly=false,expanded=new Set(),scroll={enabled:0,policy:0};
   const key='toolstack.settings.v1:'+JSON.stringify([state.installation,state.operator,state.name,state.caller_id]);
   const url='/callers/'+encodeURIComponent(state.name)+'/settings';
   let saved=null;try{saved=JSON.parse(localStorage.getItem(key));}catch(e){storageOK=false;}
   if(saved?.state?.name===state.name&&saved?.state?.installation===state.installation){
     draft=saved.draft;base=saved.base;unknown=!!saved.unknown;blocked=!!saved.blocked;
     tab=saved.tab||tab;query=saved.query||'';enabledOnly=!!saved.enabledOnly;reviewOnly=!!saved.reviewOnly;
     expanded=new Set(saved.expanded||[]);scroll=saved.scroll||scroll;
     if(saved.state.revision!==state.revision)blocked=true;
     const freshCSRF=state.csrf;state=saved.state;state.csrf=freshCSRF;
   }
   const dialog=node('dialog',null,{class:'caller-settings','aria-label':'Caller settings for '+state.name});
   const shell=node('div',null,{class:'settings-shell'});dialog.append(shell);
   const heading=node('h2','Caller settings · '+state.name);shell.append(heading);
   const tabs=node('div',null,{class:'settings-tabs',role:'tablist','aria-label':'Caller settings tabs'});shell.append(tabs);
   const filter=node('div',null,{class:'settings-filter'}),search=node('input',null,{type:'search','aria-label':'Search tools and functions',placeholder:'Search tools and functions'});
   search.value=query;filter.append(search);
   function filterToggle(title,initial,change){const l=node('label',null),i=node('input',null,{type:'checkbox'});i.checked=initial;i.onchange=()=>change(i.checked);l.append(i,node('span',title));filter.append(l);return i;}
   const enabledFilter=filterToggle('Enabled only',enabledOnly,v=>{enabledOnly=v;render();});
   const reviewFilter=filterToggle('Needs review',reviewOnly,v=>{reviewOnly=v;render();});shell.append(filter);
   const count=node('div','',{role:'status'});shell.append(count);
   const stale=node('div',null,{class:'settings-stale'}),staleText=node('span','Changed elsewhere · Draft retained. ');
   const compare=button('Compare latest',()=>compareLatest());stale.append(staleText,compare);shell.append(stale);
   const list=node('div',null,{class:'settings-list',role:'tabpanel',id:'settings-panel',tabindex:'0'});shell.append(list);
   const scope=node('small','',{class:'muted'});shell.append(scope);
   const footer=node('div',null,{class:'settings-footer'}),status=node('p','',{role:'status'}),actions=node('div',null,{class:'actions'});
   const cancel=button('Cancel',()=>leave()),save=button('Save changes',()=>saveDraft(),{class:'primary'});
   actions.append(cancel,save);footer.append(status,actions);shell.append(footer);
   const dirty=()=>!same(base,draft);
   function persist(){try{if(dirty()||unknown||blocked||writing)localStorage.setItem(key,JSON.stringify({state:{...state,csrf:undefined},base,draft,unknown:unknown||writing,blocked,tab,query,enabledOnly,reviewOnly,expanded:[...expanded],scroll}));else localStorage.removeItem(key);storageOK=true;}
     catch(e){storageOK=false;status.textContent='Draft storage unavailable. Keep this window open or save before quitting.';}}
   function changed(){draft.enabled.sort();Object.values(draft.disabled_functions).forEach(a=>a.sort());persist();render();}
   function setFunction(t,o,v){const wasEnabled=draft.enabled.includes(t);
     if(v&&!wasEnabled){draft.enabled.push(t);draft.disabled_functions[t]=state.catalog[t].map(o=>o.op);}
     draft.disabled_functions[t]=draft.disabled_functions[t].filter(x=>x!==o);
     if(!v)draft.disabled_functions[t].push(o);
   }
   function setTool(t,v){draft.enabled=draft.enabled.filter(x=>x!==t);if(v){draft.enabled.push(t);draft.disabled_functions[t]=[];}changed();}
   function filtered(){const q=query.trim().toLowerCase();return Object.keys(state.catalog).sort().map(t=>[t,state.catalog[t].filter(o=>(!q||(t+' '+o.op+' '+(o.description||'')).toLowerCase().includes(q))&&(!enabledOnly||active(draft,t,o.op))&&(!reviewOnly||effect(draft,t,o.op)==='review'))]).filter(([t,ops])=>ops.length);}
   function render(){
     const focus=document.activeElement?.dataset.focus, top=list.scrollTop;tabs.replaceChildren();
     ['enabled','policy'].forEach((id,i)=>{const title=i?'Policy':'Enabled tools';
       const isDirty=i?!same(base.tools,draft.tools):!same([base.enabled,base.disabled_functions],[draft.enabled,draft.disabled_functions]);
       const b=button(title+(isDirty?' · Unsaved changes':''),()=>switchTab(id),{role:'tab','aria-selected':String(tab===id),'aria-controls':'settings-panel',id:'settings-tab-'+id,tabindex:tab===id?'0':'-1','data-focus':'tab-'+id});
       b.onkeydown=e=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(e.key)){e.preventDefault();switchTab(e.key==='Home'?'enabled':e.key==='End'?'policy':tab==='enabled'?'policy':'enabled');tabs.querySelector('[aria-selected=true]').focus();}};tabs.append(b);});
     list.setAttribute('aria-labelledby','settings-tab-'+tab);list.replaceChildren();
     const groups=filtered(),total=Object.values(state.catalog).reduce((n,a)=>n+a.length,0),matches=groups.reduce((n,[t,a])=>n+a.length,0);
     count.textContent=matches+' of '+total+' functions · '+groups.length+' tools';
     const filtering=!!query.trim()||enabledOnly||reviewOnly;
     scope.textContent=filtering?'All / None affect visible filtered matches only.':'All / None affect the whole tool. Enabling never grants Allow.';
     if(!groups.length){list.append(node('p','No matching functions.'));
       list.append(button('Clear filters',()=>{query='';search.value='';enabledOnly=false;reviewOnly=false;enabledFilter.checked=false;reviewFilter.checked=false;render();search.focus();}));}
     groups.forEach(([t,ops])=>{
       const group=node('div',null,{class:'settings-group'}),head=node('div',null,{class:'settings-group-head'});
       const isOpen=expanded.has(t)||filtering&&!expanded.has('closed:'+t),body=node('div',null,{id:'functions-'+t});body.hidden=!isOpen;
       head.append(button((isOpen?'▾ ':'▸ ')+t,()=>{if(isOpen){expanded.delete(t);expanded.add('closed:'+t);}else{expanded.add(t);expanded.delete('closed:'+t);}persist();render();},{'aria-expanded':String(isOpen),'aria-controls':'functions-'+t,'aria-label':t+' functions','data-focus':'group-'+t}));
       const allOps=state.catalog[t],n=allOps.filter(o=>active(draft,t,o.op)).length;
       head.append(node('span',n+'/'+allOps.length+' enabled'+(filtering?' · '+ops.length+' matches':''),{class:'summary'}));
       if(tab==='enabled'){
         const label=node('label',null),toggle=node('input',null,{type:'checkbox','aria-label':'Enable whole tool '+t,'data-focus':'tool-'+t});
         toggle.checked=n===allOps.length;toggle.indeterminate=n>0&&n<allOps.length;toggle.disabled=busy;
         toggle.onchange=()=>setTool(t,toggle.checked);label.append(toggle,node('span','Whole tool'));head.append(label);
         [true,false].forEach(v=>head.append(button((v?'All':'None')+(filtering?' matches':''),()=>{ops.forEach(o=>setFunction(t,o.op,v));changed();},{'aria-label':(v?'Enable ':'Disable ')+(filtering?'matched':'all')+' '+t+' functions','data-focus':'bulk-'+t+'-'+v})));}
       if(isOpen)ops.forEach(o=>{
         const row=node('div',null,{class:'function-row'}),title=node('div',o.op,{class:'function-name'});
         if(tab==='enabled'){const label=node('label',null,{class:'function-name'}),input=node('input',null,{type:'checkbox','aria-label':'Enable '+t+' / '+o.op,'data-focus':'enable-'+t+'.'+o.op});input.checked=active(draft,t,o.op);input.disabled=busy;input.onchange=()=>{setFunction(t,o.op,input.checked);changed();};label.append(input,title);row.append(label,node('small',effect(draft,t,o.op),{class:'muted'}));}
         else {row.append(title);if(!active(draft,t,o.op))row.append(node('small','Disabled',{class:'muted'}));const select=node('select',null,{'aria-label':'Policy for '+t+' / '+o.op,'data-focus':'effect-'+t+'.'+o.op});
           ['deny','review','allow'].forEach(v=>{const option=node('option',v[0].toUpperCase()+v.slice(1),{value:v});select.append(option);});select.value=effect(draft,t,o.op);select.disabled=busy;select.onchange=()=>{draft.tools[t][o.op]=select.value;changed();};row.append(select);}
         body.append(row);
       });group.append(head,body);list.append(group);
     });
     stale.hidden=!(blocked||unknown);staleText.textContent=unknown?'Save outcome unknown · Draft retained. ':'Changed elsewhere · Draft retained. ';
     save.disabled=busy||blocked||unknown||!dirty();cancel.disabled=busy;compare.disabled=busy;
     search.disabled=busy;enabledFilter.disabled=busy;reviewFilter.disabled=busy;
     list.querySelectorAll('button').forEach(b=>b.disabled=busy);
     if(storageOK)status.textContent=busy?'Saving both tabs…':dirty()?'Unsaved changes · Both tabs · Draft kept on this device':'No unsaved changes';
     list.scrollTop=top;
     if(focus){const control=[...dialog.querySelectorAll('[data-focus]')].find(n=>n.dataset.focus===focus);(control||search).focus();}
     persist();
   }
   function switchTab(id){scroll[tab]=list.scrollTop;tab=id;render();list.scrollTop=scroll[tab]||0;tabs.querySelector('[aria-selected=true]').focus();persist();}
   search.oninput=()=>{query=search.value;render();};
   list.onscroll=()=>{scroll[tab]=list.scrollTop;persist();};
   function close(){persist();dialog.close();dialog.remove();document.removeEventListener('visibilitychange',visible);window.removeEventListener('pagehide',persist);clearInterval(poll);onClose();}
   function leave(){if(busy)return;if(!dirty()&&!unknown){close();return;}
     const d=node('dialog',null,{'aria-label':'Leave settings for '+state.name+'?'});d.append(node('h2','Leave settings for '+state.name+'?'));
     const a=node('div',null,{class:'actions'}),stay=button('Stay',()=>d.close());a.append(stay,button('Keep draft and close',()=>{d.close();close();}),button('Discard draft',()=>{draft=clone(base);unknown=false;blocked=false;localStorage.removeItem(key);d.close();close();}));d.append(a);document.body.append(d);d.onclose=()=>d.remove();d.showModal();stay.focus();}
   dialog.addEventListener('cancel',e=>{e.preventDefault();leave();});
   async function request(options={}){const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
     try{const r=await fetch(url,{cache:'no-store',...options,signal:controller.signal,headers:{Accept:'application/json',...options.headers}});
       if(r.url&&new URL(r.url,location.href).pathname==='/login')throw Error('Session expired');return {response:r,data:await r.json()};}finally{clearTimeout(timer);}}
   async function observe(){if(busy||!dialog.open)return;const revision=state.revision;try{const {response,data}=await request();if(busy||!dialog.open||state.revision!==revision)return;if(!response.ok||data.name!==state.name||data.installation!==state.installation||data.caller_id!==state.caller_id)throw Error();
       if(data.revision!==state.revision){blocked=true;render();}}catch(e){if(busy||!dialog.open||state.revision!==revision)return;blocked=true;render();staleText.textContent='Latest settings unavailable · Draft retained. ';}}
   async function compareLatest(){if(busy)return;busy=true;render();let remote;
     try{const {response,data}=await request();if(!response.ok||data.name!==state.name||data.installation!==state.installation||data.caller_id!==state.caller_id)throw Error();remote=data;}
     catch(e){busy=false;blocked=true;render();staleText.textContent='Comparison unavailable · Draft retained. Sign in if needed, then retry. ';return;}
     busy=false;render();
     const latest=values(remote),d=node('dialog',null,{class:'settings-compare','aria-label':'Compare settings for '+state.name});
     d.append(node('h2','Compare · '+state.name),node('p','Your draft is unchanged. Keep only your explicit edits on the latest settings, or Stay.'));
     const table=node('table'),thead=node('thead'),tr=node('tr');['Setting','Your draft','Latest saved'].forEach(s=>tr.append(node('th',s)));thead.append(tr);table.append(thead);const tbody=node('tbody');table.append(tbody);let removed=false,rows=0;
     const merged=clone(latest);
     function diff(label,a,b){if(a===b)return;rows++;const row=node('tr');[label,a,b].forEach(x=>row.append(node('td',String(x))));tbody.append(row);}
     Object.keys(state.catalog).forEach(t=>{
       if(!(t in remote.catalog)){removed=true;diff(t,'Draft retained','Tool no longer available');return;}
       diff(t+' / whole tool',draft.enabled.includes(t),latest.enabled.includes(t));
       if(base.enabled.includes(t)!==draft.enabled.includes(t)){merged.enabled=merged.enabled.filter(x=>x!==t);if(draft.enabled.includes(t))merged.enabled.push(t);}
       state.catalog[t].forEach(o=>{
         if(!(o.op in latest.tools[t])){removed=true;diff(t+' / '+o.op,'Draft retained','Function no longer available');return;}
         diff(t+' / '+o.op,active(draft,t,o.op)+' / '+effect(draft,t,o.op),active(latest,t,o.op)+' / '+effect(latest,t,o.op));
         if(effect(base,t,o.op)!==effect(draft,t,o.op))merged.tools[t][o.op]=effect(draft,t,o.op);
         const excluded=s=>s.disabled_functions[t]?.includes(o.op)||false;
         if(excluded(base)!==excluded(draft)){merged.disabled_functions[t]=merged.disabled_functions[t].filter(x=>x!==o.op);if(excluded(draft))merged.disabled_functions[t].push(o.op);}
       });
     });
     if(!rows)d.append(node('p','Both tabs match the saved settings. No write is needed.'));else d.append(table);
     if(removed)d.append(node('p','The function set changed. Your original draft is retained; discard it explicitly and reopen to edit the new catalog.'));
     const a=node('div',null,{class:'actions'}),stay=button('Stay',()=>d.close());a.append(stay);
     if(!removed)a.append(button('Keep my edits on latest',()=>{state=remote;base=latest;draft=merged;draft.enabled.sort();blocked=false;unknown=false;d.close();changed();},{class:'primary'}));
     d.append(a);document.body.append(d);d.onclose=()=>d.remove();d.showModal();stay.focus();
   }
   async function saveDraft(){if(busy||blocked||unknown||!dirty())return;busy=true;writing=true;persist();render();
     const body=new URLSearchParams({_csrf:state.csrf,settings_json:JSON.stringify({revision:state.revision,...draft})});
     try{const {response,data}=await request({method:'POST',body});
       if(response.ok&&data.outcome==='saved'&&data.name===state.name&&data.policy&&same(values({...state,policy:data.policy,enabled:data.policy.enabled}),draft)){
         base=clone(draft);unknown=false;blocked=false;busy=false;writing=false;persist();close();return;
       }
       blocked=true;if(!(response.status>=400&&response.status<500&&data.outcome==='rejected'))unknown=true;
     }catch(e){blocked=true;unknown=true;}
     busy=false;writing=false;persist();render();compare.focus();
   }
   function visible(){if(!document.hidden)observe();}
   document.addEventListener('visibilitychange',visible);window.addEventListener('pagehide',persist);
   const poll=setInterval(observe,20000);
   document.body.append(dialog);render();dialog.showModal();tabs.querySelector('[aria-selected=true]').focus();
   if(saved)observe();
 }
 document.addEventListener('DOMContentLoaded',()=>{
   const payload=document.getElementById('caller-settings-state');if(payload)open(JSON.parse(payload.textContent),()=>location.assign('/'));
   document.querySelectorAll('a[data-settings-link]').forEach(link=>link.addEventListener('click',async e=>{
     e.preventDefault();if(link.dataset.loading)return;link.dataset.loading='true';
     try{const r=await fetch(link.href,{headers:{Accept:'application/json'},cache:'no-store'}),s=await r.json();if(!r.ok||!s.revision)throw Error();open(s,()=>link.closest('[data-caller-policy]')?.focus());}
     catch(e){location.assign(link.href);}finally{delete link.dataset.loading;}
   }));
 });
 return {open};
})();
"""
