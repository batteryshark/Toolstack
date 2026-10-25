"""Rendered SVG bounds and overlap gate in existing isolated headless Chrome.

Allowed overlay: an element inside its explicitly declared ancestor container.
No blanket exclusions for text, panels, chrome, rails, or footers. Sibling
intersections and parent overflow fail. Stroke edge contact <=0.5px is tolerated.
"""
from pathlib import Path
import json, subprocess, tempfile, re, html

ROOT=Path(__file__).resolve().parent
screens=json.loads((ROOT/'evidence/screens.json').read_text())
JS=r'''
const frames=FRAMES, results=[], failures=[];
function check(svg){
 const nodes=[...svg.querySelectorAll('[data-id]')].map(e=>{
  const b=e.getBBox();return {id:e.dataset.id,parent:e.dataset.parent,kind:e.dataset.kind,
    text:e.tagName==='text'?e.textContent:'',x:b.x,y:b.y,w:b.width,h:b.height};});
 const map=Object.fromEntries(nodes.map(n=>[n.id,n]));
 const ancestor=(a,b)=>{let p=b.parent;while(p){if(p===a.id)return true;p=map[p]?.parent}return false};
 const inside=(a,b)=>a.x>=b.x-.5&&a.y>=b.y-.5&&a.x+a.w<=b.x+b.w+.5&&a.y+a.h<=b.y+b.h+.5;
 const errors=[];
 for(const a of nodes){
  if(!inside(a,{x:0,y:0,w:1440,h:900}))errors.push({type:'viewport overflow',a});
  if(a.parent&&!inside(a,map[a.parent]))errors.push({type:'parent overflow',a,parent:map[a.parent]});
 }
 for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){
  const a=nodes[i],b=nodes[j];if(ancestor(a,b)||ancestor(b,a))continue;
  const dx=Math.min(a.x+a.w,b.x+b.w)-Math.max(a.x,b.x),dy=Math.min(a.y+a.h,b.y+b.h)-Math.max(a.y,b.y);
  if(dx>.5&&dy>.5)errors.push({type:'unallowed overlap',a,b,dx,dy});
 }
 return {nodes,errors};
}
for(const [key,source] of Object.entries(frames)){
 document.querySelector('#stage').innerHTML=source;
 const {nodes,errors}=check(document.querySelector('svg'));
 results.push({frame:key,elements:nodes.length,errors,geometry:nodes});
 if(errors.length)failures.push(key);
}
// Regression: a root-level footer crosses a rail. It must be rejected.
document.querySelector('#stage').innerHTML='<svg width="1440" height="900"><rect data-id="root" data-parent="" data-kind="container" x="0" y="0" width="1440" height="900"/><rect data-id="rail" data-parent="root" data-kind="container" x="0" y="104" width="245" height="796"/><text data-id="footer" data-parent="root" data-kind="text" x="30" y="847">Native adaptation footer overlaps the rail</text></svg>';
const regression=check(document.querySelector('svg')).errors.some(e=>e.type==='unallowed overlap');
document.querySelector('#result').textContent=JSON.stringify({frames:results.length,failures,regression_footer_detected:regression,allowed_overlays:'Explicit ancestor/descendant containment only; edge tolerance 0.5px',results});
document.querySelector('#stage').remove();
'''
page='<html><meta charset="utf-8"><body><div id="stage"></div><pre id="result"></pre><script>'+JS.replace('FRAMES',json.dumps(screens).replace('</','<\\/'))+'</script></body></html>'
with tempfile.TemporaryDirectory(prefix='toolstack-geometry-',dir='/private/var/folders/pz/lrml3ths3mg3mf4bb75rmcvc0000gn/T/opencode') as tmp:
 p=Path(tmp);(p/'check.html').write_text(page)
 cmd=['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome','--headless','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-sync',f'--user-data-dir={p/"profile"}','--dump-dom',(p/'check.html').as_uri()]
 run=subprocess.run(cmd,capture_output=True,text=True,timeout=40)
 (ROOT/'evidence/geometry-renderer.log').write_text(run.stderr)
 assert run.returncode==0
 match=re.search(r'<pre id="result">(.*?)</pre>',run.stdout,re.S)
 assert match,'No geometry output'
 result=json.loads(html.unescape(match.group(1)))
 (ROOT/'evidence/geometry.json').write_text(json.dumps(result,indent=2))
 print(json.dumps({k:v for k,v in result.items() if k!='results'},indent=2))
 for frame in result['results']:
  if frame['errors']:print(frame['frame'],json.dumps(frame['errors'][:3]))
 assert result['frames']==81 and not result['failures'] and result['regression_footer_detected']
