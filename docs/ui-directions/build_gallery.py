"""Revision 02 design drawings only. Stdlib; no product imports or network."""
from pathlib import Path
from html import escape as E
import json

ROOT=Path(__file__).resolve().parent
INK,MUTED,LINE,BLUE,NAV='#18202a','#526173','#d9dee7','#0d6efd','#172033'
DIRECTIONS={
 'a':('01 · Clear desk','Familiar navigation; lowest migration cost.','Less persistent collection context.'),
 'b':('02 · Operator workbench','Selected entity stays visible.','More width and scanning.'),
 'c':('03 · Guided ledger','Explicit task sequence.','More stage navigation for experts.')}
FLOWS={'grant':('Caller access',['Enable tool','Edit policy','Saved policy']),
       'add':('Local folder',['Add folder','Start tool','Register in broker']),
       'recover':('Crash recovery',['Inspect failure','Confirm restart','Check outcome'])}
PRIMARY={('grant',0):'Enable notes-demo',('grant',1):'Retry save',('grant',2):'Back to callers',
         ('add',0):'Add from folder',('add',1):'Start weather-demo',('add',2):'Restart local broker',
         ('recover',0):'Review restart',('recover',1):'Restart notes-demo',('recover',2):'Refresh state'}

class SVG:
 def __init__(self,title,native=False):
  self.s=[f'<svg xmlns="http://www.w3.org/2000/svg" width="1440" height="900" viewBox="0 0 1440 900" role="img" aria-label="{E(title)}"><title>{E(title)}</title>', '<style>text{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}</style>']
  self.parent='';self.n=0;self.native=native
 def attrs(self,kind):
  self.n+=1
  return f'data-id="e{self.n}" data-parent="{self.parent}" data-kind="{kind}"'
 def box(self,x,y,w,h,fill='#fff',stroke=LINE,r=7,kind='container'):
  self.s.append(f'<rect {self.attrs(kind)} x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}"/>')
  return f'e{self.n}'
 def text(self,x,y,t,size=16,color=INK,weight=400):
  self.s.append(f'<text {self.attrs("text")} x="{x}" y="{y}" font-size="{size}" fill="{color}" font-weight="{weight}">{E(t)}</text>')
 def button(self,x,y,t,primary=False,w=170,selected=False):
  parent=self.parent;h=32 if self.native else 38
  self.parent=self.box(x,y,w,h,BLUE if primary else '#e3edfc' if selected else '#fff',BLUE if primary else LINE,5,'control')
  self.text(x+12,y+(22 if self.native else 25),t,14 if self.native else 16,'#fff' if primary else INK,550)
  self.parent=parent
 def row(self,x,y,w,label,value):
  parent=self.parent;self.parent=self.box(x,y,w,43,'#fff',LINE,0)
  self.text(x+14,y+28,label,15);self.text(x+w*.55,y+28,value,15,MUTED)
  self.parent=parent
 def notice(self,x,y,w,lines,error=False):
  parent=self.parent;self.parent=self.box(x,y,w,18+len(lines)*24,'#fff0f0' if error else '#fff6df','#efb3b3' if error else '#e4cc94',5)
  for i,line in enumerate(lines):self.text(x+14,y+26+i*24,line,15,'#8c1f1f' if error else '#765000')
  self.parent=parent
 def end(self):return ''.join(self.s)+'</svg>'

def screen(d,surface,flow,step):
 native=surface=='mac';p=SVG(f'{DIRECTIONS[d][0]} / {surface} / {flow} / {step}',native)
 root=p.box(0,0,1440,900,'#f6f7f9',LINE,0);p.parent=root
 # Only true ancestor/descendant containment is allowed by the overlap checker.
 bar=p.box(0,0,1440,64 if native else 40,'#edeff3',LINE,0);p.parent=bar
 for i,col in enumerate(['#ff6058','#ffbd2e','#28c840']):p.box(20+i*22,20 if native else 14,12,12,col,col,6,'decoration')
 p.text(110,38 if native else 26,'Toolstack Operator' if native else 'Toolstack · desktop shell' if surface=='shell' else 'Toolstack Admin',16,INK,600)
 p.text(1130,38 if native else 26,'Design mockup · 02',14,MUTED)
 p.parent=root
 if not native:
  nav=p.box(0,40,1440,64,NAV,NAV,0);p.parent=nav
  p.text(28,80,'▤  Toolstack',23,'#fff',650)
  if d!='b':
   for i,t in enumerate(['Dashboard','Tools','Config']):p.text(285+i*145,79,t,17,'#fff' if t==('Dashboard' if flow=='grant' else 'Tools') else '#c7d0dc',550)
  p.text(1110,79,'Local admin',16,'#c7d0dc')
  p.parent=root
 entity='writer-demo' if flow=='grant' else 'weather-demo' if flow=='add' else 'notes-demo'
 section='Callers' if flow=='grant' else 'Tools'
 if d=='a':
  if native:
   nav=p.box(0,64,1440,54,'#f4f5f7',LINE,0);p.parent=nav
   for i,t in enumerate(['Callers','Tools','Activity','Config']):p.button(405+i*150,75,t,w=140,selected=t==section)
   p.parent=root
   x,w,top=302,836,186
  else:x,w,top=96,1248,158
 elif d=='b':
  rail=p.box(0,64 if native else 104,220,836 if native else 796,'#eef1f5' if native else NAV,LINE,0);p.parent=rail
  for i,t in enumerate(['Callers','Tools','Requests','Config']):
   y=105+i*48 if native else 145+i*48
   if t==section:
    selected=p.box(12,y-24,196,38,'#dceaff' if native else '#314965','none',5);p.parent=selected
   p.text(28,y,t,16,INK if native else '#e2e9f2',550);p.parent=rail
  p.parent=root
  collection=p.box(220,64 if native else 104,245,836 if native else 796,'#f9fafc',LINE,0);p.parent=collection
  p.text(242,103 if native else 143,section,17,INK,600)
  names=['writer-demo','reader-demo'] if flow=='grant' else ['weather-demo','notes-demo','echo-demo']
  for i,t in enumerate(names):p.button(232,(126 if native else 166)+i*48,t,w=221,selected=t==entity)
  p.parent=root;x,w,top=497,911,158 if native else 196
 else:
  rail=p.box(0,64 if native else 104,260,836 if native else 796,'#edf3fc',LINE,0);p.parent=rail
  p.text(24,106 if native else 146,FLOWS[flow][0],18,INK,600)
  for i,t in enumerate(FLOWS[flow][1]):p.button(16,(134 if native else 174)+i*56,f'{i+1}  {t}',w=228,selected=i==step)
  p.parent=root;x,w,top=304,1096,158 if native else 196
 p.text(x,top-18,section+' / '+entity,16,MUTED,550)
 titles={'grant':['Enable notes-demo','Policy','Saved policy'], 'add':['Add a local folder','Start weather-demo','Restart local broker?'], 'recover':['notes-demo · Process absent','Restart notes-demo?','Restart outcome unknown']}
 p.text(x,top+23,titles[flow][step],25 if native else 28,INK,650)
 # Scope is a single compact identifier line, not an empty inspector column.
 scope='writer-demo  /  notes-demo  /  read_note' if flow=='grant' else 'Local admin  /  weather-demo' if flow=='add' else 'Local admin  /  notes-demo'
 p.text(x,top+56,scope,15,MUTED)
 y=top+80
 heights={'grant':[192,291,190],'add':[286,276,254],'recover':[234,250,228]}
 panel=p.box(x,y,w,heights[flow][step],'#fff',LINE,8);p.parent=panel
 xx=x+24;ww=w-48
 if flow=='grant':
  if step==0:
   p.row(xx,y+20,ww,'Tool access','Disabled for writer-demo')
   p.row(xx,y+63,ww,'Operation policy','Not granted')
  elif step==1:
   p.notice(xx,y+18,ww,['Save rejected · Draft retained'],True)
   p.text(xx,y+100,'read_note',16,INK,600)
   # Segmented value selection is not a second primary action.
   for i,t in enumerate(['Deny','Human review','Allow']):p.button(xx+220+i*145,y+76,t,w=136,selected=i==2)
   p.row(xx,y+129,ww,'write_note','Deny')
   p.text(xx,y+201,'Unsaved changes',14,MUTED)
  else:
   p.row(xx,y+20,ww,'read_note','Allow · Saved 10:42')
   p.row(xx,y+63,ww,'write_note','Deny')
 elif flow=='add':
  if step==0:
   p.text(xx,y+35,'Folder path on admin host',15,INK,550)
   field=p.box(xx,y+48,ww,42);p.parent=field;p.text(xx+12,y+75,'/srv/demo-tools/weather-demo',16);p.parent=panel
   p.text(xx,y+120,'Copy into managed tools',15,MUTED)
   p.button(xx,y+177,'Import OpenAPI…',w=190)
  elif step==1:
   p.row(xx,y+20,ww,'Folder','Added')
   p.row(xx,y+63,ww,'Process','Stopped')
   p.row(xx,y+106,ww,'Broker catalog','Not registered')
   p.text(xx,y+185,'Process runner · Trusted tools only',15,MUTED)
  else:
   p.row(xx,y+20,ww,'Broker','127.0.0.1:8765')
   p.row(xx,y+63,ww,'Catalog update','weather-demo')
   p.notice(xx,y+125,ww,['Interrupts broker availability and active calls.'])
 elif flow=='recover':
  if step==0:
   p.row(xx,y+20,ww,'Process','Not alive · 10:42')
   p.row(xx,y+63,ww,'Runner record','Running')
   p.text(xx,y+137,'Failure · Process absent',15,'#8c1f1f',550)
  elif step==1:
   p.row(xx,y+20,ww,'Runner','Process')
   p.notice(xx,y+83,ww,['Stops the recorded instance; starts notes-demo.','Previous requests are not replayed.'])
  else:
   p.notice(xx,y+20,ww,['Connection lost before restart result.','Outcome unknown · Refresh before retrying.'])
   p.text(xx,y+126,'Last observed: process absent · 10:42',15,MUTED)
 # Native dialogs use right-aligned compact standard-sized actions.
 bottom=y+heights[flow][step]-57
 primary=PRIMARY[flow,step]
 pw=210 if len(primary)>18 else 180
 ax=x+w-24-pw if native else xx
 p.button(ax,bottom,primary,True,pw)
 secondary='Cancel' if (flow,step) in [('grant',0),('add',0),('recover',1)] else 'Keep editing' if (flow,step)==('grant',1) else 'Not now' if (flow,step)==('add',2) else 'Refresh state' if (flow,step)==('recover',0) else None
 if secondary:
  sx=ax-158 if native else ax+pw+14
  p.button(sx,bottom,secondary,w=144)
 return p.end()

def build():
 out=ROOT/'visuals';out.mkdir(exist_ok=True)
 screens={f'{d}-{s}-{f}-{n}':screen(d,s,f,n) for d in DIRECTIONS for s in ('web','shell','mac') for f in FLOWS for n in range(3)}
 for key,svg in screens.items():(out/(key+'.svg')).write_text(svg)
 (ROOT/'evidence'/'screens.json').write_text(json.dumps(screens))
 style='''*{box-sizing:border-box}body{margin:0;background:#f6f7f9;color:#18202a;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}header{background:#172033;color:white;padding:16px 28px}h1{font-size:24px;margin:0}main{padding:20px 28px}label{display:inline-flex;flex-direction:column;margin-right:18px;font-size:14px}select,button{font:inherit;padding:8px 12px;border:1px solid #aab7c8;border-radius:5px;background:#fff;color:#18202a;min-height:38px}a{color:#0754b9}button:focus-visible,select:focus-visible,a:focus-visible{outline:3px solid #0d6efd;outline-offset:3px}.viewport{overflow:auto;border:1px solid #d9dee7;margin-top:18px;background:#fff}.viewport svg{display:block;width:1440px;height:900px}.viewport.fit svg{width:100%;height:auto}.summary{margin:14px 0}.columns{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:20px}.columns svg{display:block;width:100%;height:auto;background:#fff}.columns article{min-width:0}.columns h2{font-size:20px}.columns p{font-size:14px}figure{margin:16px 0}figcaption{font-size:14px;margin:4px 0}@media(max-width:900px){.columns{grid-template-columns:1fr}}'''
 html='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Toolstack directions · revision 02</title><style>STYLE</style><header><h1>Toolstack / Directions · revision 02</h1></header><main><label>Direction<select id="direction"><option value="a">01 · Clear desk</option><option value="b">02 · Operator workbench</option><option value="c">03 · Guided ledger</option></select></label><label>Surface<select id="surface"><option value="web">Admin web</option><option value="shell">Desktop shell</option><option value="mac">Native Mac</option></select></label><label>Flow<select id="flow"><option value="grant">Caller access</option><option value="add">Local folder</option><option value="recover">Crash recovery</option></select></label><label>Frame<select id="step"></select></label><button id="fit">Fit to width</button><a href="overview.html">Comparison overview</a><p class="summary" id="summary"></p><div class="viewport" id="viewport"></div></main><script>const screens=SCREENS,directions=DIRECTIONS,flows=FLOWS;const $=id=>document.getElementById(id);function stages(){const old=$('step').value;$('step').replaceChildren(...flows[$('flow').value][1].map((s,i)=>new Option(s,i)));$('step').value=old||'0'}function show(){const d=$('direction').value,k=[d,$('surface').value,$('flow').value,$('step').value].join('-');$('viewport').innerHTML=screens[k];$('summary').textContent=directions[d][1]+' Tradeoff: '+directions[d][2];history.replaceState(null,'','#'+k)}for(const id of ['direction','surface','step'])$(id).onchange=show;$('flow').onchange=()=>{stages();show()};$('fit').onclick=()=>{const fit=$('viewport').classList.toggle('fit');$('fit').textContent=fit?'Show at 100%':'Fit to width'};const init=location.hash.slice(1).split('-');if(screens[init.join('-')]){$('direction').value=init[0];$('surface').value=init[1];$('flow').value=init[2];stages();$('step').value=init[3]}else stages();show();</script></html>'''
 html=html.replace('STYLE',style).replace('SCREENS',json.dumps(screens).replace('</','<\\/')).replace('DIRECTIONS',json.dumps(DIRECTIONS)).replace('FLOWS',json.dumps(FLOWS))
 (ROOT/'gallery.html').write_text(html)
 board=f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Toolstack comparison · revision 02</title><style>{style}</style><header><h1>Toolstack / Three directions</h1></header><main><p>Recommendation: <strong>01 · Clear desk</strong> · Revision 02 · Selection pending</p><p><a href="gallery.html">Full desktop-size gallery · all 81 frames</a></p><div class="columns">'
 for d,(name,merit,trade) in DIRECTIONS.items():
  board+=f'<article><h2>{E(name)}</h2><p>{E(merit)}<br>Tradeoff: {E(trade)}</p>'
  for s,f,n,label in [('web','grant',1,'Admin web · rejected policy save'),('shell','add',2,'Desktop shell · broker restart'),('mac','recover',0,'Native Mac · crashed tool')]:
   key=f'{d}-{s}-{f}-{n}';board+=f'<figure>{screens[key]}<figcaption><a href="gallery.html#{key}">{label} ↗</a></figcaption></figure>'
  board+='</article>'
 board+='</div></main></html>'; (ROOT/'overview.html').write_text(board)
 print('Revision 02: 81 SVGs, self-contained gallery and comparison overview')

if __name__=='__main__':build()
