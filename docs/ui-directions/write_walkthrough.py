"""Produce an explicit source-design Norman record for every revised view."""
from build_gallery import ROOT, DIRECTIONS, FLOWS, PRIMARY

notes={
 ('grant',0):('Enablement gate','Named Enable button beside Disabled state','Disabled → policy only on acknowledged enable','Disabled label teaches gate','Direct enable opens policy','Retain caller/tool on failed enable'),
 ('grant',1):('Rejected-save recovery','Retry save beside retained policy','Save rejected; unsaved changes retained','Named scope identifies the edit','Retry without reopening menu','Stay in editor; keep draft on failure'),
 ('grant',2):('Mutation receipt','Back to callers below saved rows','Saved time and per-operation effects','Receipt confirms exact grant','Return without rereading guidance','Receipt stays tied to caller'),
 ('add',0):('Host-path import','Labeled path and Add from folder','Populated host path; copy mode','Host label avoids client-path ambiguity','Enter one path; no tutorial','Keep path and import draft on failure'),
 ('add',1):('Explicit code execution','Start weather-demo below stopped state','Folder added; stopped; catalog unregistered','Separate Start from import','Named Start is direct','Preserve added folder on start failure'),
 ('add',2):('Broker interruption decision','Restart local broker beside Not now','Broker endpoint and catalog target visible','Consequence warning remains','One named confirmation','Not now retains registration stage'),
 ('recover',0):('Recover actual process failure','Review restart under observed failure','Not alive separate from running record','Failure points to recovery','Immediate recovery entry','Refresh retains selected tool'),
 ('recover',1):('Target-specific restart consent','Named Restart beside Cancel','Stop/start consequence; no request replay','Target and consequence before commit','One confirmation','Cancel returns to same failed tool'),
 ('recover',2):('Reconcile lost response','Refresh state beside Unknown outcome','Connection lost; outcome unknown','Unknown does not mean safe retry','Refresh rather than blind restart','Retain last observation and target')}
out=['# Revision 02 — per-view Norman walkthrough',
 'All 81 views are recorded below. These are source-design counts, not observed usability. Pictured SVG controls do not execute product actions. One primary activation advances each populated fixture; add-folder requires an additional field entry from blank. Full proposed paths remain grant 6, add/start/register 7, recover 5, including navigation and final verification not all depicted. Reading, waits, retries and login are excluded. No speed or reduction claim.',
 'Q1 earned place; Q2 findable signifier; Q3 source-counted task cost and primary; Q4 visible state; Q5 first use / hundredth use / interruption. Interruption behavior is a design requirement, not persistence evidence.',
 'A entry: familiar top navigation / native tabs. B entry: persistent collection selection / native source list. C entry: task-stage rail / native source list. Shell content is the web composition. No independent shell policy model.']
for d in DIRECTIONS:
 for s in ('web','shell','mac'):
  for f in FLOWS:
   for n in range(3):
    key=f'{d}-{s}-{f}-{n}';earned,find,state,first,hundred,interrupt=notes[f,n]
    out += [f'## {key}',f'- Q1: {earned}.',f'- Q2: {find}.',f'- Q3: **{PRIMARY[f,n]}** — 1 primary activation from this populated frame'+('; 2 including path entry from blank.' if (f,n)==('add',0) else '.'),f'- Q4: {state}.',f'- Q5: First: {first}. Hundredth: {hundred}. Interruption: {interrupt}.']
(ROOT/'walkthrough.md').write_text('\n\n'.join(out)+'\n')
print('81 explicit per-view Norman records written')
