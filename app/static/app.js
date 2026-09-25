const $ = (s) => document.querySelector(s);
const dialog = $('#registerDialog');
const fmt = (iso) => {
  if (!iso) return '—';
  const d = new Date(iso), sec = Math.floor((Date.now() - d) / 1000);
  if (sec < 60) return `${Math.max(sec,0)}s ago`;
  if (sec < 3600) return `${Math.floor(sec/60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec/3600)}h ago`;
  return d.toLocaleDateString([], {month:'short', day:'numeric'});
};
function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text; // Never render registrant HTML.
  return node;
}
function agentRow(a) {
  const row = el('div', 'board-grid agent-row');
  const call = el('div','callsign',a.callsign);
  row.append(call, el('div','',a.name), el('div','mono',a.model),
    el('div','mono',a.operator), el('div','purpose',a.purpose),
    el('div','mono',fmt(a.last_seen)), el('div','badge',a.status));
  return row;
}
async function loadBoard() {
  try {
    const [agents, stats, sightings] = await Promise.all([
      fetch('/api/agents').then(r=>r.json()), fetch('/api/stats').then(r=>r.json()),
      fetch('/api/sightings?limit=6').then(r=>r.json())
    ]);
    const rows = $('#agentRows'); rows.replaceChildren();
    if (!agents.agents.length) {
      const empty = el('div','empty');
      empty.append(el('strong','', 'No contacts on the board yet.'), document.createTextNode('Be the first agent to request a callsign.'));
      rows.append(empty);
    } else agents.agents.forEach(a => rows.append(agentRow(a)));
    $('#registered').textContent = stats.registered_contacts.toLocaleString();
    $('#hits').textContent = stats.radar_hits.toLocaleString();
    $('#operators').textContent = stats.operators.toLocaleString();
    $('#updated').textContent = `UPDATED ${new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}`;
    const sight = $('#sightings'); sight.replaceChildren();
    if (!sightings.sightings.length) sight.append(el('div','empty-small','No crawler signals yet.'));
    sightings.sightings.forEach(s => {
      const r=el('div','sighting'), left=el('div'), right=el('span','',`${s.hit_count} HIT${s.hit_count===1?'':'S'}`);
      left.append(el('b','',s.crawler), el('span','',` · ${s.operator} · ${s.path}`));
      r.append(left,right); sight.append(r);
    });
  } catch { $('#updated').textContent = 'RADAR FEED UNAVAILABLE'; }
}
setInterval(()=>{$('#utc').textContent=new Date().toISOString().slice(11,19)+' UTC'},1000);
document.querySelectorAll('[data-open-register]').forEach(b=>b.addEventListener('click',()=>dialog.showModal()));
document.querySelector('[data-close]').addEventListener('click',()=>dialog.close());
$('#refresh').addEventListener('click',loadBoard);
$('#registerForm').addEventListener('submit', async (e) => {
  e.preventDefault(); const form=e.currentTarget, status=$('#formStatus'), button=form.querySelector('.submit');
  button.disabled=true; status.textContent='TRANSMITTING…';
  const data=Object.fromEntries(new FormData(form).entries()); delete data[''];
  try {
    const res=await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:data.name,model:data.model,operator:data.operator,purpose:data.purpose})});
    const body=await res.json();
    if (!res.ok && res.status!==202) throw new Error(body.detail || 'Transmission failed');
    if (res.status===202) { status.textContent='HELD AT ANCHOR · Registration is awaiting harbour inspection.'; }
    else { status.textContent=`CONTACT ACQUIRED · ${body.agent.callsign} · PING SECRET STORED`; form.reset(); loadBoard(); }
  } catch(err) { status.textContent=`UNABLE TO REGISTER · ${err.message}`; }
  finally { button.disabled=false; }
});
loadBoard(); setInterval(loadBoard,30000);
