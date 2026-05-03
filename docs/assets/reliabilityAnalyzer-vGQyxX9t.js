import{s as O}from"./theme-BUo633SF.js";/* empty css                 */import{e as u}from"./utils-CvcbX8Jd.js";async function j(n){try{return await navigator.clipboard.writeText(n),!0}catch{const s=document.createElement("textarea");s.value=n,s.style.position="fixed",s.style.opacity="0",document.body.appendChild(s),s.select();const r=document.execCommand("copy");return document.body.removeChild(s),r}}O();const M=document.getElementById("upload-section"),k=document.getElementById("processing-section"),T=document.getElementById("processing-text"),S=document.getElementById("results-section"),E=document.getElementById("drop-zone"),x=document.getElementById("file-input"),F=document.getElementById("new-analysis-btn"),C=document.getElementById("copy-ticket-btn"),z=document.getElementById("results-sub"),L=document.getElementById("overview-grid"),A=document.getElementById("findings-panel"),P=document.getElementById("records-panel"),R=document.getElementById("records-filters-wrap"),B=document.getElementById("records-table-wrap"),q=document.getElementById("tab-findings-count"),U=document.getElementById("tab-records-count");function _(n){const s=(n||"").toLowerCase();return s.includes("stopped working")?"crash":s.includes("stopped responding")?"hang":/windows update|update/.test(s)?"update":/install|reconfigur|removal/.test(s)?"software":"info"}const H={crash:"App Crash",hang:"App Hang",update:"Update",software:"Software",info:"Info"},G={crash:"#f85149",hang:"#d29922",update:"#3fb950",software:"#58a6ff",info:"#8b949e"},V=[/bad.?block/i,/disk.?error/i,/ntfs.*corrupt/i,/corrupt.*ntfs/i,/hardware.?error/i,/memory.*corrupt/i,/corrupt.*memory/i,/sector.?error/i,/read.?error/i,/i\/o.?error/i,/chkdsk/i,/file.?system.*error/i,/bad.?sector/i];function Y(n){const r=new DOMParser().parseFromString(n,"application/xml"),h=r.querySelector("parsererror");if(h)throw new Error("Invalid XML: "+h.textContent.slice(0,120));const g=r.documentElement;if(g.tagName!=="RelMonReport")throw new Error(`Unrecognised format — root element is <${g.tagName}>. Expected <RelMonReport>. Open Reliability Monitor → Action → Save Reliability History.`);const l=g.getAttribute("TimeGenerated")||"",e=[...r.querySelectorAll("RacEvents > Event")].map(i=>{const c=y=>{var b,t;return((t=(b=i.querySelector(y))==null?void 0:b.textContent)==null?void 0:t.trim())??""},m=c("Time"),d=c("Impact"),a=c("Source"),v=c("Problem");return{time:m,date:m.slice(0,10),source:a,product:a,message:v,impact:d,cat:_(v)}}).sort((i,c)=>c.time.localeCompare(i.time));if(!e.length)throw new Error("No events found in this Reliability Monitor export.");return{generated:l,records:e}}function K(n){var b;const s=[],r=(t,o,p,f="")=>s.push({sev:t,title:o,detail:p,extra:f}),h=n.filter(t=>t.cat==="crash"),g=n.filter(t=>t.cat==="hang"),l=n.filter(t=>t.impact==="Warning"),e=t=>t?t.replace("T"," ").slice(0,16):"",i=t=>`<div class="finding-event"><span class="fe-time">${u(e(t.time))}</span><span class="fe-src">${u(t.source)}</span><span class="fe-msg">${u(t.message)}</span></div>`,c=n.filter(t=>V.some(o=>o.test(t.source)||o.test(t.message)));c.length&&r("crit",`Hardware failure indicator${c.length>1?"s":""} detected (${c.length})`,"One or more records contain keywords associated with disk I/O errors, NTFS corruption, bad sectors, or memory faults. Run <code>chkdsk C: /f /r</code> and check SMART data before any other investigation.",c.slice(0,3).map(i).join(""));const m={};for(const t of h){const o=t.source.toLowerCase();m[o]||(m[o]={label:t.source,events:[]}),m[o].events.push(t)}for(const t of Object.values(m).sort((o,p)=>p.events.length-o.events.length))if(t.events.length>=2){const o=t.events.map(w=>w.time).filter(Boolean).sort(),p=o.length?e(o[0]):"",f=o.length>1?e(o[o.length-1]):"",$=p&&f&&p!==f?` between ${p} and ${f}`:p?` at ${p}`:"";r("warn",`${u(t.label)} crashed ${t.events.length} time${t.events.length>1?"s":""}`,`Repeated crash pattern${$}. Check for a pending application update, conflicting DLL, or corrupt installation. Look for Event 1000 in the Application log for faulting module details.`,t.events.slice(0,5).map(i).join(""))}const d={};for(const t of g){const o=t.source.toLowerCase();d[o]||(d[o]={label:t.source,events:[]}),d[o].events.push(t)}for(const t of Object.values(d).sort((o,p)=>p.events.length-o.events.length))if(t.events.length>=2){const o=t.events.map(w=>w.time).filter(Boolean).sort(),p=o.length?e(o[0]):"",f=o.length>1?e(o[o.length-1]):"",$=p&&f&&p!==f?` between ${p} and ${f}`:p?` at ${p}`:"";r("warn",`${u(t.label)} stopped responding ${t.events.length} time${t.events.length>1?"s":""}`,`Repeated hang pattern${$}. Common causes: main thread blocked on slow disk/network, deadlock, or antivirus scanning files the app is trying to access. Try adding the app directory to AV exclusions as a test.`,t.events.slice(0,5).map(i).join(""))}const a=n.filter(t=>t.cat==="software");for(const t of a){const o=new Date(t.time),p=new Date(o.getTime()+48*60*60*1e3),f=h.filter($=>{const w=new Date($.time);return w>=o&&w<=p});if(f.length>=2){const $=[...new Set(f.map(w=>w.source))].join(", ");r("warn",`${f.length} crash${f.length>1?"es":""} within 48h of software change on ${u(e(t.time).slice(0,10))}`,`<strong>${u(t.source)}</strong> was installed/changed at ${u(e(t.time))}. ${f.length} crash${f.length>1?"es":""} followed involving: ${u($)}. Consider rolling back or checking for compatibility issues.`,f.slice(0,5).map(i).join(""))}}const v=new Date(((b=n[0])==null?void 0:b.time)||Date.now()),y=n.filter(t=>{const o=new Date(t.time);return v-o<=24*60*60*1e3&&(t.cat==="crash"||t.cat==="hang")});if(y.length&&r("warn",`${y.length} crash/hang event${y.length>1?"s":""} in the 24h before this report`,"Active instability — these events are recent and likely still occurring. Prioritise investigation.",y.map(i).join("")),l.length>=3){const t=[...new Set(l.slice(0,5).map(o=>o.source))].join(", ");r("warn",`${l.length} failed update${l.length>1?"s":""} or installation${l.length>1?"s":""}`,`Multiple Warning-impact events detected. Check Windows Update history and application installer logs. Affected: ${u(t)}${l.length>5?` + ${l.length-5} more`:""}.`,l.slice(0,5).map(i).join(""))}return h.length>=8&&!s.some(t=>t.sev==="crit")&&r("warn",`High crash volume — ${h.length} application crashes recorded`,"Unusually high number of application crash events. Consider running <code>sfc /scannow</code> and <code>DISM /Online /Cleanup-Image /RestoreHealth</code> to check for system file corruption."),s.length===0&&r("ok","No significant issues detected","No recurring crashes, hangs, hardware indicators, or failed updates found in the reliability history."),s.sort((t,o)=>({crit:0,warn:1,ok:2}[t.sev]??3)-({crit:0,warn:1,ok:2}[o.sev]??3))}function X(n,s,r){const h=n.filter(a=>a.cat==="crash").length,g=n.filter(a=>a.cat==="hang").length,l=n.filter(a=>a.cat==="software").length,e=n.filter(a=>a.impact==="Warning").length,i=r?r.slice(0,10):"unknown",c="─".repeat(60),m=a=>a.replace(/<[^>]+>/g,""),d=["RELIABILITY ANALYSIS",`Report Date: ${i}`,"Analysed via Eventful — eventful.lrfa.dev/reliability-analyzer.html","","SUMMARY",`  Total Events:      ${String(n.length).padStart(4)}`,`  Crashes:           ${String(h).padStart(4)}`,`  Hangs:             ${String(g).padStart(4)}`,`  Software Changes:  ${String(l).padStart(4)}`,`  Warnings:          ${String(e).padStart(4)}`,"",`FINDINGS (${s.filter(a=>a.sev!=="ok").length} issue${s.filter(a=>a.sev!=="ok").length!==1?"s":""})`,c];for(const a of s){const v={crit:"CRITICAL",warn:"WARNING",ok:"OK"}[a.sev]??a.sev;d.push(`[${v}] ${m(a.title)}`),d.push(m(a.detail)),d.push("")}return d.push(c),d.join(`
`)}function Z(n,s){const r=n.filter(a=>a.cat==="crash").length,h=n.filter(a=>a.cat==="hang").length,g=n.filter(a=>a.cat==="software").length,l=n.filter(a=>a.impact==="Warning").length,e=n.map(a=>a.date).filter(Boolean).sort(),i=e.length?e[0]:"—",c=e.length?e[e.length-1]:"—",m=i===c?i:`${i} → ${c}`,d=(a,v,y,b)=>`<div class="ob-stat ${y}" data-filter="${b}" style="cursor:pointer" title="Show ${v.toLowerCase()}"><span class="ob-stat-num">${a}</span><span class="ob-stat-label">${v}</span></div>`;L.className="",L.innerHTML=`
    <div class="overview-bar">
      <div class="ob-stats">
        ${d(n.length,"Total","stat-total","all")}
        ${d(r,"Crashes",r>0?"stat-critical":"stat-total","crash")}
        ${d(h,"Hangs",h>0?"stat-error":"stat-total","hang")}
        ${d(g,"Software","stat-info","software")}
        ${d(l,"Warnings",l>0?"stat-warning":"stat-total","warning")}
      </div>
      <div class="ob-divider"></div>
      <div style="display:flex;flex-direction:column;gap:2px">
        <span style="font-family:var(--mono);font-size:11px;color:var(--text3)">Date range</span>
        <span style="font-family:var(--mono);font-size:12px;font-weight:600;color:var(--text2)">${u(m)}</span>
      </div>
    </div>
  `,L.querySelectorAll(".ob-stat[data-filter]").forEach(a=>{a.addEventListener("click",()=>{D("records"),I(n,a.dataset.filter)})})}const J={crit:"sev-header-critical",warn:"sev-header-warning",ok:"sev-header-info"},Q={crit:"#fb7185",warn:"#fbbf24",ok:"#3fb950"},ee={crit:"CRITICAL",warn:"WARNING",ok:"OK"};function te(n){if(!n.length){A.innerHTML='<p class="no-results">No findings generated.</p>';return}A.innerHTML=n.map(s=>`
    <div class="incident-card">
      <div class="incident-header ${J[s.sev]??""}" style="cursor:default">
        <span style="font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:0.1em;color:${Q[s.sev]??"#8b949e"};flex-shrink:0">${ee[s.sev]??s.sev}</span>
        <span class="incident-title">${s.title}</span>
      </div>
      <div class="incident-body">
        <div class="incident-section">
          <p class="incident-text">${s.detail}</p>
          ${s.extra?`<div class="finding-events" style="margin-top:10px">${s.extra}</div>`:""}
        </div>
      </div>
    </div>
  `).join(""),q.textContent=n.filter(s=>s.sev==="crit"||s.sev==="warn").length||""}function I(n,s){const r=["all",...new Set(n.map(e=>e.cat))];n.some(e=>e.impact==="Warning")&&r.push("warning");const h=e=>e==="all"?"All":e==="warning"?"Warnings":H[e]??e,g=e=>e==="all"?n.length:e==="warning"?n.filter(i=>i.impact==="Warning").length:n.filter(i=>i.cat===e).length;R.innerHTML=`
    <div class="filter-bar">
      ${r.map(e=>`
        <button class="filter-chip${s===e?" active":""}" data-cat="${e}">
          ${h(e)}<span class="chip-count">${g(e)}</span>
        </button>
      `).join("")}
    </div>
  `;const l=s==="all"?n:s==="warning"?n.filter(e=>e.impact==="Warning"):n.filter(e=>e.cat===s);if(!l.length){B.innerHTML='<p class="no-results">No records for this filter.</p>';return}B.innerHTML=`
    <div class="event-table-wrap">
      <table class="event-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Impact</th>
            <th>Category</th>
            <th>Source / Application</th>
            <th>Problem</th>
          </tr>
        </thead>
        <tbody>
          ${l.map(e=>`
            <tr>
              <td style="font-family:var(--mono);font-size:11px;color:var(--text3);white-space:nowrap">${u(e.time?e.time.replace("T"," ").slice(0,16):"—")}</td>
              <td><span class="cat-badge" style="color:${e.impact==="Critical"?"#f85149":e.impact==="Warning"?"#d29922":"#8b949e"}">${u(e.impact)}</span></td>
              <td><span class="cat-badge" style="color:${G[e.cat]??"#8b949e"}">${H[e.cat]??e.cat}</span></td>
              <td class="et-source">${u(e.source)}</td>
              <td class="et-msg">${u(e.message)}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `,R.querySelectorAll(".filter-chip").forEach(e=>{e.addEventListener("click",()=>I(n,e.dataset.cat))})}function D(n){document.querySelectorAll(".analyzer-tab").forEach(s=>s.classList.toggle("active",s.dataset.tab===n)),A.hidden=n!=="findings",P.hidden=n!=="records"}document.querySelectorAll(".analyzer-tab").forEach(n=>{n.addEventListener("click",()=>D(n.dataset.tab))});function N(n){if(!n)return;M.hidden=!0,k.hidden=!1,S.hidden=!0,T.textContent="Parsing reliability records…";const s=new FileReader;s.onload=r=>{var h;try{T.textContent="Analysing…";const g=r.target.result,l=new Uint8Array(g);let e;l[0]===255&&l[1]===254?e=new TextDecoder("utf-16le").decode(g):l[0]===254&&l[1]===255?e=new TextDecoder("utf-16be").decode(g):e=new TextDecoder("utf-8").decode(g);const{generated:i,records:c}=Y(e);k.hidden=!0,S.hidden=!1,z.textContent=`${c.length} events · Report generated ${i||"unknown"}`,Z(c,i);const m=K(c);te(m),U.textContent=c.length,I(c,"all"),C.onclick=async()=>{const d=X(c,m,i);await j(d)&&(C.classList.add("copied"),C.textContent="✓ Copied",setTimeout(()=>{C.classList.remove("copied"),C.textContent="Copy ticket notes"},2e3))}}catch(g){k.hidden=!1,T.textContent="",k.innerHTML=`
        <p class="processing-error">
          <strong>Could not parse file</strong><br>
          ${u(g.message)}<br>
          <span style="font-size:0.82rem;color:var(--text-muted)">Open Reliability Monitor → Action → Save Reliability History to export the correct file.</span>
        </p>
        <button class="btn-secondary" style="margin-top:1rem" id="retry-btn">← Try another file</button>
      `,(h=document.getElementById("retry-btn"))==null||h.addEventListener("click",W)}},s.readAsArrayBuffer(n)}function W(){k.innerHTML=`
    <div class="processing-spinner"></div>
    <p id="processing-text" class="processing-text">Parsing reliability records…</p>
  `,M.hidden=!1,k.hidden=!0,S.hidden=!0,x.value=""}E.addEventListener("dragover",n=>{n.preventDefault(),E.classList.add("dragover")});E.addEventListener("dragleave",()=>E.classList.remove("dragover"));E.addEventListener("drop",n=>{n.preventDefault(),E.classList.remove("dragover"),N(n.dataTransfer.files[0])});E.addEventListener("click",()=>x.click());x.addEventListener("change",()=>N(x.files[0]));F.addEventListener("click",W);
