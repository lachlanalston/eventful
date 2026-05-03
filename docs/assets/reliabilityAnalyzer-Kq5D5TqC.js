import{s as B}from"./theme-BUo633SF.js";/* empty css                 */import{e as u}from"./utils-CvcbX8Jd.js";async function H(t){try{return await navigator.clipboard.writeText(t),!0}catch{const n=document.createElement("textarea");n.value=t,n.style.position="fixed",n.style.opacity="0",document.body.appendChild(n),n.select();const i=document.execCommand("copy");return document.body.removeChild(n),i}}B();const A=document.getElementById("upload-section"),g=document.getElementById("processing-section"),y=document.getElementById("processing-text"),w=document.getElementById("results-section"),f=document.getElementById("drop-zone"),v=document.getElementById("file-input"),M=document.getElementById("new-analysis-btn"),m=document.getElementById("copy-ticket-btn"),N=document.getElementById("results-sub"),b=document.getElementById("overview-grid"),$=document.getElementById("findings-panel"),W=document.getElementById("records-panel"),L=document.getElementById("records-filters-wrap"),x=document.getElementById("records-table-wrap"),O=document.getElementById("tab-findings-count"),D=document.getElementById("tab-records-count");function F(t){const n=(t||"").toLowerCase();return n.includes("stopped working")?"crash":n.includes("stopped responding")?"hang":/windows update|update/.test(n)?"update":/install|reconfigur|removal/.test(n)?"software":"info"}const S={crash:"App Crash",hang:"App Hang",update:"Update",software:"Software",info:"Info"},j={crash:"#f85149",hang:"#d29922",update:"#3fb950",software:"#58a6ff",info:"#8b949e"},z=[/bad.?block/i,/disk.?error/i,/ntfs.*corrupt/i,/corrupt.*ntfs/i,/hardware.?error/i,/memory.*corrupt/i,/corrupt.*memory/i,/sector.?error/i,/read.?error/i,/i\/o.?error/i,/chkdsk/i,/file.?system.*error/i,/bad.?sector/i];function P(t){const i=new DOMParser().parseFromString(t,"application/xml"),p=i.querySelector("parsererror");if(p)throw new Error("Invalid XML: "+p.textContent.slice(0,120));const d=i.documentElement;if(d.tagName!=="RelMonReport")throw new Error(`Unrecognised format — root element is <${d.tagName}>. Expected <RelMonReport>. Open Reliability Monitor → Action → Save Reliability History.`);const c=d.getAttribute("TimeGenerated")||"",e=[...i.querySelectorAll("RacEvents > Event")].map(l=>{const a=h=>{var k,C;return((C=(k=l.querySelector(h))==null?void 0:k.textContent)==null?void 0:C.trim())??""},s=a("Impact"),o=a("Source"),r=a("Problem");return{source:o,product:o,message:r,impact:s,cat:F(r)}});if(!e.length)throw new Error("No events found in this Reliability Monitor export.");return{generated:c,records:e}}function q(t){const n=[],i=(s,o,r,h="")=>n.push({sev:s,title:o,detail:r,extra:h}),p=t.filter(s=>s.cat==="crash"),d=t.filter(s=>s.cat==="hang"),c=t.filter(s=>s.impact==="Warning"),e=t.filter(s=>z.some(o=>o.test(s.source)||o.test(s.message)));e.length&&i("crit",`Hardware failure indicator${e.length>1?"s":""} detected (${e.length})`,"One or more records contain keywords associated with disk I/O errors, NTFS corruption, bad sectors, or memory faults. Run <code>chkdsk C: /f /r</code> and check SMART data before any other investigation.",e.slice(0,3).map(s=>`<div class="finding-event"><span class="fe-src">${u(s.source)}</span> — ${u(s.message)}</div>`).join(""));const l={};for(const s of p){const o=s.source.toLowerCase();l[o]||(l[o]={label:s.source,count:0}),l[o].count++}for(const s of Object.values(l).sort((o,r)=>r.count-o.count))s.count>=2&&i("warn",`${u(s.label)} crashed ${s.count} time${s.count>1?"s":""}`,"Repeated crash pattern. Check for a pending application update, conflicting DLL, or corrupt installation. Look for Event 1000 in the Application log for faulting module details.");const a={};for(const s of d){const o=s.source.toLowerCase();a[o]||(a[o]={label:s.source,count:0}),a[o].count++}for(const s of Object.values(a).sort((o,r)=>r.count-o.count))s.count>=2&&i("warn",`${u(s.label)} stopped responding ${s.count} time${s.count>1?"s":""}`,"Repeated hang pattern. Common causes: main thread blocked on slow disk/network, deadlock, or antivirus scanning files the app is trying to access. Try adding the app directory to AV exclusions as a test.");if(c.length>=3){const s=[...new Set(c.slice(0,5).map(o=>o.source))].join(", ");i("warn",`${c.length} failed update${c.length>1?"s":""} or installation${c.length>1?"s":""}`,`Multiple Warning-impact events detected. Check Windows Update history and application installer logs. Affected: ${u(s)}${c.length>5?` + ${c.length-5} more`:""}.`)}return p.length>=8&&!n.some(s=>s.sev==="crit")&&i("warn",`High crash volume — ${p.length} application crashes recorded`,"Unusually high number of application crash events. Consider running <code>sfc /scannow</code> and <code>DISM /Online /Cleanup-Image /RestoreHealth</code> to check for system file corruption."),n.length===0&&i("ok","No significant issues detected","No recurring crashes, hangs, hardware indicators, or failed updates found in the reliability history."),n.sort((s,o)=>({crit:0,warn:1,ok:2}[s.sev]??3)-({crit:0,warn:1,ok:2}[o.sev]??3))}function U(t,n,i){const p=t.filter(r=>r.cat==="crash").length,d=t.filter(r=>r.cat==="hang").length,c=t.filter(r=>r.cat==="software").length,e=t.filter(r=>r.impact==="Warning").length,l=i?i.slice(0,10):"unknown",a="─".repeat(60),s=r=>r.replace(/<[^>]+>/g,""),o=["RELIABILITY ANALYSIS",`Report Date: ${l}`,"Analysed via Eventful — eventful.lrfa.dev/reliability-analyzer.html","","SUMMARY",`  Total Events:      ${String(t.length).padStart(4)}`,`  Crashes:           ${String(p).padStart(4)}`,`  Hangs:             ${String(d).padStart(4)}`,`  Software Changes:  ${String(c).padStart(4)}`,`  Warnings:          ${String(e).padStart(4)}`,"",`FINDINGS (${n.filter(r=>r.sev!=="ok").length} issue${n.filter(r=>r.sev!=="ok").length!==1?"s":""})`,a];for(const r of n){const h={crit:"CRITICAL",warn:"WARNING",ok:"OK"}[r.sev]??r.sev;o.push(`[${h}] ${s(r.title)}`),o.push(s(r.detail)),o.push("")}return o.push(a),o.join(`
`)}function _(t,n){const i=t.filter(a=>a.cat==="crash").length,p=t.filter(a=>a.cat==="hang").length,d=t.filter(a=>a.cat==="software").length,c=t.filter(a=>a.impact==="Warning").length,e=n?n.slice(0,10):"—",l=(a,s,o,r)=>`<div class="ob-stat ${o}" data-filter="${r}" style="cursor:pointer" title="Show ${s.toLowerCase()}"><span class="ob-stat-num">${a}</span><span class="ob-stat-label">${s}</span></div>`;b.className="",b.innerHTML=`
    <div class="overview-bar">
      <div class="ob-stats">
        ${l(t.length,"Total","stat-total","all")}
        ${l(i,"Crashes",i>0?"stat-critical":"stat-total","crash")}
        ${l(p,"Hangs",p>0?"stat-error":"stat-total","hang")}
        ${l(d,"Software","stat-info","software")}
        ${l(c,"Warnings",c>0?"stat-warning":"stat-total","warning")}
      </div>
      <div class="ob-divider"></div>
      <div style="display:flex;flex-direction:column;gap:2px">
        <span style="font-family:var(--mono);font-size:11px;color:var(--text3)">Report date</span>
        <span style="font-family:var(--mono);font-size:13px;font-weight:600;color:var(--text2)">${u(e)}</span>
      </div>
    </div>
  `,b.querySelectorAll(".ob-stat[data-filter]").forEach(a=>{a.addEventListener("click",()=>{T("records"),E(t,a.dataset.filter)})})}const G={crit:"sev-header-critical",warn:"sev-header-warning",ok:"sev-header-info"},V={crit:"#fb7185",warn:"#fbbf24",ok:"#3fb950"},Y={crit:"CRITICAL",warn:"WARNING",ok:"OK"};function K(t){if(!t.length){$.innerHTML='<p class="no-results">No findings generated.</p>';return}$.innerHTML=t.map(n=>`
    <div class="incident-card">
      <div class="incident-header ${G[n.sev]??""}" style="cursor:default">
        <span style="font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:0.1em;color:${V[n.sev]??"#8b949e"};flex-shrink:0">${Y[n.sev]??n.sev}</span>
        <span class="incident-title">${n.title}</span>
      </div>
      <div class="incident-body">
        <div class="incident-section">
          <p class="incident-text">${n.detail}</p>
          ${n.extra?`<div class="finding-events" style="margin-top:10px">${n.extra}</div>`:""}
        </div>
      </div>
    </div>
  `).join(""),O.textContent=t.filter(n=>n.sev==="crit"||n.sev==="warn").length||""}function E(t,n){const i=["all",...new Set(t.map(e=>e.cat))];t.some(e=>e.impact==="Warning")&&i.push("warning");const p=e=>e==="all"?"All":e==="warning"?"Warnings":S[e]??e,d=e=>e==="all"?t.length:e==="warning"?t.filter(l=>l.impact==="Warning").length:t.filter(l=>l.cat===e).length;L.innerHTML=`
    <div class="filter-bar">
      ${i.map(e=>`
        <button class="filter-chip${n===e?" active":""}" data-cat="${e}">
          ${p(e)}<span class="chip-count">${d(e)}</span>
        </button>
      `).join("")}
    </div>
  `;const c=n==="all"?t:n==="warning"?t.filter(e=>e.impact==="Warning"):t.filter(e=>e.cat===n);if(!c.length){x.innerHTML='<p class="no-results">No records for this filter.</p>';return}x.innerHTML=`
    <div class="event-table-wrap">
      <table class="event-table">
        <thead>
          <tr>
            <th>Impact</th>
            <th>Category</th>
            <th>Source / Application</th>
            <th>Problem</th>
          </tr>
        </thead>
        <tbody>
          ${c.map(e=>`
            <tr>
              <td><span class="cat-badge" style="color:${e.impact==="Critical"?"#f85149":e.impact==="Warning"?"#d29922":"#8b949e"}">${u(e.impact)}</span></td>
              <td><span class="cat-badge" style="color:${j[e.cat]??"#8b949e"}">${S[e.cat]??e.cat}</span></td>
              <td class="et-source">${u(e.source)}</td>
              <td class="et-msg">${u(e.message)}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `,L.querySelectorAll(".filter-chip").forEach(e=>{e.addEventListener("click",()=>E(t,e.dataset.cat))})}function T(t){document.querySelectorAll(".analyzer-tab").forEach(n=>n.classList.toggle("active",n.dataset.tab===t)),$.hidden=t!=="findings",W.hidden=t!=="records"}document.querySelectorAll(".analyzer-tab").forEach(t=>{t.addEventListener("click",()=>T(t.dataset.tab))});function I(t){if(!t)return;A.hidden=!0,g.hidden=!1,w.hidden=!0,y.textContent="Parsing reliability records…";const n=new FileReader;n.onload=i=>{var p;try{y.textContent="Analysing…";const d=i.target.result,c=new Uint8Array(d);let e;c[0]===255&&c[1]===254?e=new TextDecoder("utf-16le").decode(d):c[0]===254&&c[1]===255?e=new TextDecoder("utf-16be").decode(d):e=new TextDecoder("utf-8").decode(d);const{generated:l,records:a}=P(e);g.hidden=!0,w.hidden=!1,N.textContent=`${a.length} events · Report generated ${l||"unknown"}`,_(a,l);const s=q(a);K(s),D.textContent=a.length,E(a,"all"),m.onclick=async()=>{const o=U(a,s,l);await H(o)&&(m.classList.add("copied"),m.textContent="✓ Copied",setTimeout(()=>{m.classList.remove("copied"),m.textContent="Copy ticket notes"},2e3))}}catch(d){g.hidden=!1,y.textContent="",g.innerHTML=`
        <p class="processing-error">
          <strong>Could not parse file</strong><br>
          ${u(d.message)}<br>
          <span style="font-size:0.82rem;color:var(--text-muted)">Open Reliability Monitor → Action → Save Reliability History to export the correct file.</span>
        </p>
        <button class="btn-secondary" style="margin-top:1rem" id="retry-btn">← Try another file</button>
      `,(p=document.getElementById("retry-btn"))==null||p.addEventListener("click",R)}},n.readAsArrayBuffer(t)}function R(){g.innerHTML=`
    <div class="processing-spinner"></div>
    <p id="processing-text" class="processing-text">Parsing reliability records…</p>
  `,A.hidden=!1,g.hidden=!0,w.hidden=!0,v.value=""}f.addEventListener("dragover",t=>{t.preventDefault(),f.classList.add("dragover")});f.addEventListener("dragleave",()=>f.classList.remove("dragover"));f.addEventListener("drop",t=>{t.preventDefault(),f.classList.remove("dragover"),I(t.dataTransfer.files[0])});f.addEventListener("click",()=>v.click());v.addEventListener("change",()=>I(v.files[0]));M.addEventListener("click",R);
