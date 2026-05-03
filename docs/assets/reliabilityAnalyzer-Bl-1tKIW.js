import{s as R}from"./theme-BUo633SF.js";/* empty css                 */import{e as u}from"./utils-CvcbX8Jd.js";async function B(e){try{return await navigator.clipboard.writeText(e),!0}catch{const t=document.createElement("textarea");t.value=e,t.style.position="fixed",t.style.opacity="0",document.body.appendChild(t),t.select();const i=document.execCommand("copy");return document.body.removeChild(t),i}}R();const S=document.getElementById("upload-section"),g=document.getElementById("processing-section"),y=document.getElementById("processing-text"),b=document.getElementById("results-section"),f=document.getElementById("drop-zone"),v=document.getElementById("file-input"),H=document.getElementById("new-analysis-btn"),m=document.getElementById("copy-ticket-btn"),M=document.getElementById("results-sub"),k=document.getElementById("overview-grid"),w=document.getElementById("findings-panel"),N=document.getElementById("records-panel"),x=document.getElementById("records-filters-wrap"),C=document.getElementById("records-table-wrap"),O=document.getElementById("tab-findings-count"),D=document.getElementById("tab-records-count");function W(e){const t=(e||"").toLowerCase();return t.includes("stopped working")?"crash":t.includes("stopped responding")?"hang":/windows update|update/.test(t)?"update":/install|reconfigur|removal/.test(t)?"software":"info"}const L={crash:"App Crash",hang:"App Hang",update:"Update",software:"Software",info:"Info"},F={crash:"#f85149",hang:"#d29922",update:"#3fb950",software:"#58a6ff",info:"#8b949e"},j=[/bad.?block/i,/disk.?error/i,/ntfs.*corrupt/i,/corrupt.*ntfs/i,/hardware.?error/i,/memory.*corrupt/i,/corrupt.*memory/i,/sector.?error/i,/read.?error/i,/i\/o.?error/i,/chkdsk/i,/file.?system.*error/i,/bad.?sector/i];function z(e){const i=new DOMParser().parseFromString(e,"application/xml"),d=i.querySelector("parsererror");if(d)throw new Error("Invalid XML: "+d.textContent.slice(0,120));const s=i.documentElement;if(s.tagName!=="RelMonReport")throw new Error(`Unrecognised format — root element is <${s.tagName}>. Expected <RelMonReport>. Open Reliability Monitor → Action → Save Reliability History.`);const c=s.getAttribute("TimeGenerated")||"",p=[...i.querySelectorAll("RacEvents > Event")].map(l=>{const r=h=>{var $,E;return((E=($=l.querySelector(h))==null?void 0:$.textContent)==null?void 0:E.trim())??""},n=r("Impact"),o=r("Source"),a=r("Problem");return{source:o,product:o,message:a,impact:n,cat:W(a)}});if(!p.length)throw new Error("No events found in this Reliability Monitor export.");return{generated:c,records:p}}function P(e){const t=[],i=(n,o,a,h="")=>t.push({sev:n,title:o,detail:a,extra:h}),d=e.filter(n=>n.cat==="crash"),s=e.filter(n=>n.cat==="hang"),c=e.filter(n=>n.impact==="Warning"),p=e.filter(n=>j.some(o=>o.test(n.source)||o.test(n.message)));p.length&&i("crit",`Hardware failure indicator${p.length>1?"s":""} detected (${p.length})`,"One or more records contain keywords associated with disk I/O errors, NTFS corruption, bad sectors, or memory faults. Run <code>chkdsk C: /f /r</code> and check SMART data before any other investigation.",p.slice(0,3).map(n=>`<div class="finding-event"><span class="fe-src">${u(n.source)}</span> — ${u(n.message)}</div>`).join(""));const l={};for(const n of d){const o=n.source.toLowerCase();l[o]||(l[o]={label:n.source,count:0}),l[o].count++}for(const n of Object.values(l).sort((o,a)=>a.count-o.count))n.count>=2&&i("warn",`${u(n.label)} crashed ${n.count} time${n.count>1?"s":""}`,"Repeated crash pattern. Check for a pending application update, conflicting DLL, or corrupt installation. Look for Event 1000 in the Application log for faulting module details.");const r={};for(const n of s){const o=n.source.toLowerCase();r[o]||(r[o]={label:n.source,count:0}),r[o].count++}for(const n of Object.values(r).sort((o,a)=>a.count-o.count))n.count>=2&&i("warn",`${u(n.label)} stopped responding ${n.count} time${n.count>1?"s":""}`,"Repeated hang pattern. Common causes: main thread blocked on slow disk/network, deadlock, or antivirus scanning files the app is trying to access. Try adding the app directory to AV exclusions as a test.");if(c.length>=3){const n=[...new Set(c.slice(0,5).map(o=>o.source))].join(", ");i("warn",`${c.length} failed update${c.length>1?"s":""} or installation${c.length>1?"s":""}`,`Multiple Warning-impact events detected. Check Windows Update history and application installer logs. Affected: ${u(n)}${c.length>5?` + ${c.length-5} more`:""}.`)}return d.length>=8&&!t.some(n=>n.sev==="crit")&&i("warn",`High crash volume — ${d.length} application crashes recorded`,"Unusually high number of application crash events. Consider running <code>sfc /scannow</code> and <code>DISM /Online /Cleanup-Image /RestoreHealth</code> to check for system file corruption."),t.length===0&&i("ok","No significant issues detected","No recurring crashes, hangs, hardware indicators, or failed updates found in the reliability history."),t.sort((n,o)=>({crit:0,warn:1,ok:2}[n.sev]??3)-({crit:0,warn:1,ok:2}[o.sev]??3))}function U(e,t,i){const d=e.filter(a=>a.cat==="crash").length,s=e.filter(a=>a.cat==="hang").length,c=e.filter(a=>a.cat==="software").length,p=e.filter(a=>a.impact==="Warning").length,l=i?i.slice(0,10):"unknown",r="─".repeat(60),n=a=>a.replace(/<[^>]+>/g,""),o=["RELIABILITY ANALYSIS",`Report Date: ${l}`,"Analysed via Eventful — eventful.lrfa.dev/reliability-analyzer.html","","SUMMARY",`  Total Events:      ${String(e.length).padStart(4)}`,`  Crashes:           ${String(d).padStart(4)}`,`  Hangs:             ${String(s).padStart(4)}`,`  Software Changes:  ${String(c).padStart(4)}`,`  Warnings:          ${String(p).padStart(4)}`,"",`FINDINGS (${t.filter(a=>a.sev!=="ok").length} issue${t.filter(a=>a.sev!=="ok").length!==1?"s":""})`,r];for(const a of t){const h={crit:"CRITICAL",warn:"WARNING",ok:"OK"}[a.sev]??a.sev;o.push(`[${h}] ${n(a.title)}`),o.push(n(a.detail)),o.push("")}return o.push(r),o.join(`
`)}function _(e,t){const i=e.filter(r=>r.cat==="crash").length,d=e.filter(r=>r.cat==="hang").length,s=e.filter(r=>r.cat==="software").length,c=e.filter(r=>r.impact==="Warning").length,p=t?t.slice(0,10):"—",l=(r,n,o)=>`<div class="ob-stat ${o}"><span class="ob-stat-num">${r}</span><span class="ob-stat-label">${n}</span></div>`;k.className="",k.innerHTML=`
    <div class="overview-bar">
      <div class="ob-stats">
        ${l(e.length,"Total","stat-total")}
        ${l(i,"Crashes",i>0?"stat-critical":"stat-total")}
        ${l(d,"Hangs",d>0?"stat-error":"stat-total")}
        ${l(s,"Software","stat-info")}
        ${l(c,"Warnings",c>0?"stat-warning":"stat-total")}
      </div>
      <div class="ob-divider"></div>
      <div style="display:flex;flex-direction:column;gap:2px">
        <span style="font-family:var(--mono);font-size:11px;color:var(--text3)">Report date</span>
        <span style="font-family:var(--mono);font-size:13px;font-weight:600;color:var(--text2)">${u(p)}</span>
      </div>
    </div>
  `}const q={crit:"sev-header-critical",warn:"sev-header-warning",ok:"sev-header-info"},G={crit:"#fb7185",warn:"#fbbf24",ok:"#3fb950"},V={crit:"CRITICAL",warn:"WARNING",ok:"OK"};function Y(e){if(!e.length){w.innerHTML='<p class="no-results">No findings generated.</p>';return}w.innerHTML=e.map(t=>`
    <div class="incident-card">
      <div class="incident-header ${q[t.sev]??""}" style="cursor:default">
        <span style="font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:0.1em;color:${G[t.sev]??"#8b949e"};flex-shrink:0">${V[t.sev]??t.sev}</span>
        <span class="incident-title">${t.title}</span>
      </div>
      <div class="incident-body">
        <div class="incident-section">
          <p class="incident-text">${t.detail}</p>
          ${t.extra?`<div class="finding-events" style="margin-top:10px">${t.extra}</div>`:""}
        </div>
      </div>
    </div>
  `).join(""),O.textContent=e.filter(t=>t.sev==="crit"||t.sev==="warn").length||""}function A(e,t){const i=["all",...new Set(e.map(s=>s.cat))];x.innerHTML=`
    <div class="filter-bar">
      ${i.map(s=>`
        <button class="filter-chip${t===s?" active":""}" data-cat="${s}">
          ${s==="all"?"All":L[s]??s}
          <span class="chip-count">${s==="all"?e.length:e.filter(c=>c.cat===s).length}</span>
        </button>
      `).join("")}
    </div>
  `;const d=t==="all"?e:e.filter(s=>s.cat===t);if(!d.length){C.innerHTML='<p class="no-results">No records for this filter.</p>';return}C.innerHTML=`
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
          ${d.map(s=>`
            <tr>
              <td><span class="cat-badge" style="color:${s.impact==="Critical"?"#f85149":s.impact==="Warning"?"#d29922":"#8b949e"}">${u(s.impact)}</span></td>
              <td><span class="cat-badge" style="color:${F[s.cat]??"#8b949e"}">${L[s.cat]??s.cat}</span></td>
              <td class="et-source">${u(s.source)}</td>
              <td class="et-msg">${u(s.message)}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `,x.querySelectorAll(".filter-chip").forEach(s=>{s.addEventListener("click",()=>A(e,s.dataset.cat))})}document.querySelectorAll(".analyzer-tab").forEach(e=>{e.addEventListener("click",()=>{document.querySelectorAll(".analyzer-tab").forEach(i=>i.classList.remove("active")),e.classList.add("active");const t=e.dataset.tab;w.hidden=t!=="findings",N.hidden=t!=="records"})});function I(e){if(!e)return;S.hidden=!0,g.hidden=!1,b.hidden=!0,y.textContent="Parsing reliability records…";const t=new FileReader;t.onload=i=>{var d;try{y.textContent="Analysing…";const s=i.target.result,c=new Uint8Array(s);let p;c[0]===255&&c[1]===254?p=new TextDecoder("utf-16le").decode(s):c[0]===254&&c[1]===255?p=new TextDecoder("utf-16be").decode(s):p=new TextDecoder("utf-8").decode(s);const{generated:l,records:r}=z(p);g.hidden=!0,b.hidden=!1,M.textContent=`${r.length} events · Report generated ${l||"unknown"}`,_(r,l);const n=P(r);Y(n),D.textContent=r.length,A(r,"all"),m.onclick=async()=>{const o=U(r,n,l);await B(o)&&(m.classList.add("copied"),m.textContent="✓ Copied",setTimeout(()=>{m.classList.remove("copied"),m.textContent="Copy ticket notes"},2e3))}}catch(s){g.hidden=!1,y.textContent="",g.innerHTML=`
        <p class="processing-error">
          <strong>Could not parse file</strong><br>
          ${u(s.message)}<br>
          <span style="font-size:0.82rem;color:var(--text-muted)">Open Reliability Monitor → Action → Save Reliability History to export the correct file.</span>
        </p>
        <button class="btn-secondary" style="margin-top:1rem" id="retry-btn">← Try another file</button>
      `,(d=document.getElementById("retry-btn"))==null||d.addEventListener("click",T)}},t.readAsArrayBuffer(e)}function T(){g.innerHTML=`
    <div class="processing-spinner"></div>
    <p id="processing-text" class="processing-text">Parsing reliability records…</p>
  `,S.hidden=!1,g.hidden=!0,b.hidden=!0,v.value=""}f.addEventListener("dragover",e=>{e.preventDefault(),f.classList.add("dragover")});f.addEventListener("dragleave",()=>f.classList.remove("dragover"));f.addEventListener("drop",e=>{e.preventDefault(),f.classList.remove("dragover"),I(e.dataTransfer.files[0])});f.addEventListener("click",()=>v.click());v.addEventListener("change",()=>I(v.files[0]));H.addEventListener("click",T);
