import{s as R}from"./theme-BUo633SF.js";/* empty css                 */import{e as u}from"./utils-CvcbX8Jd.js";R();const x=document.getElementById("upload-section"),f=document.getElementById("processing-section"),v=document.getElementById("processing-text"),y=document.getElementById("results-section"),g=document.getElementById("drop-zone"),h=document.getElementById("file-input"),S=document.getElementById("new-analysis-btn"),B=document.getElementById("results-sub"),E=document.getElementById("overview-grid"),b=document.getElementById("findings-panel"),M=document.getElementById("records-panel"),L=document.getElementById("records-filters-wrap"),C=document.getElementById("records-table-wrap"),H=document.getElementById("tab-findings-count"),N=document.getElementById("tab-records-count");function O(n){const r=(n||"").toLowerCase();return r.includes("stopped working")?"crash":r.includes("stopped responding")?"hang":/windows update|update/.test(r)?"update":/install|reconfigur|removal/.test(r)?"software":"info"}const k={crash:"App Crash",hang:"App Hang",update:"Update",software:"Software",info:"Info"},F={crash:"#f85149",hang:"#d29922",update:"#3fb950",software:"#58a6ff",info:"#8b949e"},W=[/bad.?block/i,/disk.?error/i,/ntfs.*corrupt/i,/corrupt.*ntfs/i,/hardware.?error/i,/memory.*corrupt/i,/corrupt.*memory/i,/sector.?error/i,/read.?error/i,/i\/o.?error/i,/chkdsk/i,/file.?system.*error/i,/bad.?sector/i];function D(n){const a=new DOMParser().parseFromString(n,"application/xml"),c=a.querySelector("parsererror");if(c)throw new Error("Invalid XML: "+c.textContent.slice(0,120));const e=a.documentElement;if(e.tagName!=="RelMonReport")throw new Error(`Unrecognised format — root element is <${e.tagName}>. Expected <RelMonReport> from the Windows Reliability Monitor GUI export. Open Reliability Monitor → Action → Save Reliability History.`);const i=e.getAttribute("TimeGenerated")||"",d=[...a.querySelectorAll("RacEvents > Event")].map(l=>{const o=m=>{var w,$;return(($=(w=l.querySelector(m))==null?void 0:w.textContent)==null?void 0:$.trim())??""},t=o("Impact"),s=o("Source"),p=o("Problem");return{source:s,product:s,message:p,impact:t,cat:O(p)}});if(!d.length)throw new Error("No events found in this Reliability Monitor export.");return{generated:i,records:d}}function P(n){const r=[],a=(t,s,p,m="")=>r.push({sev:t,title:s,detail:p,extra:m}),c=n.filter(t=>t.cat==="crash"),e=n.filter(t=>t.cat==="hang"),i=n.filter(t=>t.impact==="Warning"),d=n.filter(t=>W.some(s=>s.test(t.source)||s.test(t.message)));d.length&&a("crit",`Hardware failure indicator${d.length>1?"s":""} detected (${d.length})`,"One or more records contain keywords associated with disk I/O errors, NTFS corruption, bad sectors, or memory faults. Run <code>chkdsk C: /f /r</code> and check SMART data before any other investigation.",d.slice(0,3).map(t=>`<div class="finding-event"><span class="fe-src">${u(t.source)}</span> — ${u(t.message)}</div>`).join(""));const l={};for(const t of c){const s=t.source.toLowerCase();l[s]||(l[s]={label:t.source,count:0}),l[s].count++}for(const t of Object.values(l).sort((s,p)=>p.count-s.count))t.count>=2&&a("warn",`${u(t.label)} crashed ${t.count} time${t.count>1?"s":""}`,"Repeated crash pattern. Check for a pending application update, conflicting DLL, or corrupt installation. Look for Event 1000 in the Application log for faulting module details.");const o={};for(const t of e){const s=t.source.toLowerCase();o[s]||(o[s]={label:t.source,count:0}),o[s].count++}for(const t of Object.values(o).sort((s,p)=>p.count-s.count))t.count>=2&&a("warn",`${u(t.label)} stopped responding ${t.count} time${t.count>1?"s":""}`,"Repeated hang pattern. Common causes: main thread blocked on slow disk/network, deadlock, or antivirus scanning files the app is trying to access. Try adding the app directory to AV exclusions as a test.");if(i.length>=3){const t=[...new Set(i.slice(0,5).map(s=>s.source))].join(", ");a("warn",`${i.length} failed update${i.length>1?"s":""} or installation${i.length>1?"s":""}`,`Multiple Warning-impact events detected. Check Windows Update history and application installer logs. Affected: ${u(t)}${i.length>5?` + ${i.length-5} more`:""}.`)}return c.length>=8&&!r.some(t=>t.sev==="crit")&&a("warn",`High crash volume — ${c.length} application crashes recorded`,"Unusually high number of application crash events. Consider running <code>sfc /scannow</code> and <code>DISM /Online /Cleanup-Image /RestoreHealth</code> to check for system file corruption."),r.length===0&&a("ok","No significant issues detected","No recurring crashes, hangs, hardware indicators, or failed updates found in the reliability history."),r.sort((t,s)=>{const p={crit:0,warn:1,ok:2};return(p[t.sev]??3)-(p[s.sev]??3)})}function j(n,r){const a=n.filter(o=>o.cat==="crash").length,c=n.filter(o=>o.cat==="hang").length,e=n.filter(o=>o.cat==="software").length,i=n.filter(o=>o.impact==="Warning").length,d=r?r.slice(0,10):"—",l=(o,t,s="")=>`<div class="overview-stat">${s?`<span class="overview-value" style="color:${s}">${t}</span>`:`<span class="overview-value">${t}</span>`}<span class="overview-label">${o}</span></div>`;E.className="overview-grid",E.innerHTML=l("Total Events",n.length)+l("Crashes",a,a>0?"#f85149":"")+l("Hangs",c,c>0?"#d29922":"")+l("Software Changes",e,"#58a6ff")+l("Warnings",i,i>0?"#d29922":"")+l("Report Date",d)}function U(n){if(!n.length){b.innerHTML='<p class="no-results">No findings generated.</p>';return}const r={crit:"CRITICAL",warn:"WARNING",ok:"OK"},a={crit:"#f85149",warn:"#d29922",ok:"#3fb950"};b.innerHTML=n.map(e=>`
    <div class="incident-card">
      <div class="incident-header">
        <span class="incident-sev" style="color:${a[e.sev]??"#8b949e"}">${r[e.sev]??e.sev}</span>
        <span class="incident-title">${e.title}</span>
      </div>
      <p class="incident-desc">${e.detail}</p>
      ${e.extra?`<div class="finding-events">${e.extra}</div>`:""}
    </div>
  `).join("");const c=n.filter(e=>e.sev==="crit"||e.sev==="warn").length;H.textContent=c>0?c:""}function A(n,r){const a=["all",...new Set(n.map(e=>e.cat))];L.innerHTML=`
    <div class="filter-bar">
      ${a.map(e=>`
        <button class="filter-chip${r===e?" active":""}" data-cat="${e}">
          ${e==="all"?"All":k[e]??e}
          <span class="chip-count">${e==="all"?n.length:n.filter(i=>i.cat===e).length}</span>
        </button>
      `).join("")}
    </div>
  `;const c=r==="all"?n:n.filter(e=>e.cat===r);if(!c.length){C.innerHTML='<p class="no-results">No records for this filter.</p>';return}C.innerHTML=`
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
              <td><span class="cat-badge" style="color:${F[e.cat]??"#8b949e"}">${k[e.cat]??e.cat}</span></td>
              <td class="et-source">${u(e.source)}</td>
              <td class="et-msg">${u(e.message)}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `,L.querySelectorAll(".filter-chip").forEach(e=>{e.addEventListener("click",()=>A(n,e.dataset.cat))})}document.querySelectorAll(".analyzer-tab").forEach(n=>{n.addEventListener("click",()=>{document.querySelectorAll(".analyzer-tab").forEach(a=>a.classList.remove("active")),n.classList.add("active");const r=n.dataset.tab;b.hidden=r!=="findings",M.hidden=r!=="records"})});function I(n){if(!n)return;x.hidden=!0,f.hidden=!1,y.hidden=!0,v.textContent="Parsing reliability records…";const r=new FileReader;r.onload=a=>{var c;try{v.textContent="Analysing…";const e=a.target.result,i=new Uint8Array(e);let d;i[0]===255&&i[1]===254?d=new TextDecoder("utf-16le").decode(e):i[0]===254&&i[1]===255?d=new TextDecoder("utf-16be").decode(e):d=new TextDecoder("utf-8").decode(e);const{generated:l,records:o}=D(d);f.hidden=!0,y.hidden=!1,B.textContent=`${o.length} events · Report generated ${l||"unknown"}`,j(o,l);const t=P(o);U(t),N.textContent=o.length,A(o,"all")}catch(e){f.hidden=!1,v.textContent="",f.innerHTML=`
        <p class="processing-error">
          <strong>Could not parse file</strong><br>
          ${u(e.message)}<br>
          <span style="font-size:0.82rem;color:var(--text-muted)">Open Reliability Monitor → Action → Save Reliability History to export the correct file.</span>
        </p>
        <button class="btn-secondary" style="margin-top:1rem" id="retry-btn">← Try another file</button>
      `,(c=document.getElementById("retry-btn"))==null||c.addEventListener("click",T)}},r.readAsArrayBuffer(n)}function T(){f.innerHTML=`
    <div class="processing-spinner"></div>
    <p id="processing-text" class="processing-text">Parsing reliability records…</p>
  `,x.hidden=!1,f.hidden=!0,y.hidden=!0,h.value=""}g.addEventListener("dragover",n=>{n.preventDefault(),g.classList.add("dragover")});g.addEventListener("dragleave",()=>g.classList.remove("dragover"));g.addEventListener("drop",n=>{n.preventDefault(),g.classList.remove("dragover"),I(n.dataTransfer.files[0])});g.addEventListener("click",()=>h.click());h.addEventListener("change",()=>I(h.files[0]));S.addEventListener("click",T);
