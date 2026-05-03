import{s as B}from"./theme-BUo633SF.js";/* empty css                 */import{e as i}from"./utils-CvcbX8Jd.js";B();const A=document.getElementById("upload-section"),w=document.getElementById("processing-section"),$=document.getElementById("processing-text"),E=document.getElementById("results-section"),v=document.getElementById("drop-zone"),y=document.getElementById("file-input"),H=document.getElementById("new-analysis-btn"),N=document.getElementById("results-sub"),k=document.getElementById("overview-grid"),L=document.getElementById("findings-panel"),M=document.getElementById("records-panel"),T=document.getElementById("records-filters-wrap"),I=document.getElementById("records-table-wrap"),j=document.getElementById("tab-findings-count"),D=document.getElementById("tab-records-count");function O(n){const r=(n||"").toLowerCase();return/application error/.test(r)?"crash":/application hang/.test(r)?"hang":/windows error reporting/.test(r)?"wer":/msiinstaller|install|setup|uninstall/i.test(r)?"software":/windows update|windowsupdate|updateclient/i.test(r)?"update":/windows|microsoft/.test(r)?"windows":"info"}const C={crash:"App Crash",hang:"App Hang",wer:"WER",software:"Software",update:"Update",windows:"Windows",info:"Info"},P={crash:"#f85149",hang:"#d29922",wer:"#d29922",software:"#58a6ff",update:"#3fb950",windows:"#bc8cff",info:"#8b949e"},q=[/bad.?block/i,/disk.?error/i,/ntfs.*corrupt/i,/corrupt.*ntfs/i,/hardware.?error/i,/memory.*corrupt/i,/corrupt.*memory/i,/sector.?error/i,/read.?error/i,/i\/o.?error/i,/chkdsk/i,/file.?system.*error/i,/bad.?sector/i];function F(n){return q.some(r=>r.test(n))}function W(n){const o=new DOMParser().parseFromString(n,"application/xml"),c=o.querySelector("parsererror");if(c)throw new Error("Invalid XML: "+c.textContent.slice(0,120));const t=o.querySelector("ReliabilityRecords");if(!t)throw new Error("Not a ReliabilityHistory.xml file — missing <ReliabilityRecords> root element.");const u=t.getAttribute("computer")||"",l=t.getAttribute("generated")||"",g=[...o.querySelectorAll("Record")].map(d=>{const a=e=>{var s,p;return((p=(s=d.querySelector(e))==null?void 0:s.textContent)==null?void 0:p.trim())??""},f=a("TimeGenerated");return{time:f,date:f.slice(0,10),source:a("SourceName"),product:a("ProductName"),message:a("Message"),eventId:a("EventIdentifier"),user:a("User"),cat:O(a("SourceName"))}}).sort((d,a)=>a.time.localeCompare(d.time));return{computer:u,generated:l,records:g}}function G(n){const r=[],o=(e,s,p,h="")=>r.push({sev:e,title:s,detail:p,extra:h}),c=n.filter(e=>e.cat==="crash"),t=n.filter(e=>e.cat==="hang"),u=n.filter(e=>e.cat==="software"),l=n.filter(e=>F(e.message));l.length&&o("crit",`Hardware failure indicator${l.length>1?"s":""} detected (${l.length})`,"One or more records contain keywords associated with disk I/O errors, NTFS corruption, bad sectors, or memory faults. Run <code>chkdsk C: /f /r</code> and check SMART data before any other investigation.",l.slice(0,3).map(e=>`<div class="finding-event"><span class="fe-time">${i(e.time)}</span> <span class="fe-src">${i(e.source)}</span> — ${i(e.message.slice(0,120))}</div>`).join(""));const g={};for(const e of c){const s=(e.product||e.source).toLowerCase();g[s]||(g[s]={label:e.product||e.source,events:[]}),g[s].events.push(e)}for(const[,e]of Object.entries(g).sort((s,p)=>p[1].events.length-s[1].events.length))if(e.events.length>=3){const s=e.events[e.events.length-1].time.slice(0,10),p=e.events[0].time.slice(0,10);o("warn",`${i(e.label)} crashed ${e.events.length} times`,`Repeated crash pattern from ${s} to ${p}. Check for a pending application update, conflicting DLL, or corrupt installation. Look for Event 1000 in the Application log for faulting module details.`,e.events.slice(0,3).map(h=>`<div class="finding-event"><span class="fe-time">${i(h.time)}</span> ${i(h.message.slice(0,100))}</div>`).join(""))}const d={};for(const e of t){const s=(e.product||e.source).toLowerCase();d[s]||(d[s]={label:e.product||e.source,events:[]}),d[s].events.push(e)}for(const[,e]of Object.entries(d).sort((s,p)=>p[1].events.length-s[1].events.length))e.events.length>=2&&o("warn",`${i(e.label)} stopped responding ${e.events.length} times`,`Repeated hang pattern. Common causes: main thread blocked on slow disk/network, deadlock, or antivirus scanning ' +
        'files the app is trying to access. Try disabling AV exclusions for the app directory as a test.`,e.events.slice(0,3).map(s=>`<div class="finding-event"><span class="fe-time">${i(s.time)}</span> ${i(s.message.slice(0,100))}</div>`).join(""));for(const e of u){const s=new Date(e.time),p=new Date(s.getTime()+48*60*60*1e3),h=c.filter(b=>{const m=new Date(b.time);return m>=s&&m<=p});if(h.length>=2){const b=[...new Set(h.map(m=>m.product||m.source))].join(", ");o("warn",`${h.length} crash${h.length>1?"es":""} within 48h of software change`,`<strong>${i(e.product||e.source)}</strong> was installed/changed on ${i(e.time.slice(0,10))}. ${h.length} crashes followed involving: ${i(b)}. Consider rolling back or checking for compatibility issues introduced by the change.`,h.slice(0,3).map(m=>`<div class="finding-event"><span class="fe-time">${i(m.time)}</span> ${i(m.product||m.source)} — ${i(m.message.slice(0,80))}</div>`).join(""))}}const a=new Date,f=n.filter(e=>{const s=new Date(e.time);return a-s<=24*60*60*1e3&&(e.cat==="crash"||e.cat==="hang")});return f.length&&o("warn",`${f.length} crash/hang event${f.length>1?"s":""} in the last 24 hours`,"Active instability — these issues are recent and likely still occurring. Prioritise investigation.",f.map(e=>`<div class="finding-event"><span class="fe-time">${i(e.time)}</span> <span class="fe-src">${i(C[e.cat])}</span> ${i(e.product||e.source)}</div>`).join("")),c.length>=10&&!r.some(e=>e.sev==="crit")&&o("warn",`High crash volume — ${c.length} application crashes recorded`,"This machine has an unusually high number of application crash events. Consider running SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth to check for system file corruption."),r.length===0&&o("ok","No significant issues detected","No recurring crashes, hangs, hardware indicators, or post-install regressions found in the reliability history."),r.sort((e,s)=>{const p={crit:0,warn:1,ok:2};return(p[e.sev]??3)-(p[s.sev]??3)})}function z(n,r){const o=n.filter(a=>a.cat==="crash").length,c=n.filter(a=>a.cat==="hang").length,t=n.filter(a=>a.cat==="software").length,u=n.map(a=>a.date).filter(Boolean),l=u.length?u[u.length-1]:"—",g=u.length?u[0]:"—",d=(a,f,e="")=>`<div class="overview-stat">${e?`<span class="overview-value" style="color:${e}">${f}</span>`:`<span class="overview-value">${f}</span>`}<span class="overview-label">${a}</span></div>`;k.className="overview-grid",k.innerHTML=d("Total Records",n.length)+d("Crashes",o,o>0?"#f85149":"")+d("Hangs",c,c>0?"#d29922":"")+d("Software Changes",t,"#58a6ff")+d("Date Range",l===g?l:`${l} → ${g}`)}function U(n){if(!n.length){L.innerHTML='<p class="no-results">No findings generated.</p>';return}const r={crit:"CRITICAL",warn:"WARNING",ok:"OK"},o={crit:"#f85149",warn:"#d29922",ok:"#3fb950"};L.innerHTML=n.map(t=>`
    <div class="incident-card">
      <div class="incident-header">
        <span class="incident-sev" style="color:${o[t.sev]??"#8b949e"}">${r[t.sev]??t.sev}</span>
        <span class="incident-title">${t.title}</span>
      </div>
      <p class="incident-desc">${t.detail}</p>
      ${t.extra?`<div class="finding-events">${t.extra}</div>`:""}
    </div>
  `).join("");const c=n.filter(t=>t.sev==="crit"||t.sev==="warn").length;j.textContent=c>0?c:""}function S(n,r){const o=["all",...new Set(n.map(t=>t.cat))];T.innerHTML=`
    <div class="filter-bar">
      ${o.map(t=>`
        <button class="filter-chip${r===t?" active":""}" data-cat="${t}">
          ${t==="all"?"All":C[t]??t}
          <span class="chip-count">${t==="all"?n.length:n.filter(u=>u.cat===t).length}</span>
        </button>
      `).join("")}
    </div>
  `;const c=r==="all"?n:n.filter(t=>t.cat===r);if(!c.length){I.innerHTML='<p class="no-results">No records for this filter.</p>';return}I.innerHTML=`
    <div class="event-table-wrap">
      <table class="event-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Category</th>
            <th>Product / Application</th>
            <th>Source</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          ${c.map(t=>`
            <tr>
              <td class="et-time">${i(t.time)}</td>
              <td><span class="cat-badge" style="color:${P[t.cat]??"#8b949e"}">${C[t.cat]??t.cat}</span></td>
              <td class="et-source">${i(t.product||"—")}</td>
              <td class="et-source">${i(t.source)}</td>
              <td class="et-msg">${i(t.message.slice(0,200))}${t.message.length>200?"…":""}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `,T.querySelectorAll(".filter-chip").forEach(t=>{t.addEventListener("click",()=>S(n,t.dataset.cat))})}document.querySelectorAll(".analyzer-tab").forEach(n=>{n.addEventListener("click",()=>{document.querySelectorAll(".analyzer-tab").forEach(o=>o.classList.remove("active")),n.classList.add("active");const r=n.dataset.tab;L.hidden=r!=="findings",M.hidden=r!=="records"})});function R(n){if(!n)return;A.hidden=!0,w.hidden=!1,E.hidden=!0,$.textContent="Parsing reliability records…";const r=new FileReader;r.onload=o=>{var c;try{$.textContent="Analysing…";const{computer:t,generated:u,records:l}=W(o.target.result);if(!l.length)throw new Error("No <Record> elements found in this file.");w.hidden=!0,E.hidden=!1;const g=[t?`Host: ${t}`:"",`${l.length} records`,u?`Generated ${u}`:""].filter(Boolean).join("  ·  ");N.textContent=g,z(l,t);const d=G(l);U(d),D.textContent=l.length,S(l,"all")}catch(t){w.hidden=!1,$.textContent="",w.innerHTML=`
        <p class="processing-error">
          <strong>Could not parse file</strong><br>
          ${i(t.message)}<br>
          <span style="font-size:0.82rem;color:var(--text-muted)">Expected a ReliabilityHistory.xml produced by Get-EventLogExport.ps1</span>
        </p>
        <button class="btn-secondary" style="margin-top:1rem" id="retry-btn">← Try another file</button>
      `,(c=document.getElementById("retry-btn"))==null||c.addEventListener("click",x)}},r.readAsText(n)}function x(){w.innerHTML=`
    <div class="processing-spinner"></div>
    <p id="processing-text" class="processing-text">Parsing reliability records…</p>
  `,A.hidden=!1,w.hidden=!0,E.hidden=!0,y.value=""}v.addEventListener("dragover",n=>{n.preventDefault(),v.classList.add("dragover")});v.addEventListener("dragleave",()=>v.classList.remove("dragover"));v.addEventListener("drop",n=>{n.preventDefault(),v.classList.remove("dragover"),R(n.dataTransfer.files[0])});v.addEventListener("click",()=>y.click());y.addEventListener("change",()=>R(y.files[0]));H.addEventListener("click",x);
