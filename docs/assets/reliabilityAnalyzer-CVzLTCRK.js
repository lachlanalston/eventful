import{s as z}from"./theme-BUo633SF.js";/* empty css                 */import{e as u}from"./utils-CvcbX8Jd.js";import{c as F}from"./clipboard-O7iYjrxk.js";z();const R=document.getElementById("upload-section"),$=document.getElementById("processing-section"),W=document.getElementById("processing-text"),A=document.getElementById("results-section"),y=document.getElementById("drop-zone"),T=document.getElementById("file-input"),P=document.getElementById("new-analysis-btn"),L=document.getElementById("copy-ticket-btn"),_=document.getElementById("results-sub"),S=document.getElementById("overview-grid"),I=document.getElementById("findings-panel"),q=document.getElementById("records-panel"),H=document.getElementById("records-filters-wrap"),N=document.getElementById("records-table-wrap"),G=document.getElementById("tab-findings-count"),U=document.getElementById("tab-records-count");function V(t){const r=(t||"").toLowerCase();return r.includes("stopped working")?"crash":r.includes("stopped responding")?"hang":/windows update|update/.test(r)?"update":/install|reconfigur|removal/.test(r)?"software":"info"}const O={crash:"App Crash",hang:"App Hang",update:"Update",software:"Software",info:"Info"},Y={crash:"#f85149",hang:"#d29922",update:"#3fb950",software:"#58a6ff",info:"#8b949e"},K=[/bad.?block/i,/disk.?error/i,/ntfs.*corrupt/i,/corrupt.*ntfs/i,/hardware.?error/i,/memory.*corrupt/i,/corrupt.*memory/i,/sector.?error/i,/read.?error/i,/i\/o.?error/i,/chkdsk/i,/file.?system.*error/i,/bad.?sector/i];function X(t){const i=new DOMParser().parseFromString(t,"application/xml"),d=i.querySelector("parsererror");if(d)throw new Error("Invalid XML: "+d.textContent.slice(0,120));const h=i.documentElement;if(h.tagName!=="RelMonReport")throw h.tagName==="Events"||i.querySelector("Event > System")?new Error("WRONG_TOOL:event_log"):new Error(`Unrecognised format — root element is <${h.tagName}>. Expected <RelMonReport>. Open Reliability Monitor → Action → Save Reliability History.`);const s=h.getAttribute("TimeGenerated")||"",n=[...i.querySelectorAll("RacEvents > Event")].map(l=>{const g=E=>{var w,k;return((k=(w=l.querySelector(E))==null?void 0:w.textContent)==null?void 0:k.trim())??""},v=g("Time"),f=g("Impact"),a=g("Source"),p=g("Problem");return{time:v,date:v.slice(0,10),source:a,product:a,message:p,impact:f,cat:V(p)}}).sort((l,g)=>g.time.localeCompare(l.time));if(!n.length)throw new Error("No events found in this Reliability Monitor export.");return{generated:s,records:n}}function Z(t){var k;const r=[],i=(e,o,c,m="")=>r.push({sev:e,title:o,detail:c,extra:m}),d=t.filter(e=>e.cat==="crash"),h=t.filter(e=>e.cat==="hang"),s=t.filter(e=>e.impact==="Warning"),n=e=>e?e.replace("T"," ").slice(0,16):"",l=e=>`<div class="finding-event"><span class="fe-time">${u(n(e.time))}</span><span class="fe-src">${u(e.source)}</span><span class="fe-msg">${u(e.message)}</span></div>`,g=t.filter(e=>K.some(o=>o.test(e.source)||o.test(e.message)));g.length&&i("crit",`Hardware failure indicator${g.length>1?"s":""} detected (${g.length})`,"One or more records contain keywords associated with disk I/O errors, NTFS corruption, bad sectors, or memory faults. Run <code>chkdsk C: /f /r</code> and check SMART data before any other investigation.",g.slice(0,3).map(l).join(""));const v={};for(const e of d){const o=e.source.toLowerCase();v[o]||(v[o]={label:e.source,events:[]}),v[o].events.push(e)}for(const e of Object.values(v).sort((o,c)=>c.events.length-o.events.length))if(e.events.length>=2){const o=e.events.map(b=>b.time).filter(Boolean).sort(),c=o.length?n(o[0]):"",m=o.length>1?n(o[o.length-1]):"",C=c&&m&&c!==m?` between ${c} and ${m}`:c?` at ${c}`:"";i("warn",`${u(e.label)} crashed ${e.events.length} time${e.events.length>1?"s":""}`,`Repeated crash pattern${C}. Check for a pending application update, conflicting DLL, or corrupt installation. Look for Event 1000 in the Application log for faulting module details.`,e.events.slice(0,5).map(l).join(""))}const f={};for(const e of h){const o=e.source.toLowerCase();f[o]||(f[o]={label:e.source,events:[]}),f[o].events.push(e)}for(const e of Object.values(f).sort((o,c)=>c.events.length-o.events.length))if(e.events.length>=2){const o=e.events.map(b=>b.time).filter(Boolean).sort(),c=o.length?n(o[0]):"",m=o.length>1?n(o[o.length-1]):"",C=c&&m&&c!==m?` between ${c} and ${m}`:c?` at ${c}`:"";i("warn",`${u(e.label)} stopped responding ${e.events.length} time${e.events.length>1?"s":""}`,`Repeated hang pattern${C}. Common causes: main thread blocked on slow disk/network, deadlock, or antivirus scanning files the app is trying to access. Try adding the app directory to AV exclusions as a test.`,e.events.slice(0,5).map(l).join(""))}const a=t.filter(e=>e.cat==="software"),p=[];for(const e of a){const o=new Date(e.time),c=new Date(o.getTime()+48*60*60*1e3),m=d.filter(C=>{const b=new Date(C.time);return b>=o&&b<=c});m.length>=2&&p.push({sw:e,postCrashes:m})}if(p.length){p.sort((c,m)=>m.postCrashes.length-c.postCrashes.length);const e=p.reduce((c,m)=>c+m.postCrashes.length,0),o=p.slice(0,3);i("warn",`${p.length} post-install regression${p.length>1?"s":""} detected — ${e} crash${e>1?"es":""} after software changes`,"Crash clusters found within 48h of software installs/changes. Check top offenders below — consider rolling back the relevant application.",o.map(({sw:c,postCrashes:m})=>`<div class="finding-event"><span class="fe-time">${u(n(c.time))}</span><span class="fe-src">${u(c.source)}</span><span class="fe-msg">→ ${m.length} crash${m.length>1?"es":""} in 48h</span></div>`).join("")+(p.length>3?`<div class="finding-event" style="color:var(--text3);font-size:11px">+ ${p.length-3} more</div>`:""))}const E=new Date(((k=t[0])==null?void 0:k.time)||Date.now()),w=t.filter(e=>{const o=new Date(e.time);return E-o<=24*60*60*1e3&&(e.cat==="crash"||e.cat==="hang")});if(w.length&&i("warn",`${w.length} crash/hang event${w.length>1?"s":""} in the 24h before this report`,"Active instability — these events are recent. Prioritise investigation.",w.map(l).join("")),d.length>=8&&!r.some(e=>e.sev==="crit")&&i("warn",`High crash volume — ${d.length} application crashes recorded`,"Unusually high number of application crash events. Consider running <code>sfc /scannow</code> and <code>DISM /Online /Cleanup-Image /RestoreHealth</code> to check for system file corruption."),s.length>0){const e=[...new Set(s.map(c=>c.source))],o=e.slice(0,5).join(", ")+(e.length>5?` + ${e.length-5} more`:"");i("info",`${s.length} failed update${s.length>1?"s":""} or installation${s.length>1?"s":""}`,`Check Windows Update history and application installer logs. Affected: ${u(o)}.`)}return r.some(e=>e.sev==="crit"||e.sev==="warn")||i("ok","No significant issues detected","No recurring crashes, hangs, hardware indicators, or post-install regressions found."),r.sort((e,o)=>({crit:0,warn:1,ok:2}[e.sev]??3)-({crit:0,warn:1,ok:2}[o.sev]??3))}function J(t,r,i){const d=t.filter(a=>a.cat==="crash").length,h=t.filter(a=>a.cat==="hang").length,s=t.filter(a=>a.cat==="software").length,n=t.filter(a=>a.impact==="Warning").length,l=i?i.slice(0,10):"unknown",g="─".repeat(60),v=a=>a.replace(/<[^>]+>/g,""),f=["RELIABILITY ANALYSIS",`Report Date: ${l}`,"Analysed via Eventful — eventful.lrfa.dev/reliability-analyzer.html","","SUMMARY",`  Total Events:      ${String(t.length).padStart(4)}`,`  Crashes:           ${String(d).padStart(4)}`,`  Hangs:             ${String(h).padStart(4)}`,`  Software Changes:  ${String(s).padStart(4)}`,`  Warnings:          ${String(n).padStart(4)}`,"",`FINDINGS (${r.filter(a=>a.sev==="crit"||a.sev==="warn").length} issue${r.filter(a=>a.sev==="crit"||a.sev==="warn").length!==1?"s":""})`,g];for(const a of r.filter(p=>p.sev==="crit"||p.sev==="warn"||p.sev==="ok")){const p={crit:"CRITICAL",warn:"WARNING",ok:"OK"}[a.sev]??a.sev;f.push(`[${p}] ${v(a.title)}`),f.push(v(a.detail)),f.push("")}return f.push(g),f.join(`
`)}function Q(t,r){const i=t.filter(a=>a.cat==="crash").length,d=t.filter(a=>a.cat==="hang").length,h=t.filter(a=>a.cat==="software").length,s=t.filter(a=>a.impact==="Warning").length,n=t.map(a=>a.date).filter(Boolean).sort(),l=n.length?n[0]:"—",g=n.length?n[n.length-1]:"—",v=l===g?l:`${l} → ${g}`,f=(a,p,E,w)=>`<div class="ob-stat ${E}" data-filter="${w}" style="cursor:pointer" title="Show ${p.toLowerCase()}"><span class="ob-stat-num">${a}</span><span class="ob-stat-label">${p}</span></div>`;S.className="",S.innerHTML=`
    <div class="overview-bar">
      <div class="ob-stats">
        ${f(t.length,"Total","stat-total","all")}
        ${f(i,"Crashes",i>0?"stat-critical":"stat-total","crash")}
        ${f(d,"Hangs",d>0?"stat-error":"stat-total","hang")}
        ${f(h,"Software","stat-info","software")}
        ${f(s,"Warnings",s>0?"stat-warning":"stat-total","warning")}
      </div>
      <div class="ob-divider"></div>
      <div style="display:flex;flex-direction:column;gap:2px">
        <span style="font-family:var(--mono);font-size:11px;color:var(--text3)">Date range</span>
        <span style="font-family:var(--mono);font-size:12px;font-weight:600;color:var(--text2)">${u(v)}</span>
      </div>
    </div>
  `,S.querySelectorAll(".ob-stat[data-filter]").forEach(a=>{a.addEventListener("click",()=>{D("records"),B(t,a.dataset.filter)})})}const ee={crit:"sev-header-critical",warn:"sev-header-warning",ok:"sev-header-info"},te={crit:"#fb7185",warn:"#fbbf24",ok:"#3fb950"},ne={crit:"CRITICAL",warn:"WARNING",ok:"OK"};function se(t){if(!t.length){I.innerHTML='<p class="no-results">No findings generated.</p>';return}const r=t.filter(s=>s.sev==="crit"||s.sev==="warn"||s.sev==="ok"),i=t.filter(s=>s.sev==="info"),d=r.map(s=>`
    <div class="incident-card">
      <div class="incident-header ${ee[s.sev]??""}" style="cursor:default">
        <span style="font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:0.1em;color:${te[s.sev]??"#8b949e"};flex-shrink:0">${ne[s.sev]??s.sev}</span>
        <span class="incident-title">${s.title}</span>
      </div>
      <div class="incident-body">
        <div class="incident-section">
          <p class="incident-text">${s.detail}</p>
          ${s.extra?`<div class="finding-events">${s.extra}</div>`:""}
        </div>
      </div>
    </div>
  `).join(""),h=i.length?`
    <div class="findings-notices">
      ${i.map(s=>`
        <div class="findings-notice">
          <span class="findings-notice-label">NOTE</span>
          <span class="findings-notice-title">${s.title}</span>
          <span class="findings-notice-detail">${s.detail}</span>
        </div>
      `).join("")}
    </div>
  `:"";I.innerHTML=d+h,G.textContent=r.filter(s=>s.sev==="crit"||s.sev==="warn").length||""}function B(t,r){const i=["all",...new Set(t.map(n=>n.cat))];t.some(n=>n.impact==="Warning")&&i.push("warning");const d=n=>n==="all"?"All":n==="warning"?"Warnings":O[n]??n,h=n=>n==="all"?t.length:n==="warning"?t.filter(l=>l.impact==="Warning").length:t.filter(l=>l.cat===n).length;H.innerHTML=`
    <div class="filter-bar">
      ${i.map(n=>`
        <button class="filter-chip${r===n?" active":""}" data-cat="${n}">
          ${d(n)}<span class="chip-count">${h(n)}</span>
        </button>
      `).join("")}
    </div>
  `;const s=r==="all"?t:r==="warning"?t.filter(n=>n.impact==="Warning"):t.filter(n=>n.cat===r);if(!s.length){N.innerHTML='<p class="no-results">No records for this filter.</p>';return}N.innerHTML=`
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
          ${s.map(n=>`
            <tr>
              <td style="font-family:var(--mono);font-size:11px;color:var(--text3);white-space:nowrap">${u(n.time?n.time.replace("T"," ").slice(0,16):"—")}</td>
              <td><span class="cat-badge" style="color:${n.impact==="Critical"?"#f85149":n.impact==="Warning"?"#d29922":"#8b949e"}">${u(n.impact)}</span></td>
              <td><span class="cat-badge" style="color:${Y[n.cat]??"#8b949e"}">${O[n.cat]??n.cat}</span></td>
              <td class="et-source">${u(n.source)}</td>
              <td class="et-msg">${u(n.message)}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `,H.querySelectorAll(".filter-chip").forEach(n=>{n.addEventListener("click",()=>B(t,n.dataset.cat))})}function D(t){document.querySelectorAll(".analyzer-tab").forEach(r=>r.classList.toggle("active",r.dataset.tab===t)),I.hidden=t!=="findings",q.hidden=t!=="records"}document.querySelectorAll(".analyzer-tab").forEach(t=>{t.addEventListener("click",()=>D(t.dataset.tab))});function x(t,r){var i;R.hidden=!0,$.hidden=!1,$.innerHTML=`
    <p class="processing-error">
      <strong>${u(t)}</strong><br>
      ${r}
    </p>
    <button class="btn-secondary" style="margin-top:1rem" id="retry-btn">← Try another file</button>
  `,(i=document.getElementById("retry-btn"))==null||i.addEventListener("click",j)}function M(t){if(!t)return;if(t.name.toLowerCase().endsWith(".zip")){x("Wrong file type",'This looks like a ZIP archive — use <a href="incident-analyzer.html">Windows Incident Analyser</a> to analyse multiple logs together.');return}R.hidden=!0,$.hidden=!1,A.hidden=!0,W.textContent="Parsing reliability records…";const r=new FileReader;r.onload=i=>{try{W.textContent="Analysing…";const d=i.target.result,h=new Uint8Array(d);let s;h[0]===255&&h[1]===254?s=new TextDecoder("utf-16le").decode(d):h[0]===254&&h[1]===255?s=new TextDecoder("utf-16be").decode(d):s=new TextDecoder("utf-8").decode(d);const{generated:n,records:l}=X(s);$.hidden=!0,A.hidden=!1,_.textContent=`${l.length} events · Report generated ${n||"unknown"}`,Q(l,n);const g=Z(l);se(g),U.textContent=l.length,B(l,"all"),L.onclick=async()=>{const v=J(l,g,n);await F(v)&&(L.classList.add("copied"),L.textContent="✓ Copied",setTimeout(()=>{L.classList.remove("copied"),L.textContent="Copy ticket notes"},2e3))}}catch(d){d.message==="WRONG_TOOL:event_log"?x("Wrong file type",'This looks like a Windows Event Log export — use <a href="windows-log-analyzer.html">Windows Log Analyser</a> instead.'):x("Could not parse file",`${u(d.message)}<br><span style="font-size:0.82rem;color:var(--text-muted)">Open Reliability Monitor → Action → Save Reliability History to export the correct file.</span>`)}},r.readAsArrayBuffer(t)}function j(){$.innerHTML=`
    <div class="processing-spinner"></div>
    <p id="processing-text" class="processing-text">Parsing reliability records…</p>
  `,R.hidden=!1,$.hidden=!0,A.hidden=!0,T.value=""}y.addEventListener("dragover",t=>{t.preventDefault(),y.classList.add("dragover")});y.addEventListener("dragleave",()=>y.classList.remove("dragover"));y.addEventListener("drop",t=>{t.preventDefault(),y.classList.remove("dragover"),M(t.dataTransfer.files[0])});y.addEventListener("click",()=>T.click());T.addEventListener("change",()=>M(T.files[0]));P.addEventListener("click",j);
