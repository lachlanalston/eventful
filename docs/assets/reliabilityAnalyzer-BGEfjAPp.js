import{s as j}from"./theme-BUo633SF.js";/* empty css                 */import{e as v}from"./utils-CvcbX8Jd.js";async function F(n){try{return await navigator.clipboard.writeText(n),!0}catch{const r=document.createElement("textarea");r.value=n,r.style.position="fixed",r.style.opacity="0",document.body.appendChild(r),r.select();const i=document.execCommand("copy");return document.body.removeChild(r),i}}j();const M=document.getElementById("upload-section"),$=document.getElementById("processing-section"),L=document.getElementById("processing-text"),A=document.getElementById("results-section"),y=document.getElementById("drop-zone"),T=document.getElementById("file-input"),z=document.getElementById("new-analysis-btn"),x=document.getElementById("copy-ticket-btn"),P=document.getElementById("results-sub"),S=document.getElementById("overview-grid"),I=document.getElementById("findings-panel"),q=document.getElementById("records-panel"),B=document.getElementById("records-filters-wrap"),H=document.getElementById("records-table-wrap"),U=document.getElementById("tab-findings-count"),_=document.getElementById("tab-records-count");function G(n){const r=(n||"").toLowerCase();return r.includes("stopped working")?"crash":r.includes("stopped responding")?"hang":/windows update|update/.test(r)?"update":/install|reconfigur|removal/.test(r)?"software":"info"}const D={crash:"App Crash",hang:"App Hang",update:"Update",software:"Software",info:"Info"},V={crash:"#f85149",hang:"#d29922",update:"#3fb950",software:"#58a6ff",info:"#8b949e"},Y=[/bad.?block/i,/disk.?error/i,/ntfs.*corrupt/i,/corrupt.*ntfs/i,/hardware.?error/i,/memory.*corrupt/i,/corrupt.*memory/i,/sector.?error/i,/read.?error/i,/i\/o.?error/i,/chkdsk/i,/file.?system.*error/i,/bad.?sector/i];function K(n){const i=new DOMParser().parseFromString(n,"application/xml"),f=i.querySelector("parsererror");if(f)throw new Error("Invalid XML: "+f.textContent.slice(0,120));const g=i.documentElement;if(g.tagName!=="RelMonReport")throw new Error(`Unrecognised format — root element is <${g.tagName}>. Expected <RelMonReport>. Open Reliability Monitor → Action → Save Reliability History.`);const s=g.getAttribute("TimeGenerated")||"",t=[...i.querySelectorAll("RacEvents > Event")].map(d=>{const l=E=>{var w,C;return((C=(w=d.querySelector(E))==null?void 0:w.textContent)==null?void 0:C.trim())??""},m=l("Time"),h=l("Impact"),a=l("Source"),p=l("Problem");return{time:m,date:m.slice(0,10),source:a,product:a,message:p,impact:h,cat:G(p)}}).sort((d,l)=>l.time.localeCompare(d.time));if(!t.length)throw new Error("No events found in this Reliability Monitor export.");return{generated:s,records:t}}function X(n){var C;const r=[],i=(e,o,c,u="")=>r.push({sev:e,title:o,detail:c,extra:u}),f=n.filter(e=>e.cat==="crash"),g=n.filter(e=>e.cat==="hang"),s=n.filter(e=>e.impact==="Warning"),t=e=>e?e.replace("T"," ").slice(0,16):"",d=e=>`<div class="finding-event"><span class="fe-time">${v(t(e.time))}</span><span class="fe-src">${v(e.source)}</span><span class="fe-msg">${v(e.message)}</span></div>`,l=n.filter(e=>Y.some(o=>o.test(e.source)||o.test(e.message)));l.length&&i("crit",`Hardware failure indicator${l.length>1?"s":""} detected (${l.length})`,"One or more records contain keywords associated with disk I/O errors, NTFS corruption, bad sectors, or memory faults. Run <code>chkdsk C: /f /r</code> and check SMART data before any other investigation.",l.slice(0,3).map(d).join(""));const m={};for(const e of f){const o=e.source.toLowerCase();m[o]||(m[o]={label:e.source,events:[]}),m[o].events.push(e)}for(const e of Object.values(m).sort((o,c)=>c.events.length-o.events.length))if(e.events.length>=2){const o=e.events.map(b=>b.time).filter(Boolean).sort(),c=o.length?t(o[0]):"",u=o.length>1?t(o[o.length-1]):"",k=c&&u&&c!==u?` between ${c} and ${u}`:c?` at ${c}`:"";i("warn",`${v(e.label)} crashed ${e.events.length} time${e.events.length>1?"s":""}`,`Repeated crash pattern${k}. Check for a pending application update, conflicting DLL, or corrupt installation. Look for Event 1000 in the Application log for faulting module details.`,e.events.slice(0,5).map(d).join(""))}const h={};for(const e of g){const o=e.source.toLowerCase();h[o]||(h[o]={label:e.source,events:[]}),h[o].events.push(e)}for(const e of Object.values(h).sort((o,c)=>c.events.length-o.events.length))if(e.events.length>=2){const o=e.events.map(b=>b.time).filter(Boolean).sort(),c=o.length?t(o[0]):"",u=o.length>1?t(o[o.length-1]):"",k=c&&u&&c!==u?` between ${c} and ${u}`:c?` at ${c}`:"";i("warn",`${v(e.label)} stopped responding ${e.events.length} time${e.events.length>1?"s":""}`,`Repeated hang pattern${k}. Common causes: main thread blocked on slow disk/network, deadlock, or antivirus scanning files the app is trying to access. Try adding the app directory to AV exclusions as a test.`,e.events.slice(0,5).map(d).join(""))}const a=n.filter(e=>e.cat==="software"),p=[];for(const e of a){const o=new Date(e.time),c=new Date(o.getTime()+48*60*60*1e3),u=f.filter(k=>{const b=new Date(k.time);return b>=o&&b<=c});u.length>=2&&p.push({sw:e,postCrashes:u})}if(p.length){p.sort((c,u)=>u.postCrashes.length-c.postCrashes.length);const e=p.reduce((c,u)=>c+u.postCrashes.length,0),o=p.slice(0,3);i("warn",`${p.length} post-install regression${p.length>1?"s":""} detected — ${e} crash${e>1?"es":""} after software changes`,"Crash clusters found within 48h of software installs/changes. Check top offenders below — consider rolling back the relevant application.",o.map(({sw:c,postCrashes:u})=>`<div class="finding-event"><span class="fe-time">${v(t(c.time))}</span><span class="fe-src">${v(c.source)}</span><span class="fe-msg">→ ${u.length} crash${u.length>1?"es":""} in 48h</span></div>`).join("")+(p.length>3?`<div class="finding-event" style="color:var(--text3);font-size:11px">+ ${p.length-3} more</div>`:""))}const E=new Date(((C=n[0])==null?void 0:C.time)||Date.now()),w=n.filter(e=>{const o=new Date(e.time);return E-o<=24*60*60*1e3&&(e.cat==="crash"||e.cat==="hang")});if(w.length&&i("warn",`${w.length} crash/hang event${w.length>1?"s":""} in the 24h before this report`,"Active instability — these events are recent. Prioritise investigation.",w.map(d).join("")),f.length>=8&&!r.some(e=>e.sev==="crit")&&i("warn",`High crash volume — ${f.length} application crashes recorded`,"Unusually high number of application crash events. Consider running <code>sfc /scannow</code> and <code>DISM /Online /Cleanup-Image /RestoreHealth</code> to check for system file corruption."),s.length>0){const e=[...new Set(s.map(c=>c.source))],o=e.slice(0,5).join(", ")+(e.length>5?` + ${e.length-5} more`:"");i("info",`${s.length} failed update${s.length>1?"s":""} or installation${s.length>1?"s":""}`,`Check Windows Update history and application installer logs. Affected: ${v(o)}.`)}return r.some(e=>e.sev==="crit"||e.sev==="warn")||i("ok","No significant issues detected","No recurring crashes, hangs, hardware indicators, or post-install regressions found."),r.sort((e,o)=>({crit:0,warn:1,ok:2}[e.sev]??3)-({crit:0,warn:1,ok:2}[o.sev]??3))}function Z(n,r,i){const f=n.filter(a=>a.cat==="crash").length,g=n.filter(a=>a.cat==="hang").length,s=n.filter(a=>a.cat==="software").length,t=n.filter(a=>a.impact==="Warning").length,d=i?i.slice(0,10):"unknown",l="─".repeat(60),m=a=>a.replace(/<[^>]+>/g,""),h=["RELIABILITY ANALYSIS",`Report Date: ${d}`,"Analysed via Eventful — eventful.lrfa.dev/reliability-analyzer.html","","SUMMARY",`  Total Events:      ${String(n.length).padStart(4)}`,`  Crashes:           ${String(f).padStart(4)}`,`  Hangs:             ${String(g).padStart(4)}`,`  Software Changes:  ${String(s).padStart(4)}`,`  Warnings:          ${String(t).padStart(4)}`,"",`FINDINGS (${r.filter(a=>a.sev==="crit"||a.sev==="warn").length} issue${r.filter(a=>a.sev==="crit"||a.sev==="warn").length!==1?"s":""})`,l];for(const a of r.filter(p=>p.sev==="crit"||p.sev==="warn"||p.sev==="ok")){const p={crit:"CRITICAL",warn:"WARNING",ok:"OK"}[a.sev]??a.sev;h.push(`[${p}] ${m(a.title)}`),h.push(m(a.detail)),h.push("")}return h.push(l),h.join(`
`)}function J(n,r){const i=n.filter(a=>a.cat==="crash").length,f=n.filter(a=>a.cat==="hang").length,g=n.filter(a=>a.cat==="software").length,s=n.filter(a=>a.impact==="Warning").length,t=n.map(a=>a.date).filter(Boolean).sort(),d=t.length?t[0]:"—",l=t.length?t[t.length-1]:"—",m=d===l?d:`${d} → ${l}`,h=(a,p,E,w)=>`<div class="ob-stat ${E}" data-filter="${w}" style="cursor:pointer" title="Show ${p.toLowerCase()}"><span class="ob-stat-num">${a}</span><span class="ob-stat-label">${p}</span></div>`;S.className="",S.innerHTML=`
    <div class="overview-bar">
      <div class="ob-stats">
        ${h(n.length,"Total","stat-total","all")}
        ${h(i,"Crashes",i>0?"stat-critical":"stat-total","crash")}
        ${h(f,"Hangs",f>0?"stat-error":"stat-total","hang")}
        ${h(g,"Software","stat-info","software")}
        ${h(s,"Warnings",s>0?"stat-warning":"stat-total","warning")}
      </div>
      <div class="ob-divider"></div>
      <div style="display:flex;flex-direction:column;gap:2px">
        <span style="font-family:var(--mono);font-size:11px;color:var(--text3)">Date range</span>
        <span style="font-family:var(--mono);font-size:12px;font-weight:600;color:var(--text2)">${v(m)}</span>
      </div>
    </div>
  `,S.querySelectorAll(".ob-stat[data-filter]").forEach(a=>{a.addEventListener("click",()=>{N("records"),R(n,a.dataset.filter)})})}const Q={crit:"sev-header-critical",warn:"sev-header-warning",ok:"sev-header-info"},ee={crit:"#fb7185",warn:"#fbbf24",ok:"#3fb950"},te={crit:"CRITICAL",warn:"WARNING",ok:"OK"};function ne(n){if(!n.length){I.innerHTML='<p class="no-results">No findings generated.</p>';return}const r=n.filter(s=>s.sev==="crit"||s.sev==="warn"||s.sev==="ok"),i=n.filter(s=>s.sev==="info"),f=r.map(s=>`
    <div class="incident-card">
      <div class="incident-header ${Q[s.sev]??""}" style="cursor:default">
        <span style="font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:0.1em;color:${ee[s.sev]??"#8b949e"};flex-shrink:0">${te[s.sev]??s.sev}</span>
        <span class="incident-title">${s.title}</span>
      </div>
      <div class="incident-body">
        <div class="incident-section">
          <p class="incident-text">${s.detail}</p>
          ${s.extra?`<div class="finding-events">${s.extra}</div>`:""}
        </div>
      </div>
    </div>
  `).join(""),g=i.length?`
    <div class="findings-notices">
      ${i.map(s=>`
        <div class="findings-notice">
          <span class="findings-notice-label">NOTE</span>
          <span class="findings-notice-title">${s.title}</span>
          <span class="findings-notice-detail">${s.detail}</span>
        </div>
      `).join("")}
    </div>
  `:"";I.innerHTML=f+g,U.textContent=r.filter(s=>s.sev==="crit"||s.sev==="warn").length||""}function R(n,r){const i=["all",...new Set(n.map(t=>t.cat))];n.some(t=>t.impact==="Warning")&&i.push("warning");const f=t=>t==="all"?"All":t==="warning"?"Warnings":D[t]??t,g=t=>t==="all"?n.length:t==="warning"?n.filter(d=>d.impact==="Warning").length:n.filter(d=>d.cat===t).length;B.innerHTML=`
    <div class="filter-bar">
      ${i.map(t=>`
        <button class="filter-chip${r===t?" active":""}" data-cat="${t}">
          ${f(t)}<span class="chip-count">${g(t)}</span>
        </button>
      `).join("")}
    </div>
  `;const s=r==="all"?n:r==="warning"?n.filter(t=>t.impact==="Warning"):n.filter(t=>t.cat===r);if(!s.length){H.innerHTML='<p class="no-results">No records for this filter.</p>';return}H.innerHTML=`
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
          ${s.map(t=>`
            <tr>
              <td style="font-family:var(--mono);font-size:11px;color:var(--text3);white-space:nowrap">${v(t.time?t.time.replace("T"," ").slice(0,16):"—")}</td>
              <td><span class="cat-badge" style="color:${t.impact==="Critical"?"#f85149":t.impact==="Warning"?"#d29922":"#8b949e"}">${v(t.impact)}</span></td>
              <td><span class="cat-badge" style="color:${V[t.cat]??"#8b949e"}">${D[t.cat]??t.cat}</span></td>
              <td class="et-source">${v(t.source)}</td>
              <td class="et-msg">${v(t.message)}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `,B.querySelectorAll(".filter-chip").forEach(t=>{t.addEventListener("click",()=>R(n,t.dataset.cat))})}function N(n){document.querySelectorAll(".analyzer-tab").forEach(r=>r.classList.toggle("active",r.dataset.tab===n)),I.hidden=n!=="findings",q.hidden=n!=="records"}document.querySelectorAll(".analyzer-tab").forEach(n=>{n.addEventListener("click",()=>N(n.dataset.tab))});function O(n){if(!n)return;M.hidden=!0,$.hidden=!1,A.hidden=!0,L.textContent="Parsing reliability records…";const r=new FileReader;r.onload=i=>{var f;try{L.textContent="Analysing…";const g=i.target.result,s=new Uint8Array(g);let t;s[0]===255&&s[1]===254?t=new TextDecoder("utf-16le").decode(g):s[0]===254&&s[1]===255?t=new TextDecoder("utf-16be").decode(g):t=new TextDecoder("utf-8").decode(g);const{generated:d,records:l}=K(t);$.hidden=!0,A.hidden=!1,P.textContent=`${l.length} events · Report generated ${d||"unknown"}`,J(l,d);const m=X(l);ne(m),_.textContent=l.length,R(l,"all"),x.onclick=async()=>{const h=Z(l,m,d);await F(h)&&(x.classList.add("copied"),x.textContent="✓ Copied",setTimeout(()=>{x.classList.remove("copied"),x.textContent="Copy ticket notes"},2e3))}}catch(g){$.hidden=!1,L.textContent="",$.innerHTML=`
        <p class="processing-error">
          <strong>Could not parse file</strong><br>
          ${v(g.message)}<br>
          <span style="font-size:0.82rem;color:var(--text-muted)">Open Reliability Monitor → Action → Save Reliability History to export the correct file.</span>
        </p>
        <button class="btn-secondary" style="margin-top:1rem" id="retry-btn">← Try another file</button>
      `,(f=document.getElementById("retry-btn"))==null||f.addEventListener("click",W)}},r.readAsArrayBuffer(n)}function W(){$.innerHTML=`
    <div class="processing-spinner"></div>
    <p id="processing-text" class="processing-text">Parsing reliability records…</p>
  `,M.hidden=!1,$.hidden=!0,A.hidden=!0,T.value=""}y.addEventListener("dragover",n=>{n.preventDefault(),y.classList.add("dragover")});y.addEventListener("dragleave",()=>y.classList.remove("dragover"));y.addEventListener("drop",n=>{n.preventDefault(),y.classList.remove("dragover"),O(n.dataTransfer.files[0])});y.addEventListener("click",()=>T.click());T.addEventListener("change",()=>O(T.files[0]));z.addEventListener("click",W);
