import{i as z,t as Q}from"./theme-CCBoUXgy.js";function J(e){const n=new DOMParser().parseFromString(e,"text/xml"),s=n.querySelector("parsererror");if(s)throw new Error(`Invalid XML: ${s.textContent.substring(0,120)}`);const i=n.querySelectorAll("Event");if(i.length===0)throw new Error("No <Event> elements found. Make sure you exported in XML format from Event Viewer.");const r=[];for(const o of i)try{const a=Z(o);!isNaN(a.id)&&a.id>0&&a.timestamp instanceof Date&&!isNaN(a.timestamp)&&r.push(a)}catch{}if(r.length===0)throw new Error("No valid events could be parsed. Check that the XML is a Windows Event Viewer export.");return r.sort((o,a)=>o.timestamp-a.timestamp)}function Z(e){var R,P;const t=e.querySelector("System"),n=parseInt(v(t,"EventID"),10),s=parseInt(v(t,"Level"),10),i=t==null?void 0:t.querySelector("Provider"),r=(i==null?void 0:i.getAttribute("Name"))||(i==null?void 0:i.getAttribute("EventSourceName"))||"",o=v(t,"Channel"),a=v(t,"Computer"),c=parseInt(v(t,"EventRecordID"),10),l=t==null?void 0:t.querySelector("TimeCreated"),p=(l==null?void 0:l.getAttribute("SystemTime"))||(l==null?void 0:l.textContent)||"",f=new Date(p),m=e.querySelector("RenderingInfo"),u=(P=(R=m==null?void 0:m.querySelector("Level"))==null?void 0:R.textContent)==null?void 0:P.trim(),D=ne(s,u),K=ee(e,m),Y=te(e);return{id:n,provider:r,channel:o,levelNum:s,severity:D,timestamp:f,computer:a,message:K,recordId:isNaN(c)?0:c,data:Y}}function v(e,t){var n,s;return((s=(n=e==null?void 0:e.querySelector(t))==null?void 0:n.textContent)==null?void 0:s.trim())||""}function ee(e,t){var r,o;const n=(o=(r=t==null?void 0:t.querySelector("Message"))==null?void 0:r.textContent)==null?void 0:o.trim();if(n)return n.substring(0,800);const s=e.querySelector("EventData");if(s){const a=[];for(const c of s.querySelectorAll("Data")){const l=c.getAttribute("Name"),p=c.textContent.trim();p&&p!=="-"&&a.push(l?`${l}: ${p}`:p)}if(a.length)return a.join(" | ").substring(0,800)}const i=e.querySelector("UserData");return i?i.textContent.trim().substring(0,800):""}function te(e){const t={},n=e.querySelector("EventData");if(!n)return t;for(const s of n.querySelectorAll("Data")){const i=s.getAttribute("Name"),r=s.textContent.trim();i&&r&&(t[i]=r)}return t}function ne(e,t){if(t){const n=t.toLowerCase();if(n.includes("critical"))return"Critical";if(n.includes("error"))return"Error";if(n.includes("warning"))return"Warning";if(n.includes("information"))return"Info";if(n.includes("verbose"))return"Verbose";if(n.includes("audit"))return t.includes("Failure")?"Error":"Info"}switch(e){case 1:return"Critical";case 2:return"Error";case 3:return"Warning";case 4:return"Info";case 5:return"Verbose";case 0:return"Info";default:return"Info"}}const ie=new Set([41,6008,1001,1e3,7024]),U={7:40,11:30,51:40,52:30,55:35,57:25,129:20,153:20,4101:50,1001:45,1e3:35,1002:30,1026:20,7031:25,7034:25,7022:20,7023:20,7001:15,7011:15,1014:20,4202:20,4201:15,17:50,18:40,19:30,4625:10,4740:15},re=new Set(["Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting"]),se=[{id:"gpu-driver-crash",name:"GPU Driver Crash",icon:"🖥",category:"Hardware Driver",test(e){const t=["nvlddmkm","amdkmdag","amd","igdkmd","dxgkrnl","atikmdag"],n=e.some(i=>i.id===4101),s=e.some(i=>t.some(r=>{var o;return(o=i.provider)==null?void 0:o.toLowerCase().includes(r)}));return n?{match:!0,confidence:"high"}:s?{match:!0,confidence:"medium"}:{match:!1}},what:"The graphics card driver stopped responding and Windows could not recover it.",rootCause:"Display driver (TDR timeout) caused the system to become unresponsive.",nextSteps:["Update or roll back GPU drivers via Device Manager → Display Adapters","Use DDU (Display Driver Uninstaller) in Safe Mode for clean reinstall","Monitor GPU temperatures under load with GPU-Z or HWiNFO64","Run GPU stability test with FurMark or 3DMark","Check GPU power connector seating if system is recently assembled"],technicianHint:'NVIDIA: look for "nvlddmkm" in Event 4101 faulting module. AMD: "atikmpag" or "amdkmdag". DDU clean reinstall resolves driver corruption in ~70% of cases. If temps are fine and fresh driver fails, suspect hardware.'},{id:"disk-failure",name:"Storage / Disk Error",icon:"💾",category:"Storage",test(e){const t=[7,11,51,52,55,57,129,153],n=["disk","atapi","nvme","storport","ntfs","fastfat","stornvme"],s=e.filter(i=>t.includes(i.id)||n.some(r=>{var o;return(o=i.provider)==null?void 0:o.toLowerCase().includes(r)}));return s.length>=3?{match:!0,confidence:"high"}:s.length>=1?{match:!0,confidence:"medium"}:{match:!1}},what:"The storage device reported I/O errors before the incident.",rootCause:"Disk hardware errors were detected — possible drive failure, bad sectors, or controller issue.",nextSteps:["Run CrystalDiskInfo — check SMART reallocated/pending/uncorrectable sectors","Run chkdsk /f /r /x on affected volume","Run manufacturer disk diagnostic (SeaTools, WD Dashboard, Samsung Magician)","Check SATA/power cable connections","Consider imaging and replacing drive if SMART shows degradation"],technicianHint:"Event 7 = hardware error from disk.sys. Event 51 = error during paging (system swapping to bad sectors — urgent). Event 55 = NTFS filesystem corruption. Multiple Event 7 in a short window usually means imminent failure."},{id:"bsod-kernel-crash",name:"Blue Screen of Death (BSOD)",icon:"🔵",category:"Kernel Crash",test(e,t){return t.id===1001?{match:!0,confidence:"high"}:e.some(n=>n.id===1001)?{match:!0,confidence:"high"}:{match:!1}},what:"Windows detected an unrecoverable kernel error and created a memory dump.",rootCause:"A kernel or driver-level fault caused Windows to stop to prevent data corruption.",nextSteps:["Note the BugCheck code from Event 1001 details","Analyse minidump with WhoCrashed (free) or WinDbg (!analyze -v)","Run SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth","Run Windows Memory Diagnostic for MEMORY_MANAGEMENT (0x1A) stops","Update all drivers — especially GPU, NIC, and chipset"],technicianHint:"Common stop codes: 0x50 PAGE_FAULT (bad RAM or driver), 0x3B SYSTEM_SERVICE_EXCEPTION (driver), 0x1A MEMORY_MANAGEMENT (RAM), 0x7E SYSTEM_THREAD_EXCEPTION (driver), 0x0A IRQL_NOT_LESS_OR_EQUAL (driver/RAM). WhoCrashed gives the culprit driver in seconds."},{id:"service-crash-chain",name:"Service Crash Loop",icon:"⚙",category:"Windows Services",test(e){const t=[7031,7034,7022,7023,7024,7001,7011],n=e.filter(s=>t.includes(s.id));return n.length>=5?{match:!0,confidence:"high"}:n.length>=2?{match:!0,confidence:"medium"}:{match:!1}},what:"One or more Windows services crashed or failed to start repeatedly.",rootCause:"Service instability — possibly caused by a failed update, corrupted binary, or missing dependency.",nextSteps:["Identify which service(s) crashed from the event messages","Check service recovery settings: Services → right-click service → Properties → Recovery","Verify the service executable exists and is not corrupted","Check for related Application log events (Event 1000) for the service host","Review recent Windows Updates that may have changed the service"],technicianHint:"Event 7031 = service terminated unexpectedly (count tells you how many times). Event 7034 = crashed without telling SCM. The service name is in the event message. If it's svchost-hosted, check the service group."},{id:"application-crash-loop",name:"Application Crash Loop",icon:"💥",category:"Application",test(e){const t=e.filter(n=>n.id===1e3);return t.length>=3?{match:!0,confidence:"high"}:t.length>=1?{match:!0,confidence:"medium"}:{match:!1}},what:"An application was crashing repeatedly before the incident.",rootCause:"Application instability — possible corrupt installation, missing runtime, or incompatible update.",nextSteps:["Identify the crashing application from the Event 1000 message","Note the faulting module — it often identifies a specific DLL","Update or reinstall the application","Install/repair Visual C++ Redistributables if a runtime DLL faults","Check crash dumps in %LocalAppData%\\CrashDumps or the application's folder"],technicianHint:'The faulting module in Event 1000 is gold — "ntdll.dll" = OS issue or heap corruption, "msvcp140.dll" / "vcruntime140.dll" = missing C++ runtime, "AppName.exe" itself = bad binary. Repeated same app + same module = deterministic, reproducible fault.'},{id:"memory-hardware",name:"Memory / RAM Issue",icon:"🧠",category:"Hardware",test(e){const t=["microsoft-windows-memoryd","whea-logger","microsoft-windows-whea"],n=[17,18,19,1],s=e.some(r=>n.includes(r.id)||t.some(o=>{var a;return(a=r.provider)==null?void 0:a.toLowerCase().includes(o)})),i=e.some(r=>{var o,a;return r.id===1001&&(((o=r.data)==null?void 0:o.BugcheckCode)==="26"||((a=r.data)==null?void 0:a.BugcheckCode)==="80")});return s||i?{match:!0,confidence:"medium"}:{match:!1}},what:"Hardware memory errors or RAM-related faults were detected.",rootCause:"Defective or misconfigured RAM caused uncorrectable memory errors.",nextSteps:["Run MemTest86+ overnight (at least 2 passes)","Test RAM sticks one at a time to isolate the faulty module","Reseat RAM modules and clean contacts","Check XMP/EXPO profile stability — reset to JEDEC spec in BIOS","Check WHEA-Logger events for corrected/uncorrected error counts"],technicianHint:`WHEA Event 17/18/19 = hardware error framework caught a hardware error. Check the ErrorSource field — "MCE" (Machine Check Exception) = hardware fault, usually RAM or CPU. MemTest86+ is the definitive test. Don't trust Windows Memory Diagnostic for subtle faults.`},{id:"unexpected-power",name:"Unexpected Power Loss",icon:"⚡",category:"Power",test(e,t){var n;return t.id===41&&((n=t.data)==null?void 0:n.BugcheckCode)==="0"?{match:!0,confidence:"high"}:(t.id===41||t.id===6008)&&e.length<=3?{match:!0,confidence:"medium"}:{match:!1}},what:"The system lost power without going through a normal shutdown.",rootCause:"Hard power loss — possible PSU failure, power outage, or UPS failure.",nextSteps:["Check UPS health, battery test, and log — replace battery if > 3 years old","Test PSU voltage rails with PC Power Supply Tester or multimeter","Check power outlet and surge protector for faults","Review Event 41 BugcheckCode: 0 = power loss, non-0 = software crash","Install UPS with AVR if not present — protects against brownouts"],technicianHint:"Event 41 BugcheckCode=0 is definitive: the machine lost power while running (no BSOD, no clean shutdown). Very few preceding events confirms sudden loss. Multiple occurrences = PSU is failing. Check 12V rail — HDD-heavy systems are sensitive."},{id:"network-failure",name:"Network / Connectivity Failure",icon:"🌐",category:"Network",test(e){const t=[1014,4202,4201,6100],n=["tcpip","dns-client","dhcp","netbt","netlogon","rras"],s=e.filter(i=>t.includes(i.id)||n.some(r=>{var o;return(o=i.provider)==null?void 0:o.toLowerCase().includes(r)}));return s.length>=3?{match:!0,confidence:"medium"}:s.length>=1?{match:!0,confidence:"low"}:{match:!1}},what:"Network or DNS errors were recorded in the period leading up to the incident.",rootCause:"Network connectivity failure caused application or service faults.",nextSteps:["Check NIC driver version — update if outdated",'Disable NIC power management: Device Manager → NIC → Power Management → uncheck "Allow computer to turn off"',"Test DNS resolution: nslookup google.com","Review DHCP lease renewal logs","Check switch port, cable, and NIC hardware"],technicianHint:"Event 1014 = DNS client resolver timeout. If you see it, look at the DNS server IP in the event — a failing DC or DNS server is a common cause. Event 4201/4202 = NIC connection state changes = intermittent cable or switch issue."}],oe=15,ae={Critical:30,Error:20,Warning:10,Info:2,Verbose:0};function ce(e){var a;if(!e.length)return{incidents:[],healthScore:100,computerName:"",stats:ve()};const t=((a=e[0])==null?void 0:a.computer)||"",n=q(e),s=de(e),i=[];for(const c of s){const l=le(e,c,oe),f=ue(l,c).slice(0,8),m=me(l,c),u=pe(c,m,f);i.push({anchor:c,windowEvents:l,topContributors:f,signatureResult:m,report:u})}const r=we(i),o=ge(e,r);return{incidents:r,healthScore:o,computerName:t,stats:n}}function de(e){const t=[],n=new Set;for(const s of e){if(!ie.has(s.id))continue;const i=`${s.id}-${Math.floor(s.timestamp/3e4)}`;n.has(i)||(n.add(i),t.push(s))}return t.sort((s,i)=>i.timestamp-s.timestamp).slice(0,5)}function le(e,t,n){const s=t.timestamp-n*6e4;return e.filter(i=>i.timestamp>=s&&i.timestamp<t.timestamp)}function ue(e,t){const n=e.map(i=>{let r=ae[i.severity]??0;U[i.id]&&(r+=U[i.id]),i.provider&&t.provider&&i.provider===t.provider&&(r+=8),re.has(i.provider)&&(r=Math.max(0,r-15));const o=(t.timestamp-i.timestamp)/6e4;return o<2?r+=10:o<5&&(r+=5),{event:i,score:r}}),s=new Map;for(const{event:i}of n){const r=`${i.id}-${i.provider}`;s.set(r,(s.get(r)||0)+1)}for(const i of n){const r=`${i.event.id}-${i.event.provider}`,o=s.get(r)||1;o>=5?i.score+=15:o>=3?i.score+=8:o>=2&&(i.score+=4)}return n.filter(({score:i})=>i>0).sort((i,r)=>r.score-i.score).map(({event:i,score:r})=>({event:i,score:r}))}function me(e,t){const n=[];for(const i of se)try{const r=i.test(e,t);r.match&&n.push({signature:i,confidence:r.confidence})}catch{}const s={high:0,medium:1,low:2};return n.sort((i,r)=>(s[i.confidence]??3)-(s[r.confidence]??3)),n}function pe(e,t,n,s){const i=t[0],r=i==null?void 0:i.signature,o=(i==null?void 0:i.confidence)??"low",a=H[e.id]??`Event ${e.id}`,c=(r==null?void 0:r.what)??`${a} occurred at ${V(e.timestamp)}.`,l=(r==null?void 0:r.rootCause)??he(e,n),p=(r==null?void 0:r.nextSteps)??["Review event details for more information","Check System and Application logs for context"],f=r==null?void 0:r.technicianHint,m=fe(e,r,n,o);return{what:c,rootCause:l,confidence:o,nextSteps:p,technicianHint:f,psaSummary:m,alternateSignatures:t.slice(1,3),evidenceCount:n.length}}const H={41:"Unexpected system reboot (Kernel-Power)",6008:"Unexpected previous shutdown (EventLog)",1001:"System crash / BSOD (BugCheck)",1e3:"Application crash (Application Error)",7024:"Critical service failure"};function he(e,t){if(!t.length)return"No significant preceding events identified in the lookback window.";const n=t[0].event;return`Leading event: ${n.provider||"Unknown"} Event ${n.id} (${n.severity}) recorded shortly before the incident.`}function fe(e,t,n,s){return["INCIDENT SUMMARY","================",`Date/Time: ${e.timestamp.toLocaleString()}`,`Anchor Event: ${e.id} — ${H[e.id]??"Unknown"}`,`Provider: ${e.provider||"Unknown"}`,`Computer: ${e.computer||"Unknown"}`,"","DIAGNOSIS","---------",t?`Pattern: ${t.name} (${t.category})`:"Pattern: No known pattern matched",`Confidence: ${s.toUpperCase()}`,"",t?`What happened: ${t.what}`:"",t?`Root cause: ${t.rootCause}`:"","",`CONTRIBUTING EVENTS (top ${Math.min(n.length,5)})`,"------------------",...n.slice(0,5).map(({event:o})=>`  [${o.severity}] Event ${o.id} — ${o.provider||"Unknown"} @ ${V(o.timestamp)}`),"","SUGGESTED NEXT STEPS","--------------------",...((t==null?void 0:t.nextSteps)??["Review event log for more context"]).map(o=>`  • ${o}`),"","Generated by Eventful Incident Analyzer"].filter(o=>o!==void 0).join(`
`)}function q(e){const t={Critical:0,Error:0,Warning:0,Info:0,Verbose:0};for(const n of e)t[n.severity]=(t[n.severity]||0)+1;return{total:e.length,...t}}function ve(){return{total:0,Critical:0,Error:0,Warning:0,Info:0,Verbose:0}}function ge(e,t){let n=100;const s=q(e);n-=Math.min(s.Critical*15,40),n-=Math.min(s.Error*3,25),n-=Math.min(s.Warning*.5,10),n-=t.length*12;for(const i of t)i.report.confidence==="high"?n-=8:i.report.confidence==="medium"&&(n-=4);return Math.max(0,Math.min(100,Math.round(n)))}function we(e){const t=new Set;return e.filter(n=>{const s=`${n.anchor.id}-${Math.floor(n.anchor.timestamp/1e3)}`;return t.has(s)?!1:(t.add(s),!0)})}function V(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}z();document.querySelectorAll(".theme-btn").forEach(e=>e.addEventListener("click",Q));const M=document.getElementById("upload-section"),G=document.getElementById("processing-section"),X=document.getElementById("results-section"),d=document.getElementById("drop-zone"),S=document.getElementById("file-input"),W=document.getElementById("processing-text"),O=document.getElementById("overview-grid"),g=document.getElementById("incidents-section"),b=document.getElementById("event-table-wrap"),y=document.getElementById("event-filter"),E=document.getElementById("severity-filter"),I=document.getElementById("new-analysis-btn"),_=document.getElementById("results-sub");let C=[],A="",x="";S==null||S.addEventListener("change",e=>{var n;const t=(n=e.target.files)==null?void 0:n[0];t&&F(t)});d==null||d.addEventListener("dragover",e=>{e.preventDefault(),d.classList.add("drag-over")});d==null||d.addEventListener("dragleave",()=>d.classList.remove("drag-over"));d==null||d.addEventListener("drop",e=>{var n;e.preventDefault(),d.classList.remove("drag-over");const t=(n=e.dataTransfer.files)==null?void 0:n[0];t&&F(t)});I==null||I.addEventListener("click",Se);async function F(e){if(!e.name.toLowerCase().endsWith(".xml")&&e.type!=="text/xml"&&e.type!=="application/xml"){B("Please upload an XML file exported from Windows Event Viewer.");return}k(`Reading ${e.name}…`);try{const t=await e.text();k("Parsing events…"),await T();const n=J(t);k(`Analysing ${n.length.toLocaleString()} events…`),await T();const s=ce(n);C=n,k("Building report…"),await T(),ye(s,e.name)}catch(t){B(t.message||"Failed to parse file."),$(M)}}function T(){return new Promise(e=>setTimeout(e,16))}function $(e){[M,G,X].forEach(t=>{t&&(t.hidden=!0)}),e&&(e.hidden=!1)}function k(e){W&&(W.textContent=e),$(G)}function Se(){C=[],S&&(S.value=""),$(M)}function ye(e,t){const{incidents:n,healthScore:s,computerName:i,stats:r}=e;if(_){const o=[];i&&o.push(i),o.push(`${r.total.toLocaleString()} events`),n.length&&o.push(`${n.length} incident${n.length!==1?"s":""} detected`),_.textContent=o.join(" · ")}Ee(s,r),Ce(n),Me(C),$(X)}function Ee(e,t){if(!O)return;const n=e>=80?"#34d399":e>=60?"#f59e0b":"#f43f5e",s=e>=80?"Good":e>=60?"Degraded":"Critical";O.innerHTML=`
    <div class="overview-score-card">
      <div class="score-ring" style="--score-color: ${n}">
        <span class="score-num">${e}</span>
        <span class="score-denom">/100</span>
      </div>
      <div class="score-label">System Health</div>
      <div class="score-status" style="color: ${n}">${s}</div>
    </div>

    <div class="overview-stats">
      ${w("Critical",t.Critical,"stat-critical")}
      ${w("Error",t.Error,"stat-error")}
      ${w("Warning",t.Warning,"stat-warning")}
      ${w("Info",t.Info,"stat-info")}
      ${w("Total Events",t.total,"stat-total")}
    </div>
  `}function w(e,t,n){return`
    <div class="stat-card ${n}">
      <span class="stat-count">${t.toLocaleString()}</span>
      <span class="stat-label">${e}</span>
    </div>
  `}function Ce(e){if(g){if(!e.length){g.innerHTML=`
      <div class="no-incidents">
        <div class="no-incidents-icon">✓</div>
        <div class="no-incidents-title">No incidents detected</div>
        <div class="no-incidents-sub">No known crash or failure anchor events were found in this log.</div>
      </div>
    `;return}g.innerHTML=`
    <h2 class="section-heading">Detected Incidents</h2>
    ${e.map((t,n)=>$e(t)).join("")}
  `,g.querySelectorAll(".copy-summary-btn").forEach(t=>{t.addEventListener("click",()=>{const n=t.dataset.summary;navigator.clipboard.writeText(n).then(()=>{t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy for ticket",t.classList.remove("copied")},2e3)})})}),g.querySelectorAll("[data-lookup-id]").forEach(t=>{t.addEventListener("click",()=>{const n=t.dataset.lookupId;window.open(`results.html?q=${n}`,"_blank")})})}}function $e(e,t){var f,m;const{anchor:n,windowEvents:s,topContributors:i,signatureResult:r,report:o}=e,a=(f=r[0])==null?void 0:f.signature,c=o.confidence,l=Ie(n.severity),p=c==="high"?"conf-high":c==="medium"?"conf-medium":"conf-low";return`
    <div class="incident-card">
      <div class="incident-header ${l}">
        <div class="incident-header-left">
          <span class="incident-icon">${(a==null?void 0:a.icon)??"⚠"}</span>
          <div>
            <div class="incident-title">${(a==null?void 0:a.name)??Te(n)}</div>
            <div class="incident-meta">
              <span class="incident-time">${n.timestamp.toLocaleString()}</span>
              <span class="incident-provider">${h(n.provider)}</span>
            </div>
          </div>
        </div>
        <div class="incident-header-right">
          <span class="conf-badge ${p}">${c} confidence</span>
          <span class="event-id-pill" data-lookup-id="${n.id}" title="Look up Event ${n.id}">
            Event ${n.id}
          </span>
        </div>
      </div>

      <div class="incident-body">
        <!-- What happened -->
        <div class="incident-section">
          <div class="incident-section-label">What happened</div>
          <p class="incident-text">${h(o.what)}</p>
        </div>

        <!-- Root cause -->
        <div class="incident-section">
          <div class="incident-section-label">Likely root cause</div>
          <p class="incident-text">${h(o.rootCause)}</p>
        </div>

        <!-- Evidence events -->
        ${i.length?`
        <div class="incident-section">
          <div class="incident-section-label">Contributing events (${i.length} found)</div>
          <div class="evidence-list">
            ${i.slice(0,6).map(({event:u,score:D})=>`
              <div class="evidence-item">
                <span class="ev-sev-dot sev-${u.severity.toLowerCase()}"></span>
                <span class="ev-id" data-lookup-id="${u.id}" title="Look up Event ${u.id}">
                  ${u.id}
                </span>
                <span class="ev-provider">${h(N(u.provider))}</span>
                <span class="ev-time">${j(u.timestamp)}</span>
                <span class="ev-score" title="Relevance score">${D}</span>
              </div>
            `).join("")}
          </div>
        </div>
        `:""}

        <!-- Timeline -->
        ${s.length?ke(s,n):""}

        <!-- Next steps -->
        ${o.nextSteps.length?`
        <div class="incident-section">
          <div class="incident-section-label">Suggested next steps</div>
          <ol class="next-steps-list">
            ${o.nextSteps.map(u=>`<li>${h(u)}</li>`).join("")}
          </ol>
        </div>
        `:""}

        <!-- Technician hint -->
        ${o.technicianHint?`
        <div class="incident-section">
          <div class="technician-hint">
            <span class="hint-label">Tech Hint</span>
            <span class="hint-text">${h(o.technicianHint)}</span>
          </div>
        </div>
        `:""}

        <!-- Copy for ticket -->
        <div class="incident-footer">
          <button class="copy-summary-btn" data-summary="${h(o.psaSummary)}">
            Copy for ticket
          </button>
          ${(m=o.alternateSignatures)!=null&&m.length?`
          <span class="alt-signatures">
            Also possible: ${o.alternateSignatures.map(u=>u.signature.name).join(", ")}
          </span>
          `:""}
        </div>
      </div>
    </div>
  `}function ke(e,t){const n=[...e,t].sort((r,o)=>r.timestamp-o.timestamp),i=n.length>12?[...n.slice(0,6),{_ellipsis:!0,count:n.length-10},...n.slice(-4)]:n;return`
    <div class="incident-section">
      <div class="incident-section-label">Timeline (${e.length} events in ${be}-min window)</div>
      <div class="mini-timeline">
        ${i.map(r=>{var a;if(r._ellipsis)return`<div class="timeline-ellipsis">· · · ${r.count} more events · · ·</div>`;const o=r===t;return`
            <div class="timeline-item ${o?"timeline-anchor":""}">
              <div class="tl-dot sev-${(a=r.severity)==null?void 0:a.toLowerCase()}"></div>
              <div class="tl-content">
                <span class="tl-time">${j(r.timestamp)}</span>
                <span class="tl-id" data-lookup-id="${r.id}">${r.id}</span>
                <span class="tl-provider">${h(N(r.provider))}</span>
                ${o?'<span class="tl-anchor-label">ANCHOR</span>':""}
              </div>
            </div>
          `}).join("")}
      </div>
    </div>
  `}const be=15;function Me(e){b&&(A="",x="",y&&(y.value=""),E&&(E.value=""),L(e))}function L(e){const t=A.toLowerCase(),n=x,s=e.filter(a=>!(n&&a.severity!==n||t&&!`${a.id} ${a.provider} ${a.channel} ${a.message} ${a.severity}`.toLowerCase().includes(t)));if(!s.length){b.innerHTML='<div class="table-empty">No events match the current filter.</div>';return}const i=500,r=s.length>i,o=s.slice(0,i);b.innerHTML=`
    ${r?`<div class="table-notice">Showing first ${i} of ${s.length.toLocaleString()} matching events.</div>`:""}
    <table class="event-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Sev</th>
          <th>ID</th>
          <th>Provider</th>
          <th>Channel</th>
          <th>Message</th>
        </tr>
      </thead>
      <tbody>
        ${o.map(a=>`
          <tr class="ev-row-${a.severity.toLowerCase()}">
            <td class="ev-col-time">${De(a.timestamp)}</td>
            <td><span class="sev-badge sev-badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
            <td>
              <span class="table-event-id" data-lookup-id="${a.id}" title="Look up Event ${a.id}">
                ${a.id}
              </span>
            </td>
            <td class="ev-col-provider">${h(N(a.provider))}</td>
            <td class="ev-col-channel">${h(a.channel)}</td>
            <td class="ev-col-message">${h(a.message.substring(0,120))}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `,b.querySelectorAll("[data-lookup-id]").forEach(a=>{a.addEventListener("click",()=>window.open(`results.html?q=${a.dataset.lookupId}`,"_blank"))})}y==null||y.addEventListener("input",e=>{A=e.target.value,L(C)});E==null||E.addEventListener("change",e=>{x=e.target.value,L(C)});function B(e){const t=d==null?void 0:d.querySelector(".upload-error");t&&t.remove();const n=document.createElement("div");n.className="upload-error",n.textContent=e,d==null||d.appendChild(n),$(M)}function h(e){return e?String(e).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"):""}function N(e){return e?e.replace(/^Microsoft-Windows-/i,"").replace(/^Microsoft-/i,""):"—"}function j(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}function De(e){return e.toLocaleString([],{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})}function Ie(e){return`sev-header-${(e==null?void 0:e.toLowerCase())??"info"}`}function Te(e){return{41:"Unexpected System Reboot",6008:"Unexpected Shutdown Detected",1001:"System Crash (BSOD)",1e3:"Application Crash",7024:"Critical Service Failure"}[e.id]??`Event ${e.id}`}
