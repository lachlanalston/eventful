import{i as Y,t as Q}from"./theme-CCBoUXgy.js";function J(e){const n=new DOMParser().parseFromString(e,"text/xml"),o=n.querySelector("parsererror");if(o)throw new Error(`Invalid XML: ${o.textContent.substring(0,120)}`);const i=n.querySelectorAll("Event");if(i.length===0)throw new Error("No <Event> elements found. Make sure you exported in XML format from Event Viewer.");const s=[];for(const r of i)try{const d=Z(r);!isNaN(d.id)&&d.id>0&&d.timestamp instanceof Date&&!isNaN(d.timestamp)&&s.push(d)}catch{}if(s.length===0)throw new Error("No valid events could be parsed. Check that the XML is a Windows Event Viewer export.");return s.sort((r,d)=>r.timestamp-d.timestamp)}function Z(e){var L,R;const t=e.querySelector("System"),n=parseInt(S(t,"EventID"),10),o=parseInt(S(t,"Level"),10),i=t==null?void 0:t.querySelector("Provider"),s=(i==null?void 0:i.getAttribute("Name"))||(i==null?void 0:i.getAttribute("EventSourceName"))||"",r=S(t,"Channel"),d=S(t,"Computer"),l=parseInt(S(t,"EventRecordID"),10),c=t==null?void 0:t.querySelector("TimeCreated"),u=(c==null?void 0:c.getAttribute("SystemTime"))||(c==null?void 0:c.textContent)||"",g=new Date(u),v=e.querySelector("RenderingInfo"),h=(R=(L=v==null?void 0:v.querySelector("Level"))==null?void 0:L.textContent)==null?void 0:R.trim(),D=ne(o,h),z=ee(e,v),K=te(e);return{id:n,provider:s,channel:r,levelNum:o,severity:D,timestamp:g,computer:d,message:z,recordId:isNaN(l)?0:l,data:K}}function S(e,t){var n,o;return((o=(n=e==null?void 0:e.querySelector(t))==null?void 0:n.textContent)==null?void 0:o.trim())||""}function ee(e,t){var s,r;const n=(r=(s=t==null?void 0:t.querySelector("Message"))==null?void 0:s.textContent)==null?void 0:r.trim();if(n)return n.substring(0,800);const o=e.querySelector("EventData");if(o){const d=[];for(const l of o.querySelectorAll("Data")){const c=l.getAttribute("Name"),u=l.textContent.trim();u&&u!=="-"&&d.push(c?`${c}: ${u}`:u)}if(d.length)return d.join(" | ").substring(0,800)}const i=e.querySelector("UserData");return i?i.textContent.trim().substring(0,800):""}function te(e){const t={},n=e.querySelector("EventData");if(!n)return t;for(const o of n.querySelectorAll("Data")){const i=o.getAttribute("Name"),s=o.textContent.trim();i&&s&&(t[i]=s)}return t}function ne(e,t){if(t){const n=t.toLowerCase();if(n.includes("critical"))return"Critical";if(n.includes("error"))return"Error";if(n.includes("warning"))return"Warning";if(n.includes("information"))return"Info";if(n.includes("verbose"))return"Verbose";if(n.includes("audit"))return t.includes("Failure")?"Error":"Info"}switch(e){case 1:return"Critical";case 2:return"Error";case 3:return"Warning";case 4:return"Info";case 5:return"Verbose";case 0:return"Info";default:return"Info"}}const ie=new Set([41,6008,1001,1e3,7024]),N={7:40,11:30,51:40,52:30,55:35,57:25,129:20,153:20,4101:50,1001:45,1e3:35,1002:30,1026:20,7031:25,7034:25,7022:20,7023:20,7001:15,7011:15,1014:20,4202:20,4201:15,17:50,18:40,19:30,4625:10,4740:15},se=new Set(["Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting"]),re=[{id:"gpu-driver-crash",name:"GPU Driver Crash",icon:"🖥",category:"Hardware Driver",test(e){const t=["nvlddmkm","amdkmdag","amd","igdkmd","dxgkrnl","atikmdag"],n=e.some(i=>i.id===4101),o=e.some(i=>t.some(s=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(s)}));return n?{match:!0,confidence:"high"}:o?{match:!0,confidence:"medium"}:{match:!1}},what:"The graphics card driver stopped responding and Windows could not recover it.",rootCause:"Display driver (TDR timeout) caused the system to become unresponsive.",nextSteps:["Update or roll back GPU drivers via Device Manager → Display Adapters","Use DDU (Display Driver Uninstaller) in Safe Mode for clean reinstall","Monitor GPU temperatures under load with GPU-Z or HWiNFO64","Run GPU stability test with FurMark or 3DMark","Check GPU power connector seating if system is recently assembled"],technicianHint:'NVIDIA: look for "nvlddmkm" in Event 4101 faulting module. AMD: "atikmpag" or "amdkmdag". DDU clean reinstall resolves driver corruption in ~70% of cases. If temps are fine and fresh driver fails, suspect hardware.'},{id:"disk-failure",name:"Storage / Disk Error",icon:"💾",category:"Storage",test(e){const t=[7,11,51,52,55,57,129,153],n=["disk","atapi","nvme","storport","ntfs","fastfat","stornvme"],o=e.filter(i=>t.includes(i.id)||n.some(s=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(s)}));return o.length>=3?{match:!0,confidence:"high"}:o.length>=1?{match:!0,confidence:"medium"}:{match:!1}},what:"The storage device reported I/O errors before the incident.",rootCause:"Disk hardware errors were detected — possible drive failure, bad sectors, or controller issue.",nextSteps:["Run CrystalDiskInfo — check SMART reallocated/pending/uncorrectable sectors","Run chkdsk /f /r /x on affected volume","Run manufacturer disk diagnostic (SeaTools, WD Dashboard, Samsung Magician)","Check SATA/power cable connections","Consider imaging and replacing drive if SMART shows degradation"],technicianHint:"Event 7 = hardware error from disk.sys. Event 51 = error during paging (system swapping to bad sectors — urgent). Event 55 = NTFS filesystem corruption. Multiple Event 7 in a short window usually means imminent failure."},{id:"bsod-kernel-crash",name:"Blue Screen of Death (BSOD)",icon:"🔵",category:"Kernel Crash",test(e,t){return t.id===1001?{match:!0,confidence:"high"}:e.some(n=>n.id===1001)?{match:!0,confidence:"high"}:{match:!1}},what:"Windows detected an unrecoverable kernel error and created a memory dump.",rootCause:"A kernel or driver-level fault caused Windows to stop to prevent data corruption.",nextSteps:["Note the BugCheck code from Event 1001 details","Analyse minidump with WhoCrashed (free) or WinDbg (!analyze -v)","Run SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth","Run Windows Memory Diagnostic for MEMORY_MANAGEMENT (0x1A) stops","Update all drivers — especially GPU, NIC, and chipset"],technicianHint:"Common stop codes: 0x50 PAGE_FAULT (bad RAM or driver), 0x3B SYSTEM_SERVICE_EXCEPTION (driver), 0x1A MEMORY_MANAGEMENT (RAM), 0x7E SYSTEM_THREAD_EXCEPTION (driver), 0x0A IRQL_NOT_LESS_OR_EQUAL (driver/RAM). WhoCrashed gives the culprit driver in seconds."},{id:"service-crash-chain",name:"Service Crash Loop",icon:"⚙",category:"Windows Services",test(e){const t=[7031,7034,7022,7023,7024,7001,7011],n=e.filter(o=>t.includes(o.id));return n.length>=5?{match:!0,confidence:"high"}:n.length>=2?{match:!0,confidence:"medium"}:{match:!1}},what:"One or more Windows services crashed or failed to start repeatedly.",rootCause:"Service instability — possibly caused by a failed update, corrupted binary, or missing dependency.",nextSteps:["Identify which service(s) crashed from the event messages","Check service recovery settings: Services → right-click service → Properties → Recovery","Verify the service executable exists and is not corrupted","Check for related Application log events (Event 1000) for the service host","Review recent Windows Updates that may have changed the service"],technicianHint:"Event 7031 = service terminated unexpectedly (count tells you how many times). Event 7034 = crashed without telling SCM. The service name is in the event message. If it's svchost-hosted, check the service group."},{id:"application-crash-loop",name:"Application Crash Loop",icon:"💥",category:"Application",test(e){const t=e.filter(n=>n.id===1e3);return t.length>=3?{match:!0,confidence:"high"}:t.length>=1?{match:!0,confidence:"medium"}:{match:!1}},what:"An application was crashing repeatedly before the incident.",rootCause:"Application instability — possible corrupt installation, missing runtime, or incompatible update.",nextSteps:["Identify the crashing application from the Event 1000 message","Note the faulting module — it often identifies a specific DLL","Update or reinstall the application","Install/repair Visual C++ Redistributables if a runtime DLL faults","Check crash dumps in %LocalAppData%\\CrashDumps or the application's folder"],technicianHint:'The faulting module in Event 1000 is gold — "ntdll.dll" = OS issue or heap corruption, "msvcp140.dll" / "vcruntime140.dll" = missing C++ runtime, "AppName.exe" itself = bad binary. Repeated same app + same module = deterministic, reproducible fault.'},{id:"memory-hardware",name:"Memory / RAM Issue",icon:"🧠",category:"Hardware",test(e){const t=["microsoft-windows-memoryd","whea-logger","microsoft-windows-whea"],n=[17,18,19,1],o=e.some(s=>n.includes(s.id)||t.some(r=>{var d;return(d=s.provider)==null?void 0:d.toLowerCase().includes(r)})),i=e.some(s=>{var r,d;return s.id===1001&&(((r=s.data)==null?void 0:r.BugcheckCode)==="26"||((d=s.data)==null?void 0:d.BugcheckCode)==="80")});return o||i?{match:!0,confidence:"medium"}:{match:!1}},what:"Hardware memory errors or RAM-related faults were detected.",rootCause:"Defective or misconfigured RAM caused uncorrectable memory errors.",nextSteps:["Run MemTest86+ overnight (at least 2 passes)","Test RAM sticks one at a time to isolate the faulty module","Reseat RAM modules and clean contacts","Check XMP/EXPO profile stability — reset to JEDEC spec in BIOS","Check WHEA-Logger events for corrected/uncorrected error counts"],technicianHint:`WHEA Event 17/18/19 = hardware error framework caught a hardware error. Check the ErrorSource field — "MCE" (Machine Check Exception) = hardware fault, usually RAM or CPU. MemTest86+ is the definitive test. Don't trust Windows Memory Diagnostic for subtle faults.`},{id:"unexpected-power",name:"Unexpected Power Loss",icon:"⚡",category:"Power",test(e,t){var n;return t.id===41&&((n=t.data)==null?void 0:n.BugcheckCode)==="0"?{match:!0,confidence:"high"}:(t.id===41||t.id===6008)&&e.length<=3?{match:!0,confidence:"medium"}:{match:!1}},what:"The system lost power without going through a normal shutdown.",rootCause:"Hard power loss — possible PSU failure, power outage, or UPS failure.",nextSteps:["Check UPS health, battery test, and log — replace battery if > 3 years old","Test PSU voltage rails with PC Power Supply Tester or multimeter","Check power outlet and surge protector for faults","Review Event 41 BugcheckCode: 0 = power loss, non-0 = software crash","Install UPS with AVR if not present — protects against brownouts"],technicianHint:"Event 41 BugcheckCode=0 is definitive: the machine lost power while running (no BSOD, no clean shutdown). Very few preceding events confirms sudden loss. Multiple occurrences = PSU is failing. Check 12V rail — HDD-heavy systems are sensitive."},{id:"network-failure",name:"Network / Connectivity Failure",icon:"🌐",category:"Network",test(e){const t=[1014,4202,4201,6100],n=["tcpip","dns-client","dhcp","netbt","netlogon","rras"],o=e.filter(i=>t.includes(i.id)||n.some(s=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(s)}));return o.length>=3?{match:!0,confidence:"medium"}:o.length>=1?{match:!0,confidence:"low"}:{match:!1}},what:"Network or DNS errors were recorded in the period leading up to the incident.",rootCause:"Network connectivity failure caused application or service faults.",nextSteps:["Check NIC driver version — update if outdated",'Disable NIC power management: Device Manager → NIC → Power Management → uncheck "Allow computer to turn off"',"Test DNS resolution: nslookup google.com","Review DHCP lease renewal logs","Check switch port, cable, and NIC hardware"],technicianHint:"Event 1014 = DNS client resolver timeout. If you see it, look at the DNS server IP in the event — a failing DC or DNS server is a common cause. Event 4201/4202 = NIC connection state changes = intermittent cable or switch issue."}],oe=15,ae={Critical:30,Error:20,Warning:10,Info:2,Verbose:0};function ce(e){var d;if(!e.length)return{incidents:[],healthScore:100,computerName:"",stats:fe()};const t=((d=e[0])==null?void 0:d.computer)||"",n=H(e),o=de(e),i=[];for(const l of o){const c=le(e,l,oe),g=ue(c,l).slice(0,8),v=pe(c,l),h=me(l,v,g);i.push({anchor:l,windowEvents:c,topContributors:g,signatureResult:v,report:h})}const s=we(i),r=ge(e,s);return{incidents:s,healthScore:r,computerName:t,stats:n}}function de(e){const t=[],n=new Set;for(const o of e){if(!ie.has(o.id))continue;const i=`${o.id}-${Math.floor(o.timestamp/3e4)}`;n.has(i)||(n.add(i),t.push(o))}return t.sort((o,i)=>i.timestamp-o.timestamp).slice(0,5)}function le(e,t,n){const o=t.timestamp-n*6e4;return e.filter(i=>i.timestamp>=o&&i.timestamp<t.timestamp)}function ue(e,t){const n=e.map(i=>{let s=ae[i.severity]??0;N[i.id]&&(s+=N[i.id]),i.provider&&t.provider&&i.provider===t.provider&&(s+=8),se.has(i.provider)&&(s=Math.max(0,s-15));const r=(t.timestamp-i.timestamp)/6e4;return r<2?s+=10:r<5&&(s+=5),{event:i,score:s}}),o=new Map;for(const{event:i}of n){const s=`${i.id}-${i.provider}`;o.set(s,(o.get(s)||0)+1)}for(const i of n){const s=`${i.event.id}-${i.event.provider}`,r=o.get(s)||1;r>=5?i.score+=15:r>=3?i.score+=8:r>=2&&(i.score+=4)}return n.filter(({score:i})=>i>0).sort((i,s)=>s.score-i.score).map(({event:i,score:s})=>({event:i,score:s}))}function pe(e,t){const n=[];for(const i of re)try{const s=i.test(e,t);s.match&&n.push({signature:i,confidence:s.confidence})}catch{}const o={high:0,medium:1,low:2};return n.sort((i,s)=>(o[i.confidence]??3)-(o[s.confidence]??3)),n}function me(e,t,n,o){const i=t[0],s=i==null?void 0:i.signature,r=(i==null?void 0:i.confidence)??"low",d=_[e.id]??`Event ${e.id}`,l=(s==null?void 0:s.what)??`${d} occurred at ${q(e.timestamp)}.`,c=(s==null?void 0:s.rootCause)??ve(e,n),u=(s==null?void 0:s.nextSteps)??["Review event details for more information","Check System and Application logs for context"],g=s==null?void 0:s.technicianHint,v=he(e,s,n,r);return{what:l,rootCause:c,confidence:r,nextSteps:u,technicianHint:g,psaSummary:v,alternateSignatures:t.slice(1,3),evidenceCount:n.length}}const _={41:"Unexpected system reboot (Kernel-Power)",6008:"Unexpected previous shutdown (EventLog)",1001:"System crash / BSOD (BugCheck)",1e3:"Application crash (Application Error)",7024:"Critical service failure"};function ve(e,t){if(!t.length)return"No significant preceding events identified in the lookback window.";const n=t[0].event;return`Leading event: ${n.provider||"Unknown"} Event ${n.id} (${n.severity}) recorded shortly before the incident.`}function he(e,t,n,o){return["INCIDENT SUMMARY","================",`Date/Time: ${e.timestamp.toLocaleString()}`,`Anchor Event: ${e.id} — ${_[e.id]??"Unknown"}`,`Provider: ${e.provider||"Unknown"}`,`Computer: ${e.computer||"Unknown"}`,"","DIAGNOSIS","---------",t?`Pattern: ${t.name} (${t.category})`:"Pattern: No known pattern matched",`Confidence: ${o.toUpperCase()}`,"",t?`What happened: ${t.what}`:"",t?`Root cause: ${t.rootCause}`:"","",`CONTRIBUTING EVENTS (top ${Math.min(n.length,5)})`,"------------------",...n.slice(0,5).map(({event:r})=>`  [${r.severity}] Event ${r.id} — ${r.provider||"Unknown"} @ ${q(r.timestamp)}`),"","SUGGESTED NEXT STEPS","--------------------",...((t==null?void 0:t.nextSteps)??["Review event log for more context"]).map(r=>`  • ${r}`),"","Generated by Eventful Incident Analyzer"].filter(r=>r!==void 0).join(`
`)}function H(e){const t={Critical:0,Error:0,Warning:0,Info:0,Verbose:0};for(const n of e)t[n.severity]=(t[n.severity]||0)+1;return{total:e.length,...t}}function fe(){return{total:0,Critical:0,Error:0,Warning:0,Info:0,Verbose:0}}function ge(e,t){let n=100;const o=H(e);n-=Math.min(o.Critical*15,40),n-=Math.min(o.Error*3,25),n-=Math.min(o.Warning*.5,10),n-=t.length*12;for(const i of t)i.report.confidence==="high"?n-=8:i.report.confidence==="medium"&&(n-=4);return Math.max(0,Math.min(100,Math.round(n)))}function we(e){const t=new Set;return e.filter(n=>{const o=`${n.anchor.id}-${Math.floor(n.anchor.timestamp/1e3)}`;return t.has(o)?!1:(t.add(o),!0)})}function q(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}Y();document.querySelectorAll(".theme-btn").forEach(e=>e.addEventListener("click",Q));const I=document.getElementById("upload-section"),V=document.getElementById("processing-section"),G=document.getElementById("results-section"),m=document.getElementById("drop-zone"),C=document.getElementById("file-input"),A=document.getElementById("processing-text"),P=document.getElementById("overview-grid"),E=document.getElementById("incidents-section"),w=document.getElementById("event-table-wrap"),W=document.getElementById("event-log-filters-wrap"),T=document.getElementById("new-analysis-btn"),U=document.getElementById("results-sub");let y=[];C==null||C.addEventListener("change",e=>{var n;const t=(n=e.target.files)==null?void 0:n[0];t&&j(t)});m==null||m.addEventListener("dragover",e=>{e.preventDefault(),m.classList.add("drag-over")});m==null||m.addEventListener("dragleave",()=>m.classList.remove("drag-over"));m==null||m.addEventListener("drop",e=>{var n;e.preventDefault(),m.classList.remove("drag-over");const t=(n=e.dataTransfer.files)==null?void 0:n[0];t&&j(t)});T==null||T.addEventListener("click",ye);async function j(e){if(!e.name.toLowerCase().endsWith(".xml")&&e.type!=="text/xml"&&e.type!=="application/xml"){B("Please upload an XML file exported from Windows Event Viewer.");return}k(`Reading ${e.name}…`);try{const t=await e.text();k("Parsing events…"),await x();const n=J(t);k(`Analysing ${n.length.toLocaleString()} events…`),await x();const o=ce(n);y=n,k("Building report…"),await x(),Se(o,e.name)}catch(t){B(t.message||"Failed to parse file."),$(I)}}function x(){return new Promise(e=>setTimeout(e,16))}function $(e){[I,V,G].forEach(t=>{t&&(t.hidden=!0)}),e&&(e.hidden=!1)}function k(e){A&&(A.textContent=e),$(V)}function ye(){y=[],C&&(C.value=""),$(I)}function Se(e,t){const{incidents:n,healthScore:o,computerName:i,stats:s}=e;if(U){const r=[];i&&r.push(i),r.push(`${s.total.toLocaleString()} events`),n.length&&r.push(`${n.length} incident${n.length!==1?"s":""} detected`),U.textContent=r.join(" · ")}Ee(o,s),be(n),Me(y),$(G)}function Ee(e,t){if(!P)return;const n=e>=80?"#34d399":e>=60?"#f59e0b":"#f43f5e",o=e>=80?"Good":e>=60?"Degraded":"Critical";P.innerHTML=`
    <div class="overview-score-card">
      <div class="score-ring" style="--score-color: ${n}">
        <span class="score-num">${e}</span>
        <span class="score-denom">/100</span>
      </div>
      <div class="score-label">System Health</div>
      <div class="score-status" style="color: ${n}">${o}</div>
    </div>

    <div class="overview-stats">
      ${b("Critical",t.Critical,"stat-critical")}
      ${b("Error",t.Error,"stat-error")}
      ${b("Warning",t.Warning,"stat-warning")}
      ${b("Info",t.Info,"stat-info")}
      ${b("Total Events",t.total,"stat-total")}
    </div>
  `}function b(e,t,n){return`
    <div class="stat-card ${n}">
      <span class="stat-count">${t.toLocaleString()}</span>
      <span class="stat-label">${e}</span>
    </div>
  `}function be(e){if(E){if(!e.length){E.innerHTML=`
      <div class="no-incidents">
        <div class="no-incidents-icon">✓</div>
        <div class="no-incidents-title">No incidents detected</div>
        <div class="no-incidents-sub">No known crash or failure anchor events were found in this log.</div>
      </div>
    `;return}E.innerHTML=`
    <h2 class="section-heading">Detected Incidents</h2>
    ${e.map((t,n)=>Ce(t)).join("")}
  `,E.querySelectorAll(".copy-summary-btn").forEach(t=>{t.addEventListener("click",()=>{const n=t.dataset.summary;navigator.clipboard.writeText(n).then(()=>{t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy for ticket",t.classList.remove("copied")},2e3)})})}),E.querySelectorAll("[data-lookup-id]").forEach(t=>{t.addEventListener("click",()=>{const n=t.dataset.lookupId;window.open(`results.html?q=${n}`,"_blank")})})}}function Ce(e,t){var g,v;const{anchor:n,windowEvents:o,topContributors:i,signatureResult:s,report:r}=e,d=(g=s[0])==null?void 0:g.signature,l=r.confidence,c=Le(n.severity),u=l==="high"?"conf-high":l==="medium"?"conf-medium":"conf-low";return`
    <div class="incident-card">
      <div class="incident-header ${c}">
        <div class="incident-header-left">
          <span class="incident-icon">${(d==null?void 0:d.icon)??"⚠"}</span>
          <div>
            <div class="incident-title">${(d==null?void 0:d.name)??Re(n)}</div>
            <div class="incident-meta">
              <span class="incident-time">${n.timestamp.toLocaleString()}</span>
              <span class="incident-provider">${p(n.provider)}</span>
            </div>
          </div>
        </div>
        <div class="incident-header-right">
          <span class="conf-badge ${u}">${l} confidence</span>
          <span class="event-id-pill" data-lookup-id="${n.id}" title="Look up Event ${n.id}">
            Event ${n.id}
          </span>
        </div>
      </div>

      <div class="incident-body">
        <!-- What happened -->
        <div class="incident-section">
          <div class="incident-section-label">What happened</div>
          <p class="incident-text">${p(r.what)}</p>
        </div>

        <!-- Root cause -->
        <div class="incident-section">
          <div class="incident-section-label">Likely root cause</div>
          <p class="incident-text">${p(r.rootCause)}</p>
        </div>

        <!-- Evidence events -->
        ${i.length?`
        <div class="incident-section">
          <div class="incident-section-label">Contributing events (${i.length} found)</div>
          <div class="evidence-list">
            ${i.slice(0,6).map(({event:h,score:D})=>`
              <div class="evidence-item">
                <span class="ev-sev-dot sev-${h.severity.toLowerCase()}"></span>
                <span class="ev-id" data-lookup-id="${h.id}" title="Look up Event ${h.id}">
                  ${h.id}
                </span>
                <span class="ev-provider">${p(M(h.provider))}</span>
                <span class="ev-time">${X(h.timestamp)}</span>
                <span class="ev-score" title="Relevance score">${D}</span>
              </div>
            `).join("")}
          </div>
        </div>
        `:""}

        <!-- Timeline -->
        ${o.length?$e(o,n):""}

        <!-- Next steps -->
        ${r.nextSteps.length?`
        <div class="incident-section">
          <div class="incident-section-label">Suggested next steps</div>
          <ol class="next-steps-list">
            ${r.nextSteps.map(h=>`<li>${p(h)}</li>`).join("")}
          </ol>
        </div>
        `:""}

        <!-- Technician hint -->
        ${r.technicianHint?`
        <div class="incident-section">
          <div class="technician-hint">
            <span class="hint-label">Tech Hint</span>
            <span class="hint-text">${p(r.technicianHint)}</span>
          </div>
        </div>
        `:""}

        <!-- Copy for ticket -->
        <div class="incident-footer">
          <button class="copy-summary-btn" data-summary="${p(r.psaSummary)}">
            Copy for ticket
          </button>
          ${(v=r.alternateSignatures)!=null&&v.length?`
          <span class="alt-signatures">
            Also possible: ${r.alternateSignatures.map(h=>h.signature.name).join(", ")}
          </span>
          `:""}
        </div>
      </div>
    </div>
  `}function $e(e,t){const n=[...e,t].sort((s,r)=>s.timestamp-r.timestamp),i=n.length>12?[...n.slice(0,6),{_ellipsis:!0,count:n.length-10},...n.slice(-4)]:n;return`
    <div class="incident-section">
      <div class="incident-section-label">Timeline (${e.length} events in ${ke}-min window)</div>
      <div class="mini-timeline">
        ${i.map(s=>{var d;if(s._ellipsis)return`<div class="timeline-ellipsis">· · · ${s.count} more events · · ·</div>`;const r=s===t;return`
            <div class="timeline-item ${r?"timeline-anchor":""}">
              <div class="tl-dot sev-${(d=s.severity)==null?void 0:d.toLowerCase()}"></div>
              <div class="tl-content">
                <span class="tl-time">${X(s.timestamp)}</span>
                <span class="tl-id" data-lookup-id="${s.id}">${s.id}</span>
                <span class="tl-provider">${p(M(s.provider))}</span>
                ${r?'<span class="tl-anchor-label">ANCHOR</span>':""}
              </div>
            </div>
          `}).join("")}
      </div>
    </div>
  `}const ke=15,Ie=new Set(["Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting","Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-DistributedCOM","Microsoft-Windows-Security-SPP","Microsoft-Windows-Defrag","Microsoft-Windows-Power-Troubleshooter"]),O={Critical:0,Error:1,Warning:2,Info:3,Verbose:4},a={sortCol:"timestamp",sortDir:"asc",page:0,pageSize:100,query:"",severity:"",provider:"",channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set};function Me(e){var d,l;if(!W||!w)return;Object.assign(a,{sortCol:"timestamp",sortDir:"asc",page:0,query:"",severity:"",provider:"",channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set});const t=[...new Set(e.map(c=>c.provider).filter(Boolean))].sort(),n=[...new Set(e.map(c=>c.channel).filter(Boolean))].sort(),o=c=>c?new Date(c-c.getTimezoneOffset()*6e4).toISOString().slice(0,16):"",i=(d=e[0])==null?void 0:d.timestamp,s=(l=e[e.length-1])==null?void 0:l.timestamp;W.innerHTML=`
    <div class="event-log-filters">
      <input type="search" id="tbl-query" class="filter-control filter-control-search"
        placeholder="Search ID, provider, message…" autocomplete="off" spellcheck="false" />

      <select id="tbl-severity" class="filter-control filter-control-select">
        <option value="">All severities</option>
        <option>Critical</option><option>Error</option>
        <option>Warning</option><option>Info</option><option>Verbose</option>
      </select>

      <select id="tbl-provider" class="filter-control filter-control-select">
        <option value="">All providers</option>
        ${t.map(c=>`<option value="${p(c)}">${p(M(c))}</option>`).join("")}
      </select>

      <select id="tbl-channel" class="filter-control filter-control-select">
        <option value="">All channels</option>
        ${n.map(c=>`<option value="${p(c)}">${p(c)}</option>`).join("")}
      </select>

      <div class="filter-date-group">
        <span class="filter-date-label">From</span>
        <input type="datetime-local" id="tbl-from" class="filter-control filter-control-date"
          value="${o(i)}" />
      </div>
      <div class="filter-date-group">
        <span class="filter-date-label">To</span>
        <input type="datetime-local" id="tbl-to" class="filter-control filter-control-date"
          value="${o(s)}" />
      </div>

      <div class="filter-spacer"></div>
      <button id="tbl-noise" class="filter-noise-btn">Hide noise</button>
      <button id="tbl-csv"   class="filter-csv-btn">↓ CSV</button>
    </div>
  `;const r=(c,u,g)=>{var v;return(v=document.getElementById(c))==null?void 0:v.addEventListener(u,g)};r("tbl-query","input",c=>{a.query=c.target.value,a.page=0,f()}),r("tbl-severity","change",c=>{a.severity=c.target.value,a.page=0,f()}),r("tbl-provider","change",c=>{a.provider=c.target.value,a.page=0,f()}),r("tbl-channel","change",c=>{a.channel=c.target.value,a.page=0,f()}),r("tbl-from","change",c=>{a.fromTime=c.target.value,a.page=0,f()}),r("tbl-to","change",c=>{a.toTime=c.target.value,a.page=0,f()}),r("tbl-noise","click",c=>{a.hideNoisy=!a.hideNoisy,a.page=0,c.target.classList.toggle("active",a.hideNoisy),c.target.textContent=a.hideNoisy?"Show noise":"Hide noise",f()}),r("tbl-csv","click",()=>Te(F())),f()}function F(){const e=a.query.toLowerCase(),t=a.fromTime?new Date(a.fromTime).getTime():null,n=a.toTime?new Date(a.toTime).getTime():null;let o=y.filter(i=>!(a.severity&&i.severity!==a.severity||a.provider&&i.provider!==a.provider||a.channel&&i.channel!==a.channel||t!==null&&i.timestamp<t||n!==null&&i.timestamp>n||a.hideNoisy&&Ie.has(i.provider)||e&&!`${i.id} ${i.provider} ${i.channel} ${i.message} ${i.severity}`.toLowerCase().includes(e)));return o.sort((i,s)=>{let r=0;switch(a.sortCol){case"timestamp":r=i.timestamp-s.timestamp;break;case"severity":r=(O[i.severity]??9)-(O[s.severity]??9);break;case"id":r=i.id-s.id;break;case"provider":r=(i.provider||"").localeCompare(s.provider||"");break}return a.sortDir==="asc"?r:-r}),o}function f(){if(!w)return;const e=F(),t=e.length,n=Math.max(0,Math.ceil(t/a.pageSize)-1);a.page=Math.min(a.page,n);const o=a.page*a.pageSize,i=e.slice(o,o+a.pageSize);if(!t){w.innerHTML='<div class="table-empty">No events match the current filters.</div>';return}const s=l=>`<span class="sort-arrow ${a.sortCol===l?"active":""}">${a.sortCol===l?a.sortDir==="asc"?"↑":"↓":"↕"}</span>`,r=l=>a.sortCol===l?"sort-active":"";w.innerHTML=`
    <div class="table-info-bar">
      <span class="table-count-text">
        ${(o+1).toLocaleString()}–${Math.min(o+a.pageSize,t).toLocaleString()} of ${t.toLocaleString()} event${t!==1?"s":""}
        ${t<y.length?` (${y.length.toLocaleString()} total)`:""}
      </span>
      <div class="table-pagination">
        <button class="page-btn" id="pg-first" ${a.page===0?"disabled":""}>«</button>
        <button class="page-btn" id="pg-prev"  ${a.page===0?"disabled":""}>‹ Prev</button>
        <span class="page-info">Page ${a.page+1} / ${n+1}</span>
        <button class="page-btn" id="pg-next"  ${a.page>=n?"disabled":""}>Next ›</button>
        <button class="page-btn" id="pg-last"  ${a.page>=n?"disabled":""}>»</button>
      </div>
    </div>
    <table class="event-table">
      <thead><tr>
        <th style="width:18px"></th>
        <th data-sort="timestamp" class="${r("timestamp")}">Time ${s("timestamp")}</th>
        <th data-sort="severity"  class="${r("severity")}">Sev ${s("severity")}</th>
        <th data-sort="id"        class="${r("id")}">ID ${s("id")}</th>
        <th data-sort="provider"  class="${r("provider")}">Provider ${s("provider")}</th>
        <th>Channel</th>
        <th>Message</th>
      </tr></thead>
      <tbody>${i.map(l=>De(l)).join("")}</tbody>
    </table>
  `,w.querySelectorAll("th[data-sort]").forEach(l=>{l.addEventListener("click",()=>{const c=l.dataset.sort;a.sortDir=a.sortCol===c&&a.sortDir==="asc"?"desc":"asc",a.sortCol=c,a.page=0,f()})});const d=(l,c)=>{var u;return(u=document.getElementById(l))==null?void 0:u.addEventListener("click",c)};d("pg-first",()=>{a.page=0,f()}),d("pg-prev",()=>{a.page--,f()}),d("pg-next",()=>{a.page++,f()}),d("pg-last",()=>{a.page=n,f()}),w.querySelectorAll("tbody tr[data-record]").forEach(l=>{l.addEventListener("click",c=>{if(c.target.closest(".table-event-id"))return;const u=parseInt(l.dataset.record,10);a.expandedIds.has(u)?a.expandedIds.delete(u):a.expandedIds.add(u),f()})}),w.querySelectorAll(".table-event-id").forEach(l=>{l.addEventListener("click",c=>{c.stopPropagation(),window.open(`results.html?q=${l.dataset.lookupId}`,"_blank")})})}function De(e){const t=a.expandedIds.has(e.recordId),n=e.severity.toLowerCase(),o=Object.keys(e.data||{}),i=`
    <tr class="ev-row-${n}${t?" row-expanded":""}" data-record="${e.recordId}">
      <td class="ev-col-expand">${t?"▼":"▶"}</td>
      <td class="ev-col-time">${xe(e.timestamp)}</td>
      <td><span class="sev-badge sev-badge-${n}">${e.severity}</span></td>
      <td><span class="table-event-id" data-lookup-id="${e.id}" title="Look up Event ${e.id}">${e.id}</span></td>
      <td class="ev-col-provider" title="${p(e.provider)}">${p(M(e.provider))}</td>
      <td class="ev-col-channel">${p(e.channel)}</td>
      <td class="ev-col-message">${p(e.message.substring(0,150))}</td>
    </tr>`;return t?i+`
    <tr class="ev-detail-row">
      <td colspan="7">
        <div class="ev-detail-inner">
          <div class="ev-detail-message">${p(e.message||"(no message)")}</div>
          <div class="ev-detail-meta">
            ${[["Provider",e.provider],["Channel",e.channel],["Computer",e.computer],["Record ID",e.recordId||"—"]].filter(([,s])=>s).map(([s,r])=>`<div class="ev-detail-field"><span class="ev-detail-key">${s}</span><span class="ev-detail-val">${p(String(r))}</span></div>`).join("")}
          </div>
          ${o.length?`
          <div class="ev-detail-data">
            <div class="ev-detail-data-title">Event Data</div>
            ${o.map(s=>`
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key">${p(s)}</span>
                <span class="ev-detail-data-val">${p(String(e.data[s]))}</span>
              </div>`).join("")}
          </div>`:""}
          <div class="ev-detail-actions">
            <span class="ev-detail-lookup-btn table-event-id" data-lookup-id="${e.id}">
              Look up Event ${e.id} →
            </span>
          </div>
        </div>
      </td>
    </tr>`:i}function Te(e){const t=["Time (UTC)","Severity","EventID","Provider","Channel","Computer","RecordID","Message"],n=d=>`"${String(d??"").replace(/"/g,'""').replace(/\r?\n/g," ")}"`,o=e.map(d=>[d.timestamp.toISOString(),d.severity,d.id,n(d.provider),n(d.channel),n(d.computer),d.recordId,n(d.message)].join(",")),i=[t.join(","),...o].join(`\r
`),s=URL.createObjectURL(new Blob([i],{type:"text/csv;charset=utf-8;"})),r=Object.assign(document.createElement("a"),{href:s,download:`eventful-${new Date().toISOString().slice(0,10)}.csv`});document.body.appendChild(r),r.click(),document.body.removeChild(r),URL.revokeObjectURL(s)}function B(e){const t=m==null?void 0:m.querySelector(".upload-error");t&&t.remove();const n=document.createElement("div");n.className="upload-error",n.textContent=e,m==null||m.appendChild(n),$(I)}function p(e){return e?String(e).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"):""}function M(e){return e?e.replace(/^Microsoft-Windows-/i,"").replace(/^Microsoft-/i,""):"—"}function X(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}function xe(e){return e.toLocaleString([],{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})}function Le(e){return`sev-header-${(e==null?void 0:e.toLowerCase())??"info"}`}function Re(e){return{41:"Unexpected System Reboot",6008:"Unexpected Shutdown Detected",1001:"System Crash (BSOD)",1e3:"Application Crash",7024:"Critical Service Failure"}[e.id]??`Event ${e.id}`}
