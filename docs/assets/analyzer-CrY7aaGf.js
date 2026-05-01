import{i as ge,t as we}from"./theme-CCBoUXgy.js";import{a as ye}from"./index-BAM9NZ7H.js";function Se(e){const s=new DOMParser().parseFromString(e,"text/xml"),a=s.querySelector("parsererror");if(a)throw new Error(`Invalid XML: ${a.textContent.substring(0,120)}`);const n=s.querySelectorAll("Event");if(n.length===0)throw new Error("No <Event> elements found. Make sure you exported in XML format from Event Viewer.");const o=[];for(const i of n)try{const c=$e(i);!isNaN(c.id)&&c.id>0&&c.timestamp instanceof Date&&!isNaN(c.timestamp)&&o.push(c)}catch{}if(o.length===0)throw new Error("No valid events could be parsed. Check that the XML is a Windows Event Viewer export.");return o.sort((i,c)=>i.timestamp-c.timestamp)}function $e(e){var O,W,U,q,B,H,_,j,V;const t=e.querySelector("System"),s=parseInt(b(t,"EventID"),10),a=parseInt(b(t,"Level"),10),n=t==null?void 0:t.querySelector("Provider"),o=(n==null?void 0:n.getAttribute("Name"))||(n==null?void 0:n.getAttribute("EventSourceName"))||"",i=b(t,"Channel"),c=b(t,"Computer"),r=parseInt(b(t,"EventRecordID"),10),l=t==null?void 0:t.querySelector("TimeCreated"),u=(l==null?void 0:l.getAttribute("SystemTime"))||(l==null?void 0:l.textContent)||"",g=new Date(u),h=t==null?void 0:t.querySelector("Execution"),m=t==null?void 0:t.querySelector("Correlation"),f=t==null?void 0:t.querySelector("Security"),v=e.querySelector("RenderingInfo"),$=(W=(O=v==null?void 0:v.querySelector("Level"))==null?void 0:O.textContent)==null?void 0:W.trim(),C=Ce(a,$),le=((q=(U=v==null?void 0:v.querySelector("Task"))==null?void 0:U.textContent)==null?void 0:q.trim())||"",de=((H=(B=v==null?void 0:v.querySelector("Opcode"))==null?void 0:B.textContent)==null?void 0:H.trim())||"",pe=[...(v==null?void 0:v.querySelectorAll("Keywords > Keyword"))??[]].map(fe=>fe.textContent.trim()).filter(Boolean),ue=((j=(_=v==null?void 0:v.querySelector("Provider"))==null?void 0:_.textContent)==null?void 0:j.trim())||"",me=be(e,v),{named:ve,anon:he}=Ee(e);return{id:s,provider:o,channel:i,levelNum:a,severity:C,timestamp:g,computer:c,message:me,recordId:isNaN(r)?0:r,processId:parseInt(h==null?void 0:h.getAttribute("ProcessID"),10)||0,threadId:parseInt(h==null?void 0:h.getAttribute("ThreadID"),10)||0,activityId:(m==null?void 0:m.getAttribute("ActivityID"))||"",relatedActivityId:(m==null?void 0:m.getAttribute("RelatedActivityID"))||"",userSID:(f==null?void 0:f.getAttribute("UserID"))||"",task:b(t,"Task"),opcode:b(t,"Opcode"),keywords:b(t,"Keywords"),taskName:le,opcodeName:de,keywordNames:pe,providerDescription:ue,version:b(t,"Version"),qualifiers:((V=t==null?void 0:t.querySelector("EventID"))==null?void 0:V.getAttribute("Qualifiers"))||"",data:ve,dataAnon:he}}function b(e,t){var s,a;return((a=(s=e==null?void 0:e.querySelector(t))==null?void 0:s.textContent)==null?void 0:a.trim())||""}function be(e,t){var o,i;const s=(i=(o=t==null?void 0:t.querySelector("Message"))==null?void 0:o.textContent)==null?void 0:i.trim();if(s)return s;const a=e.querySelector("EventData");if(a){const c=[];for(const r of a.querySelectorAll("Data")){const l=r.getAttribute("Name"),u=r.textContent.trim();u&&u!=="-"&&c.push(l?`${l}: ${u}`:u)}if(c.length)return c.join(" | ")}const n=e.querySelector("UserData");return n?n.textContent.trim():""}function Ee(e){const t={},s=[],a=e.querySelector("EventData");if(!a)return{named:t,anon:s};for(const n of a.querySelectorAll("Data")){const o=n.getAttribute("Name"),i=n.textContent.trim();o?i&&(t[o]=i):i&&s.push(i)}return{named:t,anon:s}}function Ce(e,t){if(t){const s=t.toLowerCase();if(s.includes("critical"))return"Critical";if(s.includes("error"))return"Error";if(s.includes("warning"))return"Warning";if(s.includes("information"))return"Info";if(s.includes("verbose"))return"Verbose";if(s.includes("audit"))return t.includes("Failure")?"Error":"Info"}switch(e){case 1:return"Critical";case 2:return"Error";case 3:return"Warning";case 4:return"Info";case 5:return"Verbose";case 0:return"Info";default:return"Info"}}const ke=new Set([41,6008,1001,1e3,7024]),G={7:40,11:30,51:40,52:30,55:35,57:25,129:20,153:20,4101:50,1001:45,1e3:35,1002:30,1026:20,7031:25,7034:25,7022:20,7023:20,7001:15,7011:15,1014:20,4202:20,4201:15,17:50,18:40,19:30,4625:10,4740:15},Ie=new Set(["Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting"]),De=[{id:"gpu-driver-crash",name:"GPU Driver Crash",icon:"🖥",category:"Hardware Driver",test(e){const t=["nvlddmkm","amdkmdag","amd","igdkmd","dxgkrnl","atikmdag"],s=e.some(n=>n.id===4101),a=e.some(n=>t.some(o=>{var i;return(i=n.provider)==null?void 0:i.toLowerCase().includes(o)}));return s?{match:!0,confidence:"high"}:a?{match:!0,confidence:"medium"}:{match:!1}},what:"The graphics card driver stopped responding and Windows could not recover it.",rootCause:"Display driver (TDR timeout) caused the system to become unresponsive.",nextSteps:["Update or roll back GPU drivers via Device Manager → Display Adapters","Use DDU (Display Driver Uninstaller) in Safe Mode for clean reinstall","Monitor GPU temperatures under load with GPU-Z or HWiNFO64","Run GPU stability test with FurMark or 3DMark","Check GPU power connector seating if system is recently assembled"],technicianHint:'NVIDIA: look for "nvlddmkm" in Event 4101 faulting module. AMD: "atikmpag" or "amdkmdag". DDU clean reinstall resolves driver corruption in ~70% of cases. If temps are fine and fresh driver fails, suspect hardware.'},{id:"disk-failure",name:"Storage / Disk Error",icon:"💾",category:"Storage",test(e){const t=[7,11,51,52,55,57,129,153],s=["disk","atapi","nvme","storport","ntfs","fastfat","stornvme"],a=e.filter(n=>t.includes(n.id)||s.some(o=>{var i;return(i=n.provider)==null?void 0:i.toLowerCase().includes(o)}));return a.length>=3?{match:!0,confidence:"high"}:a.length>=1?{match:!0,confidence:"medium"}:{match:!1}},what:"The storage device reported I/O errors before the incident.",rootCause:"Disk hardware errors were detected — possible drive failure, bad sectors, or controller issue.",nextSteps:["Run CrystalDiskInfo — check SMART reallocated/pending/uncorrectable sectors","Run chkdsk /f /r /x on affected volume","Run manufacturer disk diagnostic (SeaTools, WD Dashboard, Samsung Magician)","Check SATA/power cable connections","Consider imaging and replacing drive if SMART shows degradation"],technicianHint:"Event 7 = hardware error from disk.sys. Event 51 = error during paging (system swapping to bad sectors — urgent). Event 55 = NTFS filesystem corruption. Multiple Event 7 in a short window usually means imminent failure."},{id:"bsod-kernel-crash",name:"Blue Screen of Death (BSOD)",icon:"🔵",category:"Kernel Crash",test(e,t){return t.id===1001?{match:!0,confidence:"high"}:e.some(s=>s.id===1001)?{match:!0,confidence:"high"}:{match:!1}},what:"Windows detected an unrecoverable kernel error and created a memory dump.",rootCause:"A kernel or driver-level fault caused Windows to stop to prevent data corruption.",nextSteps:["Note the BugCheck code from Event 1001 details","Analyse minidump with WhoCrashed (free) or WinDbg (!analyze -v)","Run SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth","Run Windows Memory Diagnostic for MEMORY_MANAGEMENT (0x1A) stops","Update all drivers — especially GPU, NIC, and chipset"],technicianHint:"Common stop codes: 0x50 PAGE_FAULT (bad RAM or driver), 0x3B SYSTEM_SERVICE_EXCEPTION (driver), 0x1A MEMORY_MANAGEMENT (RAM), 0x7E SYSTEM_THREAD_EXCEPTION (driver), 0x0A IRQL_NOT_LESS_OR_EQUAL (driver/RAM). WhoCrashed gives the culprit driver in seconds."},{id:"service-crash-chain",name:"Service Crash Loop",icon:"⚙",category:"Windows Services",test(e){const t=[7031,7034,7022,7023,7024,7001,7011],s=e.filter(a=>t.includes(a.id));return s.length>=5?{match:!0,confidence:"high"}:s.length>=2?{match:!0,confidence:"medium"}:{match:!1}},what:"One or more Windows services crashed or failed to start repeatedly.",rootCause:"Service instability — possibly caused by a failed update, corrupted binary, or missing dependency.",nextSteps:["Identify which service(s) crashed from the event messages","Check service recovery settings: Services → right-click service → Properties → Recovery","Verify the service executable exists and is not corrupted","Check for related Application log events (Event 1000) for the service host","Review recent Windows Updates that may have changed the service"],technicianHint:"Event 7031 = service terminated unexpectedly (count tells you how many times). Event 7034 = crashed without telling SCM. The service name is in the event message. If it's svchost-hosted, check the service group."},{id:"application-crash-loop",name:"Application Crash Loop",icon:"💥",category:"Application",test(e){const t=e.filter(s=>s.id===1e3);return t.length>=3?{match:!0,confidence:"high"}:t.length>=1?{match:!0,confidence:"medium"}:{match:!1}},what:"An application was crashing repeatedly before the incident.",rootCause:"Application instability — possible corrupt installation, missing runtime, or incompatible update.",nextSteps:["Identify the crashing application from the Event 1000 message","Note the faulting module — it often identifies a specific DLL","Update or reinstall the application","Install/repair Visual C++ Redistributables if a runtime DLL faults","Check crash dumps in %LocalAppData%\\CrashDumps or the application's folder"],technicianHint:'The faulting module in Event 1000 is gold — "ntdll.dll" = OS issue or heap corruption, "msvcp140.dll" / "vcruntime140.dll" = missing C++ runtime, "AppName.exe" itself = bad binary. Repeated same app + same module = deterministic, reproducible fault.'},{id:"memory-hardware",name:"Memory / RAM Issue",icon:"🧠",category:"Hardware",test(e){const t=["microsoft-windows-memoryd","whea-logger","microsoft-windows-whea"],s=[17,18,19,1],a=e.some(o=>s.includes(o.id)||t.some(i=>{var c;return(c=o.provider)==null?void 0:c.toLowerCase().includes(i)})),n=e.some(o=>{var i,c;return o.id===1001&&(((i=o.data)==null?void 0:i.BugcheckCode)==="26"||((c=o.data)==null?void 0:c.BugcheckCode)==="80")});return a||n?{match:!0,confidence:"medium"}:{match:!1}},what:"Hardware memory errors or RAM-related faults were detected.",rootCause:"Defective or misconfigured RAM caused uncorrectable memory errors.",nextSteps:["Run MemTest86+ overnight (at least 2 passes)","Test RAM sticks one at a time to isolate the faulty module","Reseat RAM modules and clean contacts","Check XMP/EXPO profile stability — reset to JEDEC spec in BIOS","Check WHEA-Logger events for corrected/uncorrected error counts"],technicianHint:`WHEA Event 17/18/19 = hardware error framework caught a hardware error. Check the ErrorSource field — "MCE" (Machine Check Exception) = hardware fault, usually RAM or CPU. MemTest86+ is the definitive test. Don't trust Windows Memory Diagnostic for subtle faults.`},{id:"unexpected-power",name:"Unexpected Power Loss",icon:"⚡",category:"Power",test(e,t){var s;return t.id===41&&((s=t.data)==null?void 0:s.BugcheckCode)==="0"?{match:!0,confidence:"high"}:(t.id===41||t.id===6008)&&e.length<=3?{match:!0,confidence:"medium"}:{match:!1}},what:"The system lost power without going through a normal shutdown.",rootCause:"Hard power loss — possible PSU failure, power outage, or UPS failure.",nextSteps:["Check UPS health, battery test, and log — replace battery if > 3 years old","Test PSU voltage rails with PC Power Supply Tester or multimeter","Check power outlet and surge protector for faults","Review Event 41 BugcheckCode: 0 = power loss, non-0 = software crash","Install UPS with AVR if not present — protects against brownouts"],technicianHint:"Event 41 BugcheckCode=0 is definitive: the machine lost power while running (no BSOD, no clean shutdown). Very few preceding events confirms sudden loss. Multiple occurrences = PSU is failing. Check 12V rail — HDD-heavy systems are sensitive."},{id:"network-failure",name:"Network / Connectivity Failure",icon:"🌐",category:"Network",test(e){const t=[1014,4202,4201,6100],s=["tcpip","dns-client","dhcp","netbt","netlogon","rras"],a=e.filter(n=>t.includes(n.id)||s.some(o=>{var i;return(i=n.provider)==null?void 0:i.toLowerCase().includes(o)}));return a.length>=3?{match:!0,confidence:"medium"}:a.length>=1?{match:!0,confidence:"low"}:{match:!1}},what:"Network or DNS errors were recorded in the period leading up to the incident.",rootCause:"Network connectivity failure caused application or service faults.",nextSteps:["Check NIC driver version — update if outdated",'Disable NIC power management: Device Manager → NIC → Power Management → uncheck "Allow computer to turn off"',"Test DNS resolution: nslookup google.com","Review DHCP lease renewal logs","Check switch port, cable, and NIC hardware"],technicianHint:"Event 1014 = DNS client resolver timeout. If you see it, look at the DNS server IP in the event — a failing DC or DNS server is a common cause. Event 4201/4202 = NIC connection state changes = intermittent cable or switch issue."}],Te=15,Ae={Critical:30,Error:20,Warning:10,Info:2,Verbose:0};function Me(e){var c;if(!e.length)return{incidents:[],healthScore:100,computerName:"",stats:Ue()};const t=((c=e[0])==null?void 0:c.computer)||"",s=te(e),a=xe(e),n=[];for(const r of a){const l=Le(e,r,Te),g=Ne(l,r).slice(0,8),h=Re(l,r),m=Pe(r,h,g);n.push({anchor:r,windowEvents:l,topContributors:g,signatureResult:h,report:m})}const o=Be(n),i=qe(e,o);return{incidents:o,healthScore:i,computerName:t,stats:s}}function xe(e){const t=[],s=new Set;for(const a of e){if(!ke.has(a.id))continue;const n=`${a.id}-${Math.floor(a.timestamp/3e4)}`;s.has(n)||(s.add(n),t.push(a))}return t.sort((a,n)=>n.timestamp-a.timestamp).slice(0,5)}function Le(e,t,s){const a=t.timestamp-s*6e4;return e.filter(n=>n.timestamp>=a&&n.timestamp<t.timestamp)}function Ne(e,t){const s=e.map(n=>{let o=Ae[n.severity]??0;G[n.id]&&(o+=G[n.id]),n.provider&&t.provider&&n.provider===t.provider&&(o+=8),Ie.has(n.provider)&&(o=Math.max(0,o-15));const i=(t.timestamp-n.timestamp)/6e4;return i<2?o+=10:i<5&&(o+=5),{event:n,score:o}}),a=new Map;for(const{event:n}of s){const o=`${n.id}-${n.provider}`;a.set(o,(a.get(o)||0)+1)}for(const n of s){const o=`${n.event.id}-${n.event.provider}`,i=a.get(o)||1;i>=5?n.score+=15:i>=3?n.score+=8:i>=2&&(n.score+=4)}return s.filter(({score:n})=>n>0).sort((n,o)=>o.score-n.score).map(({event:n,score:o})=>({event:n,score:o}))}function Re(e,t){const s=[];for(const n of De)try{const o=n.test(e,t);o.match&&s.push({signature:n,confidence:o.confidence})}catch{}const a={high:0,medium:1,low:2};return s.sort((n,o)=>(a[n.confidence]??3)-(a[o.confidence]??3)),s}function Pe(e,t,s,a){const n=t[0],o=n==null?void 0:n.signature,i=(n==null?void 0:n.confidence)??"low",c=ee[e.id]??`Event ${e.id}`,r=(o==null?void 0:o.what)??`${c} occurred at ${se(e.timestamp)}.`,l=(o==null?void 0:o.rootCause)??Oe(e,s),u=(o==null?void 0:o.nextSteps)??["Review event details for more information","Check System and Application logs for context"],g=o==null?void 0:o.technicianHint,h=We(e,o,s,i);return{what:r,rootCause:l,confidence:i,nextSteps:u,technicianHint:g,psaSummary:h,alternateSignatures:t.slice(1,3),evidenceCount:s.length}}const ee={41:"Unexpected system reboot (Kernel-Power)",6008:"Unexpected previous shutdown (EventLog)",1001:"System crash / BSOD (BugCheck)",1e3:"Application crash (Application Error)",7024:"Critical service failure"};function Oe(e,t){if(!t.length)return"No significant preceding events identified in the lookback window.";const s=t[0].event;return`Leading event: ${s.provider||"Unknown"} Event ${s.id} (${s.severity}) recorded shortly before the incident.`}function We(e,t,s,a){return["INCIDENT SUMMARY","================",`Date/Time: ${e.timestamp.toLocaleString()}`,`Anchor Event: ${e.id} — ${ee[e.id]??"Unknown"}`,`Provider: ${e.provider||"Unknown"}`,`Computer: ${e.computer||"Unknown"}`,"","DIAGNOSIS","---------",t?`Pattern: ${t.name} (${t.category})`:"Pattern: No known pattern matched",`Confidence: ${a.toUpperCase()}`,"",t?`What happened: ${t.what}`:"",t?`Root cause: ${t.rootCause}`:"","",`CONTRIBUTING EVENTS (top ${Math.min(s.length,5)})`,"------------------",...s.slice(0,5).map(({event:i})=>`  [${i.severity}] Event ${i.id} — ${i.provider||"Unknown"} @ ${se(i.timestamp)}`),"","SUGGESTED NEXT STEPS","--------------------",...((t==null?void 0:t.nextSteps)??["Review event log for more context"]).map(i=>`  • ${i}`),"","Generated by Eventful Incident Analyzer"].filter(i=>i!==void 0).join(`
`)}function te(e){const t={Critical:0,Error:0,Warning:0,Info:0,Verbose:0};for(const s of e)t[s.severity]=(t[s.severity]||0)+1;return{total:e.length,...t}}function Ue(){return{total:0,Critical:0,Error:0,Warning:0,Info:0,Verbose:0}}function qe(e,t){let s=100;const a=te(e);s-=Math.min(a.Critical*15,40),s-=Math.min(a.Error*3,25),s-=Math.min(a.Warning*.5,10),s-=t.length*12;for(const n of t)n.report.confidence==="high"?s-=8:n.report.confidence==="medium"&&(s-=4);return Math.max(0,Math.min(100,Math.round(s)))}function Be(e){const t=new Set;return e.filter(s=>{const a=`${s.anchor.id}-${Math.floor(s.anchor.timestamp/1e3)}`;return t.has(a)?!1:(t.add(a),!0)})}function se(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}ge();document.querySelectorAll(".theme-btn").forEach(e=>e.addEventListener("click",we));const L=document.getElementById("upload-section"),ne=document.getElementById("processing-section"),ie=document.getElementById("results-section"),w=document.getElementById("drop-zone"),T=document.getElementById("file-input"),K=document.getElementById("processing-text"),F=document.getElementById("overview-grid"),I=document.getElementById("incidents-section"),E=document.getElementById("event-table-wrap"),X=document.getElementById("event-log-filters-wrap"),N=document.getElementById("new-analysis-btn"),z=document.getElementById("results-sub");let k=[];T==null||T.addEventListener("change",e=>{var s;const t=(s=e.target.files)==null?void 0:s[0];t&&oe(t)});w==null||w.addEventListener("dragover",e=>{e.preventDefault(),w.classList.add("drag-over")});w==null||w.addEventListener("dragleave",()=>w.classList.remove("drag-over"));w==null||w.addEventListener("drop",e=>{var s;e.preventDefault(),w.classList.remove("drag-over");const t=(s=e.dataTransfer.files)==null?void 0:s[0];t&&oe(t)});N==null||N.addEventListener("click",He);var J;(J=document.getElementById("lp-backdrop"))==null||J.addEventListener("click",P);var Z;(Z=document.getElementById("lp-close"))==null||Z.addEventListener("click",P);document.addEventListener("keydown",e=>{e.key==="Escape"&&P()});async function oe(e){if(!e.name.toLowerCase().endsWith(".xml")&&e.type!=="text/xml"&&e.type!=="application/xml"){Q("Please upload an XML file exported from Windows Event Viewer.");return}x(`Reading ${e.name}…`);try{const t=await e.text();x("Parsing events…"),await R();const s=Se(t);x(`Analysing ${s.length.toLocaleString()} events…`),await R();const a=Me(s);k=s,x("Building report…"),await R(),_e(a,e.name)}catch(t){Q(t.message||"Failed to parse file."),A(L)}}function R(){return new Promise(e=>setTimeout(e,16))}function A(e){[L,ne,ie].forEach(t=>{t&&(t.hidden=!0)}),e&&(e.hidden=!1)}function x(e){K&&(K.textContent=e),A(ne)}function He(){k=[],T&&(T.value=""),A(L)}function _e(e,t){const{incidents:s,healthScore:a,computerName:n,stats:o}=e;if(z){const i=[];n&&i.push(n),i.push(`${o.total.toLocaleString()} events`),s.length&&i.push(`${s.length} incident${s.length!==1?"s":""} detected`),z.textContent=i.join(" · ")}je(a,o),Ve(s),ze(k),A(ie)}function je(e,t){if(!F)return;const s=e>=80?"#34d399":e>=60?"#f59e0b":"#f43f5e",a=e>=80?"Good":e>=60?"Degraded":"Critical";F.innerHTML=`
    <div class="overview-score-card">
      <div class="score-ring" style="--score-color: ${s}">
        <span class="score-num">${e}</span>
        <span class="score-denom">/100</span>
      </div>
      <div class="score-label">System Health</div>
      <div class="score-status" style="color: ${s}">${a}</div>
    </div>

    <div class="overview-stats">
      ${D("Critical",t.Critical,"stat-critical")}
      ${D("Error",t.Error,"stat-error")}
      ${D("Warning",t.Warning,"stat-warning")}
      ${D("Info",t.Info,"stat-info")}
      ${D("Total Events",t.total,"stat-total")}
    </div>
  `}function D(e,t,s){return`
    <div class="stat-card ${s}">
      <span class="stat-count">${t.toLocaleString()}</span>
      <span class="stat-label">${e}</span>
    </div>
  `}function Ve(e){if(I){if(!e.length){I.innerHTML=`
      <div class="no-incidents">
        <div class="no-incidents-icon">✓</div>
        <div class="no-incidents-title">No incidents detected</div>
        <div class="no-incidents-sub">No known crash or failure anchor events were found in this log.</div>
      </div>
    `;return}I.innerHTML=`
    <h2 class="section-heading">Detected Incidents</h2>
    ${e.map((t,s)=>Ge(t)).join("")}
  `,I.querySelectorAll(".copy-summary-btn").forEach(t=>{t.addEventListener("click",()=>{const s=t.dataset.summary;navigator.clipboard.writeText(s).then(()=>{t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy for ticket",t.classList.remove("copied")},2e3)})})}),I.querySelectorAll("[data-lookup-id]").forEach(t=>{t.addEventListener("click",()=>re(t.dataset.lookupId))})}}function Ge(e,t){var g,h;const{anchor:s,windowEvents:a,topContributors:n,signatureResult:o,report:i}=e,c=(g=o[0])==null?void 0:g.signature,r=i.confidence,l=et(s.severity),u=r==="high"?"conf-high":r==="medium"?"conf-medium":"conf-low";return`
    <div class="incident-card">
      <div class="incident-header ${l}">
        <div class="incident-header-left">
          <span class="incident-icon">${(c==null?void 0:c.icon)??"⚠"}</span>
          <div>
            <div class="incident-title">${(c==null?void 0:c.name)??tt(s)}</div>
            <div class="incident-meta">
              <span class="incident-time">${s.timestamp.toLocaleString()}</span>
              <span class="incident-provider">${p(s.provider)}</span>
            </div>
          </div>
        </div>
        <div class="incident-header-right">
          <span class="conf-badge ${u}">${r} confidence</span>
          <span class="event-id-pill" data-lookup-id="${s.id}" title="Look up Event ${s.id}">
            Event ${s.id}
          </span>
        </div>
      </div>

      <div class="incident-body">
        <!-- What happened -->
        <div class="incident-section">
          <div class="incident-section-label">What happened</div>
          <p class="incident-text">${p(i.what)}</p>
        </div>

        <!-- Root cause -->
        <div class="incident-section">
          <div class="incident-section-label">Likely root cause</div>
          <p class="incident-text">${p(i.rootCause)}</p>
        </div>

        <!-- Evidence events -->
        ${n.length?`
        <div class="incident-section">
          <div class="incident-section-label">Contributing events (${n.length} found)</div>
          <div class="evidence-list">
            ${n.slice(0,6).map(({event:m,score:f})=>`
              <div class="evidence-item">
                <span class="ev-sev-dot sev-${m.severity.toLowerCase()}"></span>
                <span class="ev-id" data-lookup-id="${m.id}" title="Look up Event ${m.id}">
                  ${m.id}
                </span>
                <span class="ev-provider">${p(M(m.provider))}</span>
                <span class="ev-time">${ce(m.timestamp)}</span>
                <span class="ev-score" title="Relevance score">${f}</span>
              </div>
            `).join("")}
          </div>
        </div>
        `:""}

        <!-- Timeline -->
        ${a.length?Ke(a,s):""}

        <!-- Next steps -->
        ${i.nextSteps.length?`
        <div class="incident-section">
          <div class="incident-section-label">Suggested next steps</div>
          <ol class="next-steps-list">
            ${i.nextSteps.map(m=>`<li>${p(m)}</li>`).join("")}
          </ol>
        </div>
        `:""}

        <!-- Technician hint -->
        ${i.technicianHint?`
        <div class="incident-section">
          <div class="technician-hint">
            <span class="hint-label">Tech Hint</span>
            <span class="hint-text">${p(i.technicianHint)}</span>
          </div>
        </div>
        `:""}

        <!-- Copy for ticket -->
        <div class="incident-footer">
          <button class="copy-summary-btn" data-summary="${p(i.psaSummary)}">
            Copy for ticket
          </button>
          ${(h=i.alternateSignatures)!=null&&h.length?`
          <span class="alt-signatures">
            Also possible: ${i.alternateSignatures.map(m=>m.signature.name).join(", ")}
          </span>
          `:""}
        </div>
      </div>
    </div>
  `}function Ke(e,t){const s=[...e,t].sort((o,i)=>o.timestamp-i.timestamp),n=s.length>12?[...s.slice(0,6),{_ellipsis:!0,count:s.length-10},...s.slice(-4)]:s;return`
    <div class="incident-section">
      <div class="incident-section-label">Timeline (${e.length} events in ${Fe}-min window)</div>
      <div class="mini-timeline">
        ${n.map(o=>{var c;if(o._ellipsis)return`<div class="timeline-ellipsis">· · · ${o.count} more events · · ·</div>`;const i=o===t;return`
            <div class="timeline-item ${i?"timeline-anchor":""}">
              <div class="tl-dot sev-${(c=o.severity)==null?void 0:c.toLowerCase()}"></div>
              <div class="tl-content">
                <span class="tl-time">${ce(o.timestamp)}</span>
                <span class="tl-id" data-lookup-id="${o.id}">${o.id}</span>
                <span class="tl-provider">${p(M(o.provider))}</span>
                ${i?'<span class="tl-anchor-label">ANCHOR</span>':""}
              </div>
            </div>
          `}).join("")}
      </div>
    </div>
  `}const Fe=15,Xe=new Set(["Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting","Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-DistributedCOM","Microsoft-Windows-Security-SPP","Microsoft-Windows-Defrag","Microsoft-Windows-Power-Troubleshooter"]),Y={Critical:0,Error:1,Warning:2,Info:3,Verbose:4},d={sortCol:"timestamp",sortDir:"asc",page:0,pageSize:100,query:"",severity:"",provider:"",channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set};function ze(e){var c,r;if(!X||!E)return;Object.assign(d,{sortCol:"timestamp",sortDir:"asc",page:0,query:"",severity:"",provider:"",channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set});const t=[...new Set(e.map(l=>l.provider).filter(Boolean))].sort(),s=[...new Set(e.map(l=>l.channel).filter(Boolean))].sort(),a=l=>l?new Date(l-l.getTimezoneOffset()*6e4).toISOString().slice(0,16):"",n=(c=e[0])==null?void 0:c.timestamp,o=(r=e[e.length-1])==null?void 0:r.timestamp;X.innerHTML=`
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
        ${t.map(l=>`<option value="${p(l)}">${p(M(l))}</option>`).join("")}
      </select>

      <select id="tbl-channel" class="filter-control filter-control-select">
        <option value="">All channels</option>
        ${s.map(l=>`<option value="${p(l)}">${p(l)}</option>`).join("")}
      </select>

      <div class="filter-date-group">
        <span class="filter-date-label">From</span>
        <input type="datetime-local" id="tbl-from" class="filter-control filter-control-date"
          value="${a(n)}" />
      </div>
      <div class="filter-date-group">
        <span class="filter-date-label">To</span>
        <input type="datetime-local" id="tbl-to" class="filter-control filter-control-date"
          value="${a(o)}" />
      </div>

      <div class="filter-spacer"></div>
      <button id="tbl-noise" class="filter-noise-btn">Hide noise</button>
      <button id="tbl-csv"   class="filter-csv-btn">↓ CSV</button>
    </div>
  `;const i=(l,u,g)=>{var h;return(h=document.getElementById(l))==null?void 0:h.addEventListener(u,g)};i("tbl-query","input",l=>{d.query=l.target.value,d.page=0,S()}),i("tbl-severity","change",l=>{d.severity=l.target.value,d.page=0,S()}),i("tbl-provider","change",l=>{d.provider=l.target.value,d.page=0,S()}),i("tbl-channel","change",l=>{d.channel=l.target.value,d.page=0,S()}),i("tbl-from","change",l=>{d.fromTime=l.target.value,d.page=0,S()}),i("tbl-to","change",l=>{d.toTime=l.target.value,d.page=0,S()}),i("tbl-noise","click",l=>{d.hideNoisy=!d.hideNoisy,d.page=0,l.target.classList.toggle("active",d.hideNoisy),l.target.textContent=d.hideNoisy?"Show noise":"Hide noise",S()}),i("tbl-csv","click",()=>Qe(ae())),S()}function ae(){const e=d.query.toLowerCase(),t=d.fromTime?new Date(d.fromTime).getTime():null,s=d.toTime?new Date(d.toTime).getTime():null;let a=k.filter(n=>!(d.severity&&n.severity!==d.severity||d.provider&&n.provider!==d.provider||d.channel&&n.channel!==d.channel||t!==null&&n.timestamp<t||s!==null&&n.timestamp>s||d.hideNoisy&&Xe.has(n.provider)||e&&!`${n.id} ${n.provider} ${n.channel} ${n.message} ${n.severity}`.toLowerCase().includes(e)));return a.sort((n,o)=>{let i=0;switch(d.sortCol){case"timestamp":i=n.timestamp-o.timestamp;break;case"severity":i=(Y[n.severity]??9)-(Y[o.severity]??9);break;case"id":i=n.id-o.id;break;case"provider":i=(n.provider||"").localeCompare(o.provider||"");break}return d.sortDir==="asc"?i:-i}),a}function S(){if(!E)return;const e=ae(),t=e.length,s=Math.max(0,Math.ceil(t/d.pageSize)-1);d.page=Math.min(d.page,s);const a=d.page*d.pageSize,n=e.slice(a,a+d.pageSize);if(!t){E.innerHTML='<div class="table-empty">No events match the current filters.</div>';return}const o=r=>`<span class="sort-arrow ${d.sortCol===r?"active":""}">${d.sortCol===r?d.sortDir==="asc"?"↑":"↓":"↕"}</span>`,i=r=>d.sortCol===r?"sort-active":"";E.innerHTML=`
    <div class="table-info-bar">
      <span class="table-count-text">
        ${(a+1).toLocaleString()}–${Math.min(a+d.pageSize,t).toLocaleString()} of ${t.toLocaleString()} event${t!==1?"s":""}
        ${t<k.length?` (${k.length.toLocaleString()} total)`:""}
      </span>
      <div class="table-pagination">
        <button class="page-btn" id="pg-first" ${d.page===0?"disabled":""}>«</button>
        <button class="page-btn" id="pg-prev"  ${d.page===0?"disabled":""}>‹ Prev</button>
        <span class="page-info">Page ${d.page+1} / ${s+1}</span>
        <button class="page-btn" id="pg-next"  ${d.page>=s?"disabled":""}>Next ›</button>
        <button class="page-btn" id="pg-last"  ${d.page>=s?"disabled":""}>»</button>
      </div>
    </div>
    <table class="event-table">
      <thead><tr>
        <th style="width:18px"></th>
        <th data-sort="timestamp" class="${i("timestamp")}">Time ${o("timestamp")}</th>
        <th data-sort="severity"  class="${i("severity")}">Sev ${o("severity")}</th>
        <th data-sort="id"        class="${i("id")}">ID ${o("id")}</th>
        <th data-sort="provider"  class="${i("provider")}">Provider ${o("provider")}</th>
        <th>Channel</th>
        <th>Message</th>
      </tr></thead>
      <tbody>${n.map(r=>Ye(r)).join("")}</tbody>
    </table>
  `,E.querySelectorAll("th[data-sort]").forEach(r=>{r.addEventListener("click",()=>{const l=r.dataset.sort;d.sortDir=d.sortCol===l&&d.sortDir==="asc"?"desc":"asc",d.sortCol=l,d.page=0,S()})});const c=(r,l)=>{var u;return(u=document.getElementById(r))==null?void 0:u.addEventListener("click",l)};c("pg-first",()=>{d.page=0,S()}),c("pg-prev",()=>{d.page--,S()}),c("pg-next",()=>{d.page++,S()}),c("pg-last",()=>{d.page=s,S()}),E.querySelectorAll("tbody tr[data-record]").forEach(r=>{r.addEventListener("click",l=>{if(l.target.closest(".table-event-id"))return;const u=parseInt(r.dataset.record,10);d.expandedIds.has(u)?d.expandedIds.delete(u):d.expandedIds.add(u),S()})}),E.querySelectorAll(".table-event-id").forEach(r=>{r.addEventListener("click",l=>{l.stopPropagation(),re(r.dataset.lookupId)})}),E.querySelectorAll(".ev-advanced-toggle").forEach(r=>{r.addEventListener("click",l=>{l.stopPropagation();const g=r.closest(".ev-detail-inner").querySelector(".ev-advanced-section").classList.toggle("ev-advanced-open");r.textContent=g?"Advanced ▲":"Advanced ▼"})})}function Ye(e){var m;const t=d.expandedIds.has(e.recordId),s=e.severity.toLowerCase(),a=Object.keys(e.data||{}),n=e.message?p(e.message.substring(0,150))+(e.message.length>150?"…":""):'<span style="color:var(--text3);font-style:italic">no message</span>',o=`
    <tr class="ev-row-${s}${t?" row-expanded":""}" data-record="${e.recordId}">
      <td class="ev-col-expand">${t?"▼":"▶"}</td>
      <td class="ev-col-time">${Ze(e.timestamp)}</td>
      <td><span class="sev-badge sev-badge-${s}">${e.severity}</span></td>
      <td><span class="table-event-id" data-lookup-id="${e.id}" title="Look up Event ${e.id}">${e.id}</span></td>
      <td class="ev-col-provider" title="${p(e.provider)}">${p(M(e.provider))}</td>
      <td class="ev-col-channel">${p(e.channel)}</td>
      <td class="ev-col-message">${n}</td>
    </tr>`;if(!t)return o;const i=e.taskName||e.task||null,c=e.opcodeName||e.opcode||null,r=(m=e.keywordNames)!=null&&m.length?e.keywordNames.join(", "):e.keywords||null,l=[["Time (local)",e.timestamp.toLocaleString()],["Time (UTC)",e.timestamp.toISOString()],["Provider",e.provider],["Channel",e.channel],["Computer",e.computer],["Record ID",e.recordId||null],["User SID",e.userSID],["Process ID",e.processId||null],["Thread ID",e.threadId||null],["Activity ID",e.activityId],["Related Act. ID",e.relatedActivityId],["Task",i],["Opcode",c],["Keywords",r]].filter(([,f])=>f),u=[["Raw Level",String(e.levelNum)],["Raw Task",e.task],["Raw Opcode",e.opcode],["Raw Keywords",e.keywords],["Version",e.version],["Qualifiers",e.qualifiers],["Provider Desc.",e.providerDescription]].filter(([,f])=>f),g=e.message?`<div class="ev-detail-message">${p(e.message)}</div>`:`<div class="ev-detail-message ev-no-message">
        Message not rendered — Windows message templates are stored on the source machine.
        Export directly from the affected computer to see full event messages.
       </div>`,h=e.dataAnon||[];return o+`
    <tr class="ev-detail-row">
      <td colspan="7">
        <div class="ev-detail-inner">
          ${g}
          <div class="ev-detail-meta">
            ${l.map(([f,v])=>`
              <div class="ev-detail-field">
                <span class="ev-detail-key">${f}</span>
                <span class="ev-detail-val">${p(String(v))}</span>
              </div>`).join("")}
          </div>
          ${a.length||h.length?`
          <div class="ev-detail-data">
            <div class="ev-detail-data-title">Event Data</div>
            ${a.map(f=>`
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key">${p(f)}</span>
                <span class="ev-detail-data-val">${p(String(e.data[f]))}</span>
              </div>`).join("")}
            ${h.map((f,v)=>`
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key ev-detail-data-key--anon">[${v}]</span>
                <span class="ev-detail-data-val">${p(String(f))}</span>
              </div>`).join("")}
          </div>`:""}
          <div class="ev-detail-actions">
            <span class="ev-detail-lookup-btn table-event-id" data-lookup-id="${e.id}">
              Look up Event ${e.id} →
            </span>
            ${u.length?'<button class="ev-advanced-toggle">Advanced ▼</button>':""}
          </div>
          ${u.length?`
          <div class="ev-advanced-section">
            <div class="ev-detail-data-title">Advanced / Raw</div>
            ${u.map(([f,v])=>`
              <div class="ev-detail-field">
                <span class="ev-detail-key">${f}</span>
                <span class="ev-detail-val">${p(String(v))}</span>
              </div>`).join("")}
          </div>`:""}
        </div>
      </td>
    </tr>`}function Qe(e){const t=["Time (UTC)","Severity","EventID","Provider","Channel","Computer","RecordID","ProcessID","ThreadID","UserSID","ActivityID","RelatedActivityID","Task","TaskName","Opcode","OpcodeName","Keywords","KeywordNames","Version","Qualifiers","ProviderDescription","Message","EventData","EventDataAnon"],s=c=>`"${String(c??"").replace(/"/g,'""').replace(/\r?\n/g," ")}"`,a=e.map(c=>[c.timestamp.toISOString(),c.severity,c.id,s(c.provider),s(c.channel),s(c.computer),c.recordId,c.processId||"",c.threadId||"",s(c.userSID),s(c.activityId),s(c.relatedActivityId),s(c.task),s(c.taskName),s(c.opcode),s(c.opcodeName),s(c.keywords),s((c.keywordNames||[]).join("; ")),s(c.version),s(c.qualifiers),s(c.providerDescription),s(c.message),s(Object.entries(c.data||{}).map(([r,l])=>`${r}=${l}`).join("; ")),s((c.dataAnon||[]).join("; "))].join(",")),n=[t.join(","),...a].join(`\r
`),o=URL.createObjectURL(new Blob([n],{type:"text/csv;charset=utf-8;"})),i=Object.assign(document.createElement("a"),{href:o,download:`eventful-${new Date().toISOString().slice(0,10)}.csv`});document.body.appendChild(i),i.click(),document.body.removeChild(i),URL.revokeObjectURL(o)}function re(e){const t=parseInt(e,10),s=document.getElementById("lookup-panel"),a=document.getElementById("lp-body");if(!s||!a)return;const n=ye.find(i=>i.id===t),o=k.filter(i=>i.id===t);a.innerHTML=Je(t,n,o),s.hidden=!1,a.querySelectorAll(".lp-copy-ps").forEach(i=>{i.addEventListener("click",()=>{navigator.clipboard.writeText(i.dataset.code).then(()=>{i.textContent="Copied!",setTimeout(()=>{i.textContent="Copy"},2e3)})})}),a.querySelectorAll(".lp-advanced-toggle").forEach(i=>{i.addEventListener("click",()=>{const r=i.nextElementSibling.classList.toggle("lp-advanced-open");i.textContent=r?"Advanced ▲":"Advanced ▼"})})}function P(){const e=document.getElementById("lookup-panel");e&&(e.hidden=!0)}function Je(e,t,s){var o,i,c;let a="";if(t){const r=((o=t.severity)==null?void 0:o.toLowerCase())??"info";a+=`
      <div class="lp-section">
        <div class="lp-section-label">Knowledge Base</div>
        <div class="lp-doc-header">
          <span class="lp-id-badge">${e}</span>
          <div>
            <div class="lp-doc-title">${p(t.title)}</div>
            <div class="lp-doc-meta">
              <span class="sev-badge sev-badge-${r}">${p(t.severity)}</span>
              <span class="lp-channel">${p(t.channel||t.source||"")}</span>
            </div>
          </div>
        </div>
        <p class="lp-description">${p(t.description||t.short_desc||"")}</p>
        ${(i=t.causes)!=null&&i.length?`
          <div class="lp-subsection-label">Causes</div>
          <ul class="lp-causes">
            ${t.causes.map(l=>`<li>${p(l)}</li>`).join("")}
          </ul>`:""}
        ${(c=t.steps)!=null&&c.length?`
          <div class="lp-subsection-label">Investigation Steps</div>
          <ol class="lp-steps">
            ${t.steps.map(l=>`<li>${p(l)}</li>`).join("")}
          </ol>`:""}
        ${t.powershell?`
          <div class="lp-subsection-label">PowerShell</div>
          <div class="lp-ps-block">
            <pre>${p(t.powershell)}</pre>
            <button class="lp-copy-ps" data-code="${p(t.powershell)}">Copy</button>
          </div>`:""}
        <div class="lp-doc-footer">
          <a href="results.html?q=${e}" target="_blank" rel="noopener" class="lp-full-docs-btn">
            Open full docs →
          </a>
        </div>
      </div>`}else a+=`
      <div class="lp-section">
        <div class="lp-section-label">Knowledge Base</div>
        <div class="lp-no-doc-state">
          <div class="lp-no-doc-icon">📭</div>
          <div class="lp-no-doc-title">No documentation for Event ${e}</div>
          <div class="lp-no-doc-sub">This event ID is not in the Eventful knowledge base. Raw event data from your log is shown below.</div>
        </div>
      </div>`;if(s.length===0)return a+=`
      <div class="lp-section">
        <div class="lp-section-label">From your log</div>
        <div class="lp-no-raw">No events with this ID in the uploaded log.</div>
      </div>`,a;const n=s.slice(0,3);return a+=`
    <div class="lp-section">
      <div class="lp-section-label">
        From your log
        ${s.length>1?`<span class="lp-raw-count">${s.length} occurrences</span>`:""}
      </div>
      ${n.map((r,l)=>{var v;const u=r.taskName||r.opcode||null,g=r.opcodeName||r.opcode||null,h=(v=r.keywordNames)!=null&&v.length?r.keywordNames.join(", "):r.keywords||null,m=r.dataAnon||[],f=[["Raw Level",String(r.levelNum)],["Raw Task",r.task],["Raw Opcode",r.opcode],["Raw Keywords",r.keywords],["Version",r.version],["Qualifiers",r.qualifiers],["Provider Desc.",r.providerDescription],["Related Act. ID",r.relatedActivityId]].filter(([,$])=>$);return`
        ${l>0?'<div class="lp-raw-divider"></div>':""}
        <div class="lp-raw-fields">
          ${y("Time",r.timestamp.toLocaleString())}
          ${y("Severity",`<span class="sev-badge sev-badge-${r.severity.toLowerCase()}">${r.severity}</span>`)}
          ${y("Provider",p(M(r.provider)))}
          ${y("Channel",p(r.channel))}
          ${y("Computer",p(r.computer||"—"))}
          ${y("Record ID",String(r.recordId||"—"))}
          ${r.processId?y("Process ID",String(r.processId)):""}
          ${r.threadId?y("Thread ID",String(r.threadId)):""}
          ${r.userSID?y("User SID",p(r.userSID)):""}
          ${r.activityId?y("Activity ID",p(r.activityId)):""}
          ${u?y("Task",p(u)):""}
          ${g?y("Opcode",p(g)):""}
          ${h?y("Keywords",p(h)):""}
        </div>
        ${r.message?`<div class="lp-raw-message-label">Message</div>
             <div class="lp-raw-message">${p(r.message)}</div>`:`<div class="lp-raw-message-label">Message</div>
             <div class="lp-raw-message lp-no-message">Message not rendered — Windows message templates are stored on the source machine. Export directly from the affected computer to see full event messages.</div>`}
        ${Object.keys(r.data||{}).length||m.length?`
          <div class="lp-raw-message-label">Event Data</div>
          <div class="lp-raw-data">
            ${Object.entries(r.data).map(([$,C])=>`
              <div class="lp-raw-data-row">
                <span class="lp-raw-data-key">${p($)}</span>
                <span class="lp-raw-data-val">${p(String(C))}</span>
              </div>`).join("")}
            ${m.map(($,C)=>`
              <div class="lp-raw-data-row">
                <span class="lp-raw-data-key lp-raw-data-key--anon">[${C}]</span>
                <span class="lp-raw-data-val">${p(String($))}</span>
              </div>`).join("")}
          </div>`:""}
        ${f.length?`
          <button class="lp-advanced-toggle">Advanced ▼</button>
          <div class="lp-advanced-section">
            <div class="lp-raw-message-label">Advanced / Raw</div>
            <div class="lp-raw-fields">
              ${f.map(([$,C])=>y($,p(C))).join("")}
            </div>
          </div>`:""}
        `}).join("")}
      ${s.length>3?`<div class="lp-raw-more">+ ${s.length-3} more occurrence${s.length-3!==1?"s":""} in log</div>`:""}
    </div>`,a}function y(e,t){return`
    <div class="lp-raw-field">
      <span class="lp-raw-key">${e}</span>
      <span class="lp-raw-val">${t}</span>
    </div>`}function Q(e){const t=w==null?void 0:w.querySelector(".upload-error");t&&t.remove();const s=document.createElement("div");s.className="upload-error",s.textContent=e,w==null||w.appendChild(s),A(L)}function p(e){return e?String(e).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"):""}function M(e){return e?e.replace(/^Microsoft-Windows-/i,"").replace(/^Microsoft-/i,""):"—"}function ce(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}function Ze(e){return e.toLocaleString([],{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})}function et(e){return`sev-header-${(e==null?void 0:e.toLowerCase())??"info"}`}function tt(e){return{41:"Unexpected System Reboot",6008:"Unexpected Shutdown Detected",1001:"System Crash (BSOD)",1e3:"Application Crash",7024:"Critical Service Failure"}[e.id]??`Event ${e.id}`}
