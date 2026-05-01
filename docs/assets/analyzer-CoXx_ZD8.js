import{i as ge,t as we}from"./theme-CCBoUXgy.js";import{a as ye}from"./index-BAM9NZ7H.js";function $e(e){const n=new DOMParser().parseFromString(e,"text/xml"),a=n.querySelector("parsererror");if(a)throw new Error(`Invalid XML: ${a.textContent.substring(0,120)}`);const s=n.querySelectorAll("Event");if(s.length===0)throw new Error("No <Event> elements found. Make sure you exported in XML format from Event Viewer.");const i=[];for(const o of s)try{const r=Se(o);!isNaN(r.id)&&r.id>0&&r.timestamp instanceof Date&&!isNaN(r.timestamp)&&i.push(r)}catch{}if(i.length===0)throw new Error("No valid events could be parsed. Check that the XML is a Windows Event Viewer export.");return i.sort((o,r)=>o.timestamp-r.timestamp)}function Se(e){var W,U,B,q,j,_,H,V,G;const t=e.querySelector("System"),n=parseInt(E(t,"EventID"),10),a=parseInt(E(t,"Level"),10),s=t==null?void 0:t.querySelector("Provider"),i=(s==null?void 0:s.getAttribute("Name"))||(s==null?void 0:s.getAttribute("EventSourceName"))||"",o=E(t,"Channel"),r=E(t,"Computer"),c=parseInt(E(t,"EventRecordID"),10),l=t==null?void 0:t.querySelector("TimeCreated"),u=(l==null?void 0:l.getAttribute("SystemTime"))||(l==null?void 0:l.textContent)||"",g=new Date(u),h=t==null?void 0:t.querySelector("Execution"),v=t==null?void 0:t.querySelector("Correlation"),f=t==null?void 0:t.querySelector("Security"),m=e.querySelector("RenderingInfo"),S=(U=(W=m==null?void 0:m.querySelector("Level"))==null?void 0:W.textContent)==null?void 0:U.trim(),C=Ce(a,S),le=((q=(B=m==null?void 0:m.querySelector("Task"))==null?void 0:B.textContent)==null?void 0:q.trim())||"",de=((_=(j=m==null?void 0:m.querySelector("Opcode"))==null?void 0:j.textContent)==null?void 0:_.trim())||"",pe=[...(m==null?void 0:m.querySelectorAll("Keywords > Keyword"))??[]].map(fe=>fe.textContent.trim()).filter(Boolean),ue=((V=(H=m==null?void 0:m.querySelector("Provider"))==null?void 0:H.textContent)==null?void 0:V.trim())||"",ve=Ee(e,m),{named:me,anon:he}=be(e);return{id:n,provider:i,channel:o,levelNum:a,severity:C,timestamp:g,computer:r,message:ve,recordId:isNaN(c)?0:c,processId:parseInt(h==null?void 0:h.getAttribute("ProcessID"),10)||0,threadId:parseInt(h==null?void 0:h.getAttribute("ThreadID"),10)||0,activityId:(v==null?void 0:v.getAttribute("ActivityID"))||"",relatedActivityId:(v==null?void 0:v.getAttribute("RelatedActivityID"))||"",userSID:(f==null?void 0:f.getAttribute("UserID"))||"",task:E(t,"Task"),opcode:E(t,"Opcode"),keywords:E(t,"Keywords"),taskName:le,opcodeName:de,keywordNames:pe,providerDescription:ue,version:E(t,"Version"),qualifiers:((G=t==null?void 0:t.querySelector("EventID"))==null?void 0:G.getAttribute("Qualifiers"))||"",data:me,dataAnon:he}}function E(e,t){var n,a;return((a=(n=e==null?void 0:e.querySelector(t))==null?void 0:n.textContent)==null?void 0:a.trim())||""}function Ee(e,t){var i,o;const n=(o=(i=t==null?void 0:t.querySelector("Message"))==null?void 0:i.textContent)==null?void 0:o.trim();if(n)return n;const a=e.querySelector("EventData");if(a){const r=[];for(const c of a.querySelectorAll("Data")){const l=c.getAttribute("Name"),u=c.textContent.trim();u&&u!=="-"&&r.push(l?`${l}: ${u}`:u)}if(r.length)return r.join(" | ")}const s=e.querySelector("UserData");return s?s.textContent.trim():""}function be(e){const t={},n=[],a=e.querySelector("EventData");if(!a)return{named:t,anon:n};for(const s of a.querySelectorAll("Data")){const i=s.getAttribute("Name"),o=s.textContent.trim();i?o&&(t[i]=o):o&&n.push(o)}return{named:t,anon:n}}function Ce(e,t){if(t){const n=t.toLowerCase();if(n.includes("critical"))return"Critical";if(n.includes("error"))return"Error";if(n.includes("warning"))return"Warning";if(n.includes("information"))return"Info";if(n.includes("verbose"))return"Verbose";if(n.includes("audit"))return t.includes("Failure")?"Error":"Info"}switch(e){case 1:return"Critical";case 2:return"Error";case 3:return"Warning";case 4:return"Info";case 5:return"Verbose";case 0:return"Info";default:return"Info"}}const ke=new Set([41,6008,1001,1e3,7024]),K={7:40,11:30,51:40,52:30,55:35,57:25,129:20,153:20,4101:50,1001:45,1e3:35,1002:30,1026:20,7031:25,7034:25,7022:20,7023:20,7001:15,7011:15,1014:20,4202:20,4201:15,17:50,18:40,19:30,4625:10,4740:15},Ie=new Set(["Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting"]),De=[{id:"gpu-driver-crash",name:"GPU Driver Crash",icon:"🖥",category:"Hardware Driver",test(e){const t=["nvlddmkm","amdkmdag","amd","igdkmd","dxgkrnl","atikmdag"],n=e.some(s=>s.id===4101),a=e.find(s=>t.some(i=>{var o;return(o=s.provider)==null?void 0:o.toLowerCase().includes(i)}));return n?{match:!0,confidence:"high",reason:"Event 4101 (display driver TDR timeout) found in window"}:a?{match:!0,confidence:"medium",reason:`GPU provider "${a.provider}" found in window — no Event 4101`}:{match:!1}},what:"The graphics card driver stopped responding and Windows could not recover it.",rootCause:"Display driver (TDR timeout) caused the system to become unresponsive.",nextSteps:["Update or roll back GPU drivers via Device Manager → Display Adapters","Use DDU (Display Driver Uninstaller) in Safe Mode for clean reinstall","Monitor GPU temperatures under load with GPU-Z or HWiNFO64","Run GPU stability test with FurMark or 3DMark","Check GPU power connector seating if system is recently assembled"],technicianHint:'NVIDIA: look for "nvlddmkm" in Event 4101 faulting module. AMD: "atikmpag" or "amdkmdag". DDU clean reinstall resolves driver corruption in ~70% of cases. If temps are fine and fresh driver fails, suspect hardware.'},{id:"disk-failure",name:"Storage / Disk Error",icon:"💾",category:"Storage",test(e){const t=[7,11,51,52,55,57,129,153],n=["disk","atapi","nvme","storport","ntfs","fastfat","stornvme"],a=e.filter(i=>t.includes(i.id)||n.some(o=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(o)})),s=[...new Set(a.map(i=>i.id))].join(", ");return a.length>=3?{match:!0,confidence:"high",reason:`${a.length} disk error events in window (IDs: ${s})`}:a.length>=1?{match:!0,confidence:"medium",reason:`${a.length} disk error event in window (ID: ${s})`}:{match:!1}},what:"The storage device reported I/O errors before the incident.",rootCause:"Disk hardware errors were detected — possible drive failure, bad sectors, or controller issue.",nextSteps:["Run CrystalDiskInfo — check SMART reallocated/pending/uncorrectable sectors","Run chkdsk /f /r /x on affected volume","Run manufacturer disk diagnostic (SeaTools, WD Dashboard, Samsung Magician)","Check SATA/power cable connections","Consider imaging and replacing drive if SMART shows degradation"],technicianHint:"Event 7 = hardware error from disk.sys. Event 51 = error during paging (system swapping to bad sectors — urgent). Event 55 = NTFS filesystem corruption. Multiple Event 7 in a short window usually means imminent failure."},{id:"bsod-kernel-crash",name:"Blue Screen of Death (BSOD)",icon:"🔵",category:"Kernel Crash",test(e,t){return t.id===1001?{match:!0,confidence:"high",reason:"Event 1001 (BugCheck) is the anchor — BSOD confirmed"}:e.some(n=>n.id===1001)?{match:!0,confidence:"high",reason:"Event 1001 (BugCheck/BSOD) found in window events"}:{match:!1}},what:"Windows detected an unrecoverable kernel error and created a memory dump.",rootCause:"A kernel or driver-level fault caused Windows to stop to prevent data corruption.",nextSteps:["Note the BugCheck code from Event 1001 details","Analyse minidump with WhoCrashed (free) or WinDbg (!analyze -v)","Run SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth","Run Windows Memory Diagnostic for MEMORY_MANAGEMENT (0x1A) stops","Update all drivers — especially GPU, NIC, and chipset"],technicianHint:"Common stop codes: 0x50 PAGE_FAULT (bad RAM or driver), 0x3B SYSTEM_SERVICE_EXCEPTION (driver), 0x1A MEMORY_MANAGEMENT (RAM), 0x7E SYSTEM_THREAD_EXCEPTION (driver), 0x0A IRQL_NOT_LESS_OR_EQUAL (driver/RAM). WhoCrashed gives the culprit driver in seconds."},{id:"service-crash-chain",name:"Service Crash Loop",icon:"⚙",category:"Windows Services",test(e){const t=[7031,7034,7022,7023,7024,7001,7011],n=e.filter(s=>t.includes(s.id)),a=[...new Set(n.map(s=>s.id))].join(", ");return n.length>=5?{match:!0,confidence:"high",reason:`${n.length} service failure events in window (IDs: ${a})`}:n.length>=2?{match:!0,confidence:"medium",reason:`${n.length} service failure events in window (IDs: ${a})`}:{match:!1}},what:"One or more Windows services crashed or failed to start repeatedly.",rootCause:"Service instability — possibly caused by a failed update, corrupted binary, or missing dependency.",nextSteps:["Identify which service(s) crashed from the event messages","Check service recovery settings: Services → right-click service → Properties → Recovery","Verify the service executable exists and is not corrupted","Check for related Application log events (Event 1000) for the service host","Review recent Windows Updates that may have changed the service"],technicianHint:"Event 7031 = service terminated unexpectedly (count tells you how many times). Event 7034 = crashed without telling SCM. The service name is in the event message. If it's svchost-hosted, check the service group."},{id:"application-crash-loop",name:"Application Crash Loop",icon:"💥",category:"Application",test(e){const t=e.filter(n=>n.id===1e3);return t.length>=3?{match:!0,confidence:"high",reason:`${t.length} Event 1000 (application crash) in window`}:t.length>=1?{match:!0,confidence:"medium",reason:"1 Event 1000 (application crash) in window"}:{match:!1}},what:"An application was crashing repeatedly before the incident.",rootCause:"Application instability — possible corrupt installation, missing runtime, or incompatible update.",nextSteps:["Identify the crashing application from the Event 1000 message","Note the faulting module — it often identifies a specific DLL","Update or reinstall the application","Install/repair Visual C++ Redistributables if a runtime DLL faults","Check crash dumps in %LocalAppData%\\CrashDumps or the application's folder"],technicianHint:'The faulting module in Event 1000 is gold — "ntdll.dll" = OS issue or heap corruption, "msvcp140.dll" / "vcruntime140.dll" = missing C++ runtime, "AppName.exe" itself = bad binary. Repeated same app + same module = deterministic, reproducible fault.'},{id:"memory-hardware",name:"Memory / RAM Issue",icon:"🧠",category:"Hardware",test(e){const t=["microsoft-windows-memoryd","whea-logger","microsoft-windows-whea"],n=[17,18,19,1],a=e.find(i=>n.includes(i.id)||t.some(o=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(o)}));return e.some(i=>{var o,r;return i.id===1001&&(((o=i.data)==null?void 0:o.BugcheckCode)==="26"||((r=i.data)==null?void 0:r.BugcheckCode)==="80")})?{match:!0,confidence:"medium",reason:"BSOD stop code indicates memory fault (0x1A MEMORY_MANAGEMENT or 0x50 PAGE_FAULT)"}:a?{match:!0,confidence:"medium",reason:`Memory/WHEA event detected (Event ${a.id} from ${a.provider||"unknown provider"})`}:{match:!1}},what:"Hardware memory errors or RAM-related faults were detected.",rootCause:"Defective or misconfigured RAM caused uncorrectable memory errors.",nextSteps:["Run MemTest86+ overnight (at least 2 passes)","Test RAM sticks one at a time to isolate the faulty module","Reseat RAM modules and clean contacts","Check XMP/EXPO profile stability — reset to JEDEC spec in BIOS","Check WHEA-Logger events for corrected/uncorrected error counts"],technicianHint:`WHEA Event 17/18/19 = hardware error framework caught a hardware error. Check the ErrorSource field — "MCE" (Machine Check Exception) = hardware fault, usually RAM or CPU. MemTest86+ is the definitive test. Don't trust Windows Memory Diagnostic for subtle faults.`},{id:"unexpected-power",name:"Unexpected Power Loss",icon:"⚡",category:"Power",test(e,t){var n;return t.id===41&&((n=t.data)==null?void 0:n.BugcheckCode)==="0"?{match:!0,confidence:"high",reason:"Event 41 BugcheckCode=0 — hard power loss confirmed (not a software crash)"}:(t.id===41||t.id===6008)&&e.length<=3?{match:!0,confidence:"medium",reason:`Only ${e.length} event(s) before anchor — abrupt stop, no software lead-up`}:{match:!1}},what:"The system lost power without going through a normal shutdown.",rootCause:"Hard power loss — possible PSU failure, power outage, or UPS failure.",nextSteps:["Check UPS health, battery test, and log — replace battery if > 3 years old","Test PSU voltage rails with PC Power Supply Tester or multimeter","Check power outlet and surge protector for faults","Review Event 41 BugcheckCode: 0 = power loss, non-0 = software crash","Install UPS with AVR if not present — protects against brownouts"],technicianHint:"Event 41 BugcheckCode=0 is definitive: the machine lost power while running (no BSOD, no clean shutdown). Very few preceding events confirms sudden loss. Multiple occurrences = PSU is failing. Check 12V rail — HDD-heavy systems are sensitive."},{id:"network-failure",name:"Network / Connectivity Failure",icon:"🌐",category:"Network",test(e){const t=[1014,4202,4201,6100],n=["tcpip","dns-client","dhcp","netbt","netlogon","rras"],a=e.filter(i=>t.includes(i.id)||n.some(o=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(o)})),s=[...new Set(a.map(i=>i.id))].join(", ");return a.length>=3?{match:!0,confidence:"medium",reason:`${a.length} network/DNS events in window (IDs: ${s})`}:a.length>=1?{match:!0,confidence:"low",reason:`1 network/DNS event in window (ID: ${s})`}:{match:!1}},what:"Network or DNS errors were recorded in the period leading up to the incident.",rootCause:"Network connectivity failure caused application or service faults.",nextSteps:["Check NIC driver version — update if outdated",'Disable NIC power management: Device Manager → NIC → Power Management → uncheck "Allow computer to turn off"',"Test DNS resolution: nslookup google.com","Review DHCP lease renewal logs","Check switch port, cable, and NIC hardware"],technicianHint:"Event 1014 = DNS client resolver timeout. If you see it, look at the DNS server IP in the event — a failing DC or DNS server is a common cause. Event 4201/4202 = NIC connection state changes = intermittent cable or switch issue."}],Te=15,Ae={Critical:30,Error:20,Warning:10,Info:2,Verbose:0};function Me(e){var r;if(!e.length)return{incidents:[],healthScore:100,computerName:"",stats:Ue()};const t=((r=e[0])==null?void 0:r.computer)||"",n=te(e),a=xe(e),s=[];for(const c of a){const l=Le(e,c,Te),g=Ne(l,c).slice(0,8),h=Re(l,c),v=Pe(c,h,g);s.push({anchor:c,windowEvents:l,topContributors:g,signatureResult:h,report:v})}const i=qe(s),o=Be(e,i);return{incidents:i,healthScore:o,computerName:t,stats:n}}function xe(e){const t=[],n=new Set;for(const a of e){if(!ke.has(a.id))continue;const s=`${a.id}-${Math.floor(a.timestamp/3e4)}`;n.has(s)||(n.add(s),t.push(a))}return t.sort((a,s)=>s.timestamp-a.timestamp).slice(0,5)}function Le(e,t,n){const a=t.timestamp-n*6e4;return e.filter(s=>s.timestamp>=a&&s.timestamp<t.timestamp)}function Ne(e,t){const n=e.map(s=>{let i=Ae[s.severity]??0;K[s.id]&&(i+=K[s.id]),s.provider&&t.provider&&s.provider===t.provider&&(i+=8),Ie.has(s.provider)&&(i=Math.max(0,i-15));const o=(t.timestamp-s.timestamp)/6e4;return o<2?i+=10:o<5&&(i+=5),{event:s,score:i}}),a=new Map;for(const{event:s}of n){const i=`${s.id}-${s.provider}`;a.set(i,(a.get(i)||0)+1)}for(const s of n){const i=`${s.event.id}-${s.event.provider}`,o=a.get(i)||1;o>=5?s.score+=15:o>=3?s.score+=8:o>=2&&(s.score+=4)}return n.filter(({score:s})=>s>0).sort((s,i)=>i.score-s.score).map(({event:s,score:i})=>({event:s,score:i}))}function Re(e,t){const n=[];for(const s of De)try{const i=s.test(e,t);i.match&&n.push({signature:s,confidence:i.confidence,reason:i.reason||""})}catch{}const a={high:0,medium:1,low:2};return n.sort((s,i)=>(a[s.confidence]??3)-(a[i.confidence]??3)),n}function Pe(e,t,n,a){const s=t[0],i=s==null?void 0:s.signature,o=(s==null?void 0:s.confidence)??"low",r=(s==null?void 0:s.reason)||"",c=ee[e.id]??`Event ${e.id}`,l=(i==null?void 0:i.what)??`${c} occurred at ${ne(e.timestamp)}.`,u=(i==null?void 0:i.rootCause)??Oe(e,n),g=(i==null?void 0:i.nextSteps)??["Review event details for more information","Check System and Application logs for context"],h=i==null?void 0:i.technicianHint,v=We(e,i,n,o,r);return{what:l,rootCause:u,confidence:o,confidenceReason:r,nextSteps:g,technicianHint:h,psaSummary:v,alternateSignatures:t.slice(1,3),evidenceCount:n.length}}const ee={41:"Unexpected system reboot (Kernel-Power)",6008:"Unexpected previous shutdown (EventLog)",1001:"System crash / BSOD (BugCheck)",1e3:"Application crash (Application Error)",7024:"Critical service failure"};function Oe(e,t){if(!t.length)return"No significant preceding events identified in the lookback window.";const n=t[0].event;return`Leading event: ${n.provider||"Unknown"} Event ${n.id} (${n.severity}) recorded shortly before the incident.`}function We(e,t,n,a,s){return["INCIDENT SUMMARY","================",`Date/Time: ${e.timestamp.toLocaleString()}`,`Anchor Event: ${e.id} — ${ee[e.id]??"Unknown"}`,`Provider: ${e.provider||"Unknown"}`,`Computer: ${e.computer||"Unknown"}`,"","DIAGNOSIS","---------",t?`Pattern: ${t.name} (${t.category})`:"Pattern: No known pattern matched",`Confidence: ${a.toUpperCase()}${s?` — ${s}`:""}`,"",t?`What happened: ${t.what}`:"",t?`Root cause: ${t.rootCause}`:"","",`CONTRIBUTING EVENTS (top ${Math.min(n.length,5)})`,"------------------",...n.slice(0,5).map(({event:r})=>`  [${r.severity}] Event ${r.id} — ${r.provider||"Unknown"} @ ${ne(r.timestamp)}`),"","SUGGESTED NEXT STEPS","--------------------",...((t==null?void 0:t.nextSteps)??["Review event log for more context"]).map(r=>`  • ${r}`),"","Generated by Eventful Incident Analyzer"].filter(r=>r!==void 0).join(`
`)}function te(e){const t={Critical:0,Error:0,Warning:0,Info:0,Verbose:0};for(const n of e)t[n.severity]=(t[n.severity]||0)+1;return{total:e.length,...t}}function Ue(){return{total:0,Critical:0,Error:0,Warning:0,Info:0,Verbose:0}}function Be(e,t){let n=100;const a=te(e);n-=Math.min(a.Critical*15,40),n-=Math.min(a.Error*3,25),n-=Math.min(a.Warning*.5,10),n-=t.length*12;for(const s of t)s.report.confidence==="high"?n-=8:s.report.confidence==="medium"&&(n-=4);return Math.max(0,Math.min(100,Math.round(n)))}function qe(e){const t=new Set;return e.filter(n=>{const a=`${n.anchor.id}-${Math.floor(n.anchor.timestamp/1e3)}`;return t.has(a)?!1:(t.add(a),!0)})}function ne(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}ge();document.querySelectorAll(".theme-btn").forEach(e=>e.addEventListener("click",we));const L=document.getElementById("upload-section"),se=document.getElementById("processing-section"),ie=document.getElementById("results-section"),w=document.getElementById("drop-zone"),T=document.getElementById("file-input"),F=document.getElementById("processing-text"),X=document.getElementById("overview-grid"),I=document.getElementById("incidents-section"),b=document.getElementById("event-table-wrap"),N=document.getElementById("event-log-filters-wrap"),R=document.getElementById("new-analysis-btn"),z=document.getElementById("results-sub");let k=[];T==null||T.addEventListener("change",e=>{var n;const t=(n=e.target.files)==null?void 0:n[0];t&&oe(t)});w==null||w.addEventListener("dragover",e=>{e.preventDefault(),w.classList.add("drag-over")});w==null||w.addEventListener("dragleave",()=>w.classList.remove("drag-over"));w==null||w.addEventListener("drop",e=>{var n;e.preventDefault(),w.classList.remove("drag-over");const t=(n=e.dataTransfer.files)==null?void 0:n[0];t&&oe(t)});R==null||R.addEventListener("click",je);var J;(J=document.getElementById("lp-backdrop"))==null||J.addEventListener("click",O);var Z;(Z=document.getElementById("lp-close"))==null||Z.addEventListener("click",O);document.addEventListener("keydown",e=>{e.key==="Escape"&&O()});async function oe(e){if(!e.name.toLowerCase().endsWith(".xml")&&e.type!=="text/xml"&&e.type!=="application/xml"){Q("Please upload an XML file exported from Windows Event Viewer.");return}x(`Reading ${e.name}…`);try{const t=await e.text();x("Parsing events…"),await P();const n=$e(t);x(`Analysing ${n.length.toLocaleString()} events…`),await P();const a=Me(n);k=n,x("Building report…"),await P(),_e(a,e.name)}catch(t){Q(t.message||"Failed to parse file."),A(L)}}function P(){return new Promise(e=>setTimeout(e,16))}function A(e){[L,se,ie].forEach(t=>{t&&(t.hidden=!0)}),e&&(e.hidden=!1)}function x(e){F&&(F.textContent=e),A(se)}function je(){k=[],T&&(T.value=""),A(L)}function _e(e,t){const{incidents:n,healthScore:a,computerName:s,stats:i}=e;if(z){const o=[];s&&o.push(s),o.push(`${i.total.toLocaleString()} events`),n.length&&o.push(`${n.length} incident${n.length!==1?"s":""} detected`),z.textContent=o.join(" · ")}He(a,i),Ve(n),ze(k),A(ie)}function He(e,t){if(!X)return;const n=e>=80?"#34d399":e>=60?"#f59e0b":"#f43f5e",a=e>=80?"Good":e>=60?"Degraded":"Critical";X.innerHTML=`
    <div class="overview-score-card">
      <div class="score-ring" style="--score-color: ${n}">
        <span class="score-num">${e}</span>
        <span class="score-denom">/100</span>
      </div>
      <div class="score-label">System Health</div>
      <div class="score-status" style="color: ${n}">${a}</div>
    </div>

    <div class="overview-stats">
      ${D("Critical",t.Critical,"stat-critical")}
      ${D("Error",t.Error,"stat-error")}
      ${D("Warning",t.Warning,"stat-warning")}
      ${D("Info",t.Info,"stat-info")}
      ${D("Total Events",t.total,"stat-total")}
    </div>
  `}function D(e,t,n){return`
    <div class="stat-card ${n}">
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
    ${e.map((t,n)=>Ge(t)).join("")}
  `,I.querySelectorAll(".copy-summary-btn").forEach(t=>{t.addEventListener("click",()=>{const n=t.dataset.summary;navigator.clipboard.writeText(n).then(()=>{t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy for ticket",t.classList.remove("copied")},2e3)})})}),I.querySelectorAll("[data-lookup-id]").forEach(t=>{t.addEventListener("click",()=>re(t.dataset.lookupId))})}}function Ge(e,t){var g,h;const{anchor:n,windowEvents:a,topContributors:s,signatureResult:i,report:o}=e,r=(g=i[0])==null?void 0:g.signature,c=o.confidence,l=et(n.severity),u=c==="high"?"conf-high":c==="medium"?"conf-medium":"conf-low";return`
    <div class="incident-card">
      <div class="incident-header ${l}">
        <div class="incident-header-left">
          <span class="incident-icon">${(r==null?void 0:r.icon)??"⚠"}</span>
          <div>
            <div class="incident-title">${(r==null?void 0:r.name)??tt(n)}</div>
            <div class="incident-meta">
              <span class="incident-time">${n.timestamp.toLocaleString()}</span>
              <span class="incident-provider">${p(n.provider)}</span>
            </div>
          </div>
        </div>
        <div class="incident-header-right">
          <div class="conf-block">
            <span class="conf-badge ${u}">${c} confidence</span>
            ${o.confidenceReason?`<span class="conf-reason">${p(o.confidenceReason)}</span>`:""}
          </div>
          <span class="event-id-pill" data-lookup-id="${n.id}" title="Look up Event ${n.id}">
            Event ${n.id}
          </span>
        </div>
      </div>

      <div class="incident-body">
        <!-- What happened -->
        <div class="incident-section">
          <div class="incident-section-label">What happened</div>
          <p class="incident-text">${p(o.what)}</p>
        </div>

        <!-- Root cause -->
        <div class="incident-section">
          <div class="incident-section-label">Likely root cause</div>
          <p class="incident-text">${p(o.rootCause)}</p>
        </div>

        <!-- Evidence events -->
        ${s.length?`
        <div class="incident-section">
          <div class="incident-section-label">Contributing events (${s.length} found)</div>
          <div class="evidence-list">
            ${s.slice(0,6).map(({event:v,score:f})=>`
              <div class="evidence-item">
                <span class="ev-sev-dot sev-${v.severity.toLowerCase()}"></span>
                <span class="ev-id" data-lookup-id="${v.id}" title="Look up Event ${v.id}">
                  ${v.id}
                </span>
                <span class="ev-provider">${p(M(v.provider))}</span>
                <span class="ev-time">${ce(v.timestamp)}</span>
                <span class="ev-score" title="Relevance score">${f}</span>
              </div>
            `).join("")}
          </div>
        </div>
        `:""}

        <!-- Timeline -->
        ${a.length?Ke(a,n):""}

        <!-- Next steps -->
        ${o.nextSteps.length?`
        <div class="incident-section">
          <div class="incident-section-label">Suggested next steps</div>
          <ol class="next-steps-list">
            ${o.nextSteps.map(v=>`<li>${p(v)}</li>`).join("")}
          </ol>
        </div>
        `:""}

        <!-- Technician hint -->
        ${o.technicianHint?`
        <div class="incident-section">
          <div class="technician-hint">
            <span class="hint-label">Tech Hint</span>
            <span class="hint-text">${p(o.technicianHint)}</span>
          </div>
        </div>
        `:""}

        <!-- Copy for ticket -->
        <div class="incident-footer">
          <button class="copy-summary-btn" data-summary="${p(o.psaSummary)}">
            Copy for ticket
          </button>
          ${(h=o.alternateSignatures)!=null&&h.length?`
          <span class="alt-signatures">
            Also possible: ${o.alternateSignatures.map(v=>v.signature.name).join(", ")}
          </span>
          `:""}
        </div>
      </div>
    </div>
  `}function Ke(e,t){const n=[...e,t].sort((i,o)=>i.timestamp-o.timestamp),s=n.length>12?[...n.slice(0,6),{_ellipsis:!0,count:n.length-10},...n.slice(-4)]:n;return`
    <div class="incident-section">
      <div class="incident-section-label">Timeline (${e.length} events in ${Fe}-min window)</div>
      <div class="mini-timeline">
        ${s.map(i=>{var r;if(i._ellipsis)return`<div class="timeline-ellipsis">· · · ${i.count} more events · · ·</div>`;const o=i===t;return`
            <div class="timeline-item ${o?"timeline-anchor":""}">
              <div class="tl-dot sev-${(r=i.severity)==null?void 0:r.toLowerCase()}"></div>
              <div class="tl-content">
                <span class="tl-time">${ce(i.timestamp)}</span>
                <span class="tl-id" data-lookup-id="${i.id}">${i.id}</span>
                <span class="tl-provider">${p(M(i.provider))}</span>
                ${o?'<span class="tl-anchor-label">ANCHOR</span>':""}
              </div>
            </div>
          `}).join("")}
      </div>
    </div>
  `}const Fe=15,Xe=new Set(["Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting","Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-DistributedCOM","Microsoft-Windows-Security-SPP","Microsoft-Windows-Defrag","Microsoft-Windows-Power-Troubleshooter"]),Y={Critical:0,Error:1,Warning:2,Info:3,Verbose:4},d={sortCol:"timestamp",sortDir:"asc",page:0,pageSize:100,query:"",severities:new Set,provider:"",channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set};function ze(e){var r,c;if(!N||!b)return;Object.assign(d,{sortCol:"timestamp",sortDir:"asc",page:0,query:"",severities:new Set,provider:"",channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set});const t=[...new Set(e.map(l=>l.provider).filter(Boolean))].sort(),n=[...new Set(e.map(l=>l.channel).filter(Boolean))].sort(),a=l=>l?new Date(l-l.getTimezoneOffset()*6e4).toISOString().slice(0,16):"",s=(r=e[0])==null?void 0:r.timestamp,i=(c=e[e.length-1])==null?void 0:c.timestamp;N.innerHTML=`
    <div class="event-log-filters">
      <input type="search" id="tbl-query" class="filter-control filter-control-search"
        placeholder="Search ID, provider, message…" autocomplete="off" spellcheck="false" />

      <div class="tbl-sev-chips">
        ${["Critical","Error","Warning","Info","Verbose"].map(l=>`
          <label class="sev-chip" data-severity="${l}">
            <input type="checkbox" class="sev-cb tbl-sev-cb" value="${l}" />
            <span class="chip-dot dot-${l}"></span>
            <span>${l}</span>
          </label>`).join("")}
      </div>

      <select id="tbl-provider" class="filter-control filter-control-select">
        <option value="">All providers</option>
        ${t.map(l=>`<option value="${p(l)}">${p(M(l))}</option>`).join("")}
      </select>

      <select id="tbl-channel" class="filter-control filter-control-select">
        <option value="">All channels</option>
        ${n.map(l=>`<option value="${p(l)}">${p(l)}</option>`).join("")}
      </select>

      <div class="filter-date-group">
        <span class="filter-date-label">From</span>
        <input type="datetime-local" id="tbl-from" class="filter-control filter-control-date"
          value="${a(s)}" />
      </div>
      <div class="filter-date-group">
        <span class="filter-date-label">To</span>
        <input type="datetime-local" id="tbl-to" class="filter-control filter-control-date"
          value="${a(i)}" />
      </div>

      <div class="filter-spacer"></div>
      <button id="tbl-noise" class="filter-noise-btn">Hide noise</button>
      <button id="tbl-csv"   class="filter-csv-btn">↓ CSV</button>
    </div>
  `;const o=(l,u,g)=>{var h;return(h=document.getElementById(l))==null?void 0:h.addEventListener(u,g)};o("tbl-query","input",l=>{d.query=l.target.value,d.page=0,$()}),N.querySelectorAll(".tbl-sev-cb").forEach(l=>{l.addEventListener("change",()=>{l.checked?d.severities.add(l.value):d.severities.delete(l.value),l.closest(".sev-chip").classList.toggle("active",l.checked),d.page=0,$()})}),o("tbl-provider","change",l=>{d.provider=l.target.value,d.page=0,$()}),o("tbl-channel","change",l=>{d.channel=l.target.value,d.page=0,$()}),o("tbl-from","change",l=>{d.fromTime=l.target.value,d.page=0,$()}),o("tbl-to","change",l=>{d.toTime=l.target.value,d.page=0,$()}),o("tbl-noise","click",l=>{d.hideNoisy=!d.hideNoisy,d.page=0,l.target.classList.toggle("active",d.hideNoisy),l.target.textContent=d.hideNoisy?"Show noise":"Hide noise",$()}),o("tbl-csv","click",()=>Qe(ae())),$()}function ae(){const e=d.query.toLowerCase(),t=d.fromTime?new Date(d.fromTime).getTime():null,n=d.toTime?new Date(d.toTime).getTime():null;let a=k.filter(s=>!(d.severities.size>0&&!d.severities.has(s.severity)||d.provider&&s.provider!==d.provider||d.channel&&s.channel!==d.channel||t!==null&&s.timestamp<t||n!==null&&s.timestamp>n||d.hideNoisy&&Xe.has(s.provider)||e&&!`${s.id} ${s.provider} ${s.channel} ${s.message} ${s.severity}`.toLowerCase().includes(e)));return a.sort((s,i)=>{let o=0;switch(d.sortCol){case"timestamp":o=s.timestamp-i.timestamp;break;case"severity":o=(Y[s.severity]??9)-(Y[i.severity]??9);break;case"id":o=s.id-i.id;break;case"provider":o=(s.provider||"").localeCompare(i.provider||"");break}return d.sortDir==="asc"?o:-o}),a}function $(){if(!b)return;const e=ae(),t=e.length,n=Math.max(0,Math.ceil(t/d.pageSize)-1);d.page=Math.min(d.page,n);const a=d.page*d.pageSize,s=e.slice(a,a+d.pageSize);if(!t){b.innerHTML='<div class="table-empty">No events match the current filters.</div>';return}const i=c=>`<span class="sort-arrow ${d.sortCol===c?"active":""}">${d.sortCol===c?d.sortDir==="asc"?"↑":"↓":"↕"}</span>`,o=c=>d.sortCol===c?"sort-active":"";b.innerHTML=`
    <div class="table-info-bar">
      <span class="table-count-text">
        ${(a+1).toLocaleString()}–${Math.min(a+d.pageSize,t).toLocaleString()} of ${t.toLocaleString()} event${t!==1?"s":""}
        ${t<k.length?` (${k.length.toLocaleString()} total)`:""}
      </span>
      <div class="table-pagination">
        <button class="page-btn" id="pg-first" ${d.page===0?"disabled":""}>«</button>
        <button class="page-btn" id="pg-prev"  ${d.page===0?"disabled":""}>‹ Prev</button>
        <span class="page-info">Page ${d.page+1} / ${n+1}</span>
        <button class="page-btn" id="pg-next"  ${d.page>=n?"disabled":""}>Next ›</button>
        <button class="page-btn" id="pg-last"  ${d.page>=n?"disabled":""}>»</button>
      </div>
    </div>
    <table class="event-table">
      <thead><tr>
        <th style="width:18px"></th>
        <th data-sort="timestamp" class="${o("timestamp")}">Time ${i("timestamp")}</th>
        <th data-sort="severity"  class="${o("severity")}">Sev ${i("severity")}</th>
        <th data-sort="id"        class="${o("id")}">ID ${i("id")}</th>
        <th data-sort="provider"  class="${o("provider")}">Provider ${i("provider")}</th>
        <th>Channel</th>
        <th>Message</th>
      </tr></thead>
      <tbody>${s.map(c=>Ye(c)).join("")}</tbody>
    </table>
  `,b.querySelectorAll("th[data-sort]").forEach(c=>{c.addEventListener("click",()=>{const l=c.dataset.sort;d.sortDir=d.sortCol===l&&d.sortDir==="asc"?"desc":"asc",d.sortCol=l,d.page=0,$()})});const r=(c,l)=>{var u;return(u=document.getElementById(c))==null?void 0:u.addEventListener("click",l)};r("pg-first",()=>{d.page=0,$()}),r("pg-prev",()=>{d.page--,$()}),r("pg-next",()=>{d.page++,$()}),r("pg-last",()=>{d.page=n,$()}),b.querySelectorAll("tbody tr[data-record]").forEach(c=>{c.addEventListener("click",l=>{if(l.target.closest(".table-event-id"))return;const u=parseInt(c.dataset.record,10);d.expandedIds.has(u)?d.expandedIds.delete(u):d.expandedIds.add(u),$()})}),b.querySelectorAll(".table-event-id").forEach(c=>{c.addEventListener("click",l=>{l.stopPropagation(),re(c.dataset.lookupId)})}),b.querySelectorAll(".ev-advanced-toggle").forEach(c=>{c.addEventListener("click",l=>{l.stopPropagation();const g=c.closest(".ev-detail-inner").querySelector(".ev-advanced-section").classList.toggle("ev-advanced-open");c.textContent=g?"Advanced ▲":"Advanced ▼"})})}function Ye(e){var v;const t=d.expandedIds.has(e.recordId),n=e.severity.toLowerCase(),a=Object.keys(e.data||{}),s=e.message?p(e.message.substring(0,150))+(e.message.length>150?"…":""):'<span style="color:var(--text3);font-style:italic">no message</span>',i=`
    <tr class="ev-row-${n}${t?" row-expanded":""}" data-record="${e.recordId}">
      <td class="ev-col-expand">${t?"▼":"▶"}</td>
      <td class="ev-col-time">${Ze(e.timestamp)}</td>
      <td><span class="sev-badge sev-badge-${n}">${e.severity}</span></td>
      <td><span class="table-event-id" data-lookup-id="${e.id}" title="Look up Event ${e.id}">${e.id}</span></td>
      <td class="ev-col-provider" title="${p(e.provider)}">${p(M(e.provider))}</td>
      <td class="ev-col-channel">${p(e.channel)}</td>
      <td class="ev-col-message">${s}</td>
    </tr>`;if(!t)return i;const o=e.taskName||e.task||null,r=e.opcodeName||e.opcode||null,c=(v=e.keywordNames)!=null&&v.length?e.keywordNames.join(", "):e.keywords||null,l=[["Time (local)",e.timestamp.toLocaleString()],["Time (UTC)",e.timestamp.toISOString()],["Provider",e.provider],["Channel",e.channel],["Computer",e.computer],["Record ID",e.recordId||null],["User SID",e.userSID],["Process ID",e.processId||null],["Thread ID",e.threadId||null],["Activity ID",e.activityId],["Related Act. ID",e.relatedActivityId],["Task",o],["Opcode",r],["Keywords",c]].filter(([,f])=>f),u=[["Raw Level",String(e.levelNum)],["Raw Task",e.task],["Raw Opcode",e.opcode],["Raw Keywords",e.keywords],["Version",e.version],["Qualifiers",e.qualifiers],["Provider Desc.",e.providerDescription]].filter(([,f])=>f),g=e.message?`<div class="ev-detail-message">${p(e.message)}</div>`:`<div class="ev-detail-message ev-no-message">
        Message not rendered — Windows message templates are stored on the source machine.
        Export directly from the affected computer to see full event messages.
       </div>`,h=e.dataAnon||[];return i+`
    <tr class="ev-detail-row">
      <td colspan="7">
        <div class="ev-detail-inner">
          ${g}
          <div class="ev-detail-meta">
            ${l.map(([f,m])=>`
              <div class="ev-detail-field">
                <span class="ev-detail-key">${f}</span>
                <span class="ev-detail-val">${p(String(m))}</span>
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
            ${h.map((f,m)=>`
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key ev-detail-data-key--anon">[${m}]</span>
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
            ${u.map(([f,m])=>`
              <div class="ev-detail-field">
                <span class="ev-detail-key">${f}</span>
                <span class="ev-detail-val">${p(String(m))}</span>
              </div>`).join("")}
          </div>`:""}
        </div>
      </td>
    </tr>`}function Qe(e){const t=["Time (UTC)","Severity","EventID","Provider","Channel","Computer","RecordID","ProcessID","ThreadID","UserSID","ActivityID","RelatedActivityID","Task","TaskName","Opcode","OpcodeName","Keywords","KeywordNames","Version","Qualifiers","ProviderDescription","Message","EventData","EventDataAnon"],n=r=>`"${String(r??"").replace(/"/g,'""').replace(/\r?\n/g," ")}"`,a=e.map(r=>[r.timestamp.toISOString(),r.severity,r.id,n(r.provider),n(r.channel),n(r.computer),r.recordId,r.processId||"",r.threadId||"",n(r.userSID),n(r.activityId),n(r.relatedActivityId),n(r.task),n(r.taskName),n(r.opcode),n(r.opcodeName),n(r.keywords),n((r.keywordNames||[]).join("; ")),n(r.version),n(r.qualifiers),n(r.providerDescription),n(r.message),n(Object.entries(r.data||{}).map(([c,l])=>`${c}=${l}`).join("; ")),n((r.dataAnon||[]).join("; "))].join(",")),s=[t.join(","),...a].join(`\r
`),i=URL.createObjectURL(new Blob([s],{type:"text/csv;charset=utf-8;"})),o=Object.assign(document.createElement("a"),{href:i,download:`eventful-${new Date().toISOString().slice(0,10)}.csv`});document.body.appendChild(o),o.click(),document.body.removeChild(o),URL.revokeObjectURL(i)}function re(e){const t=parseInt(e,10),n=document.getElementById("lookup-panel"),a=document.getElementById("lp-body");if(!n||!a)return;const s=ye.find(o=>o.id===t),i=k.filter(o=>o.id===t);a.innerHTML=Je(t,s,i),n.hidden=!1,a.querySelectorAll(".lp-copy-ps").forEach(o=>{o.addEventListener("click",()=>{navigator.clipboard.writeText(o.dataset.code).then(()=>{o.textContent="Copied!",setTimeout(()=>{o.textContent="Copy"},2e3)})})}),a.querySelectorAll(".lp-advanced-toggle").forEach(o=>{o.addEventListener("click",()=>{const c=o.nextElementSibling.classList.toggle("lp-advanced-open");o.textContent=c?"Advanced ▲":"Advanced ▼"})})}function O(){const e=document.getElementById("lookup-panel");e&&(e.hidden=!0)}function Je(e,t,n){var i,o,r;let a="";if(t){const c=((i=t.severity)==null?void 0:i.toLowerCase())??"info";a+=`
      <div class="lp-section">
        <div class="lp-section-label">Knowledge Base</div>
        <div class="lp-doc-header">
          <span class="lp-id-badge">${e}</span>
          <div>
            <div class="lp-doc-title">${p(t.title)}</div>
            <div class="lp-doc-meta">
              <span class="sev-badge sev-badge-${c}">${p(t.severity)}</span>
              <span class="lp-channel">${p(t.channel||t.source||"")}</span>
            </div>
          </div>
        </div>
        <p class="lp-description">${p(t.description||t.short_desc||"")}</p>
        ${(o=t.causes)!=null&&o.length?`
          <div class="lp-subsection-label">Causes</div>
          <ul class="lp-causes">
            ${t.causes.map(l=>`<li>${p(l)}</li>`).join("")}
          </ul>`:""}
        ${(r=t.steps)!=null&&r.length?`
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
      </div>`;if(n.length===0)return a+=`
      <div class="lp-section">
        <div class="lp-section-label">From your log</div>
        <div class="lp-no-raw">No events with this ID in the uploaded log.</div>
      </div>`,a;const s=n.slice(0,3);return a+=`
    <div class="lp-section">
      <div class="lp-section-label">
        From your log
        ${n.length>1?`<span class="lp-raw-count">${n.length} occurrences</span>`:""}
      </div>
      ${s.map((c,l)=>{var m;const u=c.taskName||c.opcode||null,g=c.opcodeName||c.opcode||null,h=(m=c.keywordNames)!=null&&m.length?c.keywordNames.join(", "):c.keywords||null,v=c.dataAnon||[],f=[["Raw Level",String(c.levelNum)],["Raw Task",c.task],["Raw Opcode",c.opcode],["Raw Keywords",c.keywords],["Version",c.version],["Qualifiers",c.qualifiers],["Provider Desc.",c.providerDescription],["Related Act. ID",c.relatedActivityId]].filter(([,S])=>S);return`
        ${l>0?'<div class="lp-raw-divider"></div>':""}
        <div class="lp-raw-fields">
          ${y("Time",c.timestamp.toLocaleString())}
          ${y("Severity",`<span class="sev-badge sev-badge-${c.severity.toLowerCase()}">${c.severity}</span>`)}
          ${y("Provider",p(M(c.provider)))}
          ${y("Channel",p(c.channel))}
          ${y("Computer",p(c.computer||"—"))}
          ${y("Record ID",String(c.recordId||"—"))}
          ${c.processId?y("Process ID",String(c.processId)):""}
          ${c.threadId?y("Thread ID",String(c.threadId)):""}
          ${c.userSID?y("User SID",p(c.userSID)):""}
          ${c.activityId?y("Activity ID",p(c.activityId)):""}
          ${u?y("Task",p(u)):""}
          ${g?y("Opcode",p(g)):""}
          ${h?y("Keywords",p(h)):""}
        </div>
        ${c.message?`<div class="lp-raw-message-label">Message</div>
             <div class="lp-raw-message">${p(c.message)}</div>`:`<div class="lp-raw-message-label">Message</div>
             <div class="lp-raw-message lp-no-message">Message not rendered — Windows message templates are stored on the source machine. Export directly from the affected computer to see full event messages.</div>`}
        ${Object.keys(c.data||{}).length||v.length?`
          <div class="lp-raw-message-label">Event Data</div>
          <div class="lp-raw-data">
            ${Object.entries(c.data).map(([S,C])=>`
              <div class="lp-raw-data-row">
                <span class="lp-raw-data-key">${p(S)}</span>
                <span class="lp-raw-data-val">${p(String(C))}</span>
              </div>`).join("")}
            ${v.map((S,C)=>`
              <div class="lp-raw-data-row">
                <span class="lp-raw-data-key lp-raw-data-key--anon">[${C}]</span>
                <span class="lp-raw-data-val">${p(String(S))}</span>
              </div>`).join("")}
          </div>`:""}
        ${f.length?`
          <button class="lp-advanced-toggle">Advanced ▼</button>
          <div class="lp-advanced-section">
            <div class="lp-raw-message-label">Advanced / Raw</div>
            <div class="lp-raw-fields">
              ${f.map(([S,C])=>y(S,p(C))).join("")}
            </div>
          </div>`:""}
        `}).join("")}
      ${n.length>3?`<div class="lp-raw-more">+ ${n.length-3} more occurrence${n.length-3!==1?"s":""} in log</div>`:""}
    </div>`,a}function y(e,t){return`
    <div class="lp-raw-field">
      <span class="lp-raw-key">${e}</span>
      <span class="lp-raw-val">${t}</span>
    </div>`}function Q(e){const t=w==null?void 0:w.querySelector(".upload-error");t&&t.remove();const n=document.createElement("div");n.className="upload-error",n.textContent=e,w==null||w.appendChild(n),A(L)}function p(e){return e?String(e).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"):""}function M(e){return e?e.replace(/^Microsoft-Windows-/i,"").replace(/^Microsoft-/i,""):"—"}function ce(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}function Ze(e){return e.toLocaleString([],{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})}function et(e){return`sev-header-${(e==null?void 0:e.toLowerCase())??"info"}`}function tt(e){return{41:"Unexpected System Reboot",6008:"Unexpected Shutdown Detected",1001:"System Crash (BSOD)",1e3:"Application Crash",7024:"Critical Service Failure"}[e.id]??`Event ${e.id}`}
