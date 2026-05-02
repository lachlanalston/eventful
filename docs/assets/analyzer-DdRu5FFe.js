import{i as be,t as $e}from"./theme-gEBc2EcC.js";import{a as ke}from"./index-xfVKLF0W.js";function Ee(e){const n=new DOMParser().parseFromString(e,"text/xml"),a=n.querySelector("parsererror");if(a)throw new Error(`Invalid XML: ${a.textContent.substring(0,120)}`);const s=n.querySelectorAll("Event");if(s.length===0)throw new Error("No <Event> elements found. Make sure you exported in XML format from Event Viewer.");const i=[];for(const o of s)try{const r=Ce(o);!isNaN(r.id)&&r.id>0&&r.timestamp instanceof Date&&!isNaN(r.timestamp)&&i.push(r)}catch{}if(i.length===0)throw new Error("No valid events could be parsed. Check that the XML is a Windows Event Viewer export.");return i.sort((o,r)=>o.timestamp-r.timestamp)}function Ce(e){var B,q,W,U,j,H,_,V,K;const t=e.querySelector("System"),n=parseInt(E(t,"EventID"),10),a=parseInt(E(t,"Level"),10),s=t==null?void 0:t.querySelector("Provider"),i=(s==null?void 0:s.getAttribute("Name"))||(s==null?void 0:s.getAttribute("EventSourceName"))||"",o=E(t,"Channel"),r=E(t,"Computer"),l=parseInt(E(t,"EventRecordID"),10),p=t==null?void 0:t.querySelector("TimeCreated"),v=(p==null?void 0:p.getAttribute("SystemTime"))||(p==null?void 0:p.textContent)||"",g=new Date(v),h=t==null?void 0:t.querySelector("Execution"),m=t==null?void 0:t.querySelector("Correlation"),b=t==null?void 0:t.querySelector("Security"),c=e.querySelector("RenderingInfo"),y=(q=(B=c==null?void 0:c.querySelector("Level"))==null?void 0:B.textContent)==null?void 0:q.trim(),f=De(a,y),$=((U=(W=c==null?void 0:c.querySelector("Task"))==null?void 0:W.textContent)==null?void 0:U.trim())||"",he=((H=(j=c==null?void 0:c.querySelector("Opcode"))==null?void 0:j.textContent)==null?void 0:H.trim())||"",me=[...(c==null?void 0:c.querySelectorAll("Keywords > Keyword"))??[]].map(Se=>Se.textContent.trim()).filter(Boolean),ge=((V=(_=c==null?void 0:c.querySelector("Provider"))==null?void 0:_.textContent)==null?void 0:V.trim())||"",fe=Ie(e,c),{named:we,anon:ye}=xe(e);return{id:n,provider:i,channel:o,levelNum:a,severity:f,timestamp:g,computer:r,message:fe,recordId:isNaN(l)?0:l,processId:parseInt(h==null?void 0:h.getAttribute("ProcessID"),10)||0,threadId:parseInt(h==null?void 0:h.getAttribute("ThreadID"),10)||0,activityId:(m==null?void 0:m.getAttribute("ActivityID"))||"",relatedActivityId:(m==null?void 0:m.getAttribute("RelatedActivityID"))||"",userSID:(b==null?void 0:b.getAttribute("UserID"))||"",task:E(t,"Task"),opcode:E(t,"Opcode"),keywords:E(t,"Keywords"),taskName:$,opcodeName:he,keywordNames:me,providerDescription:ge,version:E(t,"Version"),qualifiers:((K=t==null?void 0:t.querySelector("EventID"))==null?void 0:K.getAttribute("Qualifiers"))||"",data:we,dataAnon:ye}}function E(e,t){var n,a;return((a=(n=e==null?void 0:e.querySelector(t))==null?void 0:n.textContent)==null?void 0:a.trim())||""}function Ie(e,t){var i,o;const n=(o=(i=t==null?void 0:t.querySelector("Message"))==null?void 0:i.textContent)==null?void 0:o.trim();if(n)return n;const a=e.querySelector("EventData");if(a){const r=[];for(const l of a.querySelectorAll("Data")){const p=l.getAttribute("Name"),v=l.textContent.trim();v&&v!=="-"&&r.push(p?`${p}: ${v}`:v)}if(r.length)return r.join(" | ")}const s=e.querySelector("UserData");return s?s.textContent.trim():""}function xe(e){const t={},n=[],a=e.querySelector("EventData");if(!a)return{named:t,anon:n};for(const s of a.querySelectorAll("Data")){const i=s.getAttribute("Name"),o=s.textContent.trim();i?o&&(t[i]=o):o&&n.push(o)}return{named:t,anon:n}}function De(e,t){if(t){const n=t.toLowerCase();if(n.includes("critical"))return"Critical";if(n.includes("error"))return"Error";if(n.includes("warning"))return"Warning";if(n.includes("information"))return"Info";if(n.includes("verbose"))return"Verbose";if(n.includes("audit"))return t.includes("Failure")?"Error":"Info"}switch(e){case 1:return"Critical";case 2:return"Error";case 3:return"Warning";case 4:return"Info";case 5:return"Verbose";case 0:return"Info";default:return"Info"}}const Ae=new Set([41,6008,1001,1e3,7024]),G={7:40,11:30,51:40,52:30,55:35,57:25,129:20,153:20,4101:50,1001:45,1e3:35,1002:30,1026:20,7031:25,7034:25,7022:20,7023:20,7001:15,7011:15,1014:20,4202:20,4201:15,17:50,18:40,19:30,4625:10,4740:15},Me=new Set(["Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting"]),Te=[{id:"gpu-driver-crash",name:"GPU Driver Crash",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',category:"Hardware Driver",test(e){const t=["nvlddmkm","amdkmdag","amd","igdkmd","dxgkrnl","atikmdag"],n=e.some(s=>s.id===4101),a=e.find(s=>t.some(i=>{var o;return(o=s.provider)==null?void 0:o.toLowerCase().includes(i)}));return n?{match:!0,confidence:"high",reason:"Event 4101 (display driver TDR timeout) found in window"}:a?{match:!0,confidence:"medium",reason:`GPU provider "${a.provider}" found in window — no Event 4101`}:{match:!1}},what:"The graphics card driver stopped responding and Windows could not recover it.",rootCause:"Display driver (TDR timeout) caused the system to become unresponsive.",nextSteps:["Update or roll back GPU drivers via Device Manager → Display Adapters","Use DDU (Display Driver Uninstaller) in Safe Mode for clean reinstall","Monitor GPU temperatures under load with GPU-Z or HWiNFO64","Run GPU stability test with FurMark or 3DMark","Check GPU power connector seating if system is recently assembled"],technicianHint:'NVIDIA: look for "nvlddmkm" in Event 4101 faulting module. AMD: "atikmpag" or "amdkmdag". DDU clean reinstall resolves driver corruption in ~70% of cases. If temps are fine and fresh driver fails, suspect hardware.'},{id:"disk-failure",name:"Storage / Disk Error",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/></svg>',category:"Storage",test(e){const t=[7,11,51,52,55,57,129,153],n=["disk","atapi","nvme","storport","ntfs","fastfat","stornvme"],a=e.filter(i=>t.includes(i.id)||n.some(o=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(o)})),s=[...new Set(a.map(i=>i.id))].join(", ");return a.length>=3?{match:!0,confidence:"high",reason:`${a.length} disk error events in window (IDs: ${s})`}:a.length>=1?{match:!0,confidence:"medium",reason:`${a.length} disk error event in window (ID: ${s})`}:{match:!1}},what:"The storage device reported I/O errors before the incident.",rootCause:"Disk hardware errors were detected — possible drive failure, bad sectors, or controller issue.",nextSteps:["Run CrystalDiskInfo — check SMART reallocated/pending/uncorrectable sectors","Run chkdsk /f /r /x on affected volume","Run manufacturer disk diagnostic (SeaTools, WD Dashboard, Samsung Magician)","Check SATA/power cable connections","Consider imaging and replacing drive if SMART shows degradation"],technicianHint:"Event 7 = hardware error from disk.sys. Event 51 = error during paging (system swapping to bad sectors — urgent). Event 55 = NTFS filesystem corruption. Multiple Event 7 in a short window usually means imminent failure."},{id:"bsod-kernel-crash",name:"Blue Screen of Death (BSOD)",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',category:"Kernel Crash",test(e,t){return t.id===1001?{match:!0,confidence:"high",reason:"Event 1001 (BugCheck) is the anchor — BSOD confirmed"}:e.some(n=>n.id===1001)?{match:!0,confidence:"high",reason:"Event 1001 (BugCheck/BSOD) found in window events"}:{match:!1}},what:"Windows detected an unrecoverable kernel error and created a memory dump.",rootCause:"A kernel or driver-level fault caused Windows to stop to prevent data corruption.",nextSteps:["Note the BugCheck code from Event 1001 details","Analyse minidump with WhoCrashed (free) or WinDbg (!analyze -v)","Run SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth","Run Windows Memory Diagnostic for MEMORY_MANAGEMENT (0x1A) stops","Update all drivers — especially GPU, NIC, and chipset"],technicianHint:"Common stop codes: 0x50 PAGE_FAULT (bad RAM or driver), 0x3B SYSTEM_SERVICE_EXCEPTION (driver), 0x1A MEMORY_MANAGEMENT (RAM), 0x7E SYSTEM_THREAD_EXCEPTION (driver), 0x0A IRQL_NOT_LESS_OR_EQUAL (driver/RAM). WhoCrashed gives the culprit driver in seconds."},{id:"service-crash-chain",name:"Service Crash Loop",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',category:"Windows Services",test(e){const t=[7031,7034,7022,7023,7024,7001,7011],n=e.filter(s=>t.includes(s.id)),a=[...new Set(n.map(s=>s.id))].join(", ");return n.length>=5?{match:!0,confidence:"high",reason:`${n.length} service failure events in window (IDs: ${a})`}:n.length>=2?{match:!0,confidence:"medium",reason:`${n.length} service failure events in window (IDs: ${a})`}:{match:!1}},what:"One or more Windows services crashed or failed to start repeatedly.",rootCause:"Service instability — possibly caused by a failed update, corrupted binary, or missing dependency.",nextSteps:["Identify which service(s) crashed from the event messages","Check service recovery settings: Services → right-click service → Properties → Recovery","Verify the service executable exists and is not corrupted","Check for related Application log events (Event 1000) for the service host","Review recent Windows Updates that may have changed the service"],technicianHint:"Event 7031 = service terminated unexpectedly (count tells you how many times). Event 7034 = crashed without telling SCM. The service name is in the event message. If it's svchost-hosted, check the service group."},{id:"application-crash-loop",name:"Application Crash Loop",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',category:"Application",test(e){const t=e.filter(n=>n.id===1e3);return t.length>=3?{match:!0,confidence:"high",reason:`${t.length} Event 1000 (application crash) in window`}:t.length>=1?{match:!0,confidence:"medium",reason:"1 Event 1000 (application crash) in window"}:{match:!1}},what:"An application was crashing repeatedly before the incident.",rootCause:"Application instability — possible corrupt installation, missing runtime, or incompatible update.",nextSteps:["Identify the crashing application from the Event 1000 message","Note the faulting module — it often identifies a specific DLL","Update or reinstall the application","Install/repair Visual C++ Redistributables if a runtime DLL faults","Check crash dumps in %LocalAppData%\\CrashDumps or the application's folder"],technicianHint:'The faulting module in Event 1000 is gold — "ntdll.dll" = OS issue or heap corruption, "msvcp140.dll" / "vcruntime140.dll" = missing C++ runtime, "AppName.exe" itself = bad binary. Repeated same app + same module = deterministic, reproducible fault.'},{id:"memory-hardware",name:"Memory / RAM Issue",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/></svg>',category:"Hardware",test(e){const t=["microsoft-windows-memoryd","whea-logger","microsoft-windows-whea"],n=[17,18,19,1],a=e.find(i=>n.includes(i.id)||t.some(o=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(o)}));return e.some(i=>{var o,r;return i.id===1001&&(((o=i.data)==null?void 0:o.BugcheckCode)==="26"||((r=i.data)==null?void 0:r.BugcheckCode)==="80")})?{match:!0,confidence:"medium",reason:"BSOD stop code indicates memory fault (0x1A MEMORY_MANAGEMENT or 0x50 PAGE_FAULT)"}:a?{match:!0,confidence:"medium",reason:`Memory/WHEA event detected (Event ${a.id} from ${a.provider||"unknown provider"})`}:{match:!1}},what:"Hardware memory errors or RAM-related faults were detected.",rootCause:"Defective or misconfigured RAM caused uncorrectable memory errors.",nextSteps:["Run MemTest86+ overnight (at least 2 passes)","Test RAM sticks one at a time to isolate the faulty module","Reseat RAM modules and clean contacts","Check XMP/EXPO profile stability — reset to JEDEC spec in BIOS","Check WHEA-Logger events for corrected/uncorrected error counts"],technicianHint:`WHEA Event 17/18/19 = hardware error framework caught a hardware error. Check the ErrorSource field — "MCE" (Machine Check Exception) = hardware fault, usually RAM or CPU. MemTest86+ is the definitive test. Don't trust Windows Memory Diagnostic for subtle faults.`},{id:"unexpected-power",name:"Unexpected Power Loss",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',category:"Power",test(e,t){var n;return t.id===41&&((n=t.data)==null?void 0:n.BugcheckCode)==="0"?{match:!0,confidence:"high",reason:"Event 41 BugcheckCode=0 — hard power loss confirmed (not a software crash)"}:(t.id===41||t.id===6008)&&e.length<=3?{match:!0,confidence:"medium",reason:`Only ${e.length} event(s) before anchor — abrupt stop, no software lead-up`}:{match:!1}},what:"The system lost power without going through a normal shutdown.",rootCause:"Hard power loss — possible PSU failure, power outage, or UPS failure.",nextSteps:["Check UPS health, battery test, and log — replace battery if > 3 years old","Test PSU voltage rails with PC Power Supply Tester or multimeter","Check power outlet and surge protector for faults","Review Event 41 BugcheckCode: 0 = power loss, non-0 = software crash","Install UPS with AVR if not present — protects against brownouts"],technicianHint:"Event 41 BugcheckCode=0 is definitive: the machine lost power while running (no BSOD, no clean shutdown). Very few preceding events confirms sudden loss. Multiple occurrences = PSU is failing. Check 12V rail — HDD-heavy systems are sensitive."},{id:"network-failure",name:"Network / Connectivity Failure",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',category:"Network",test(e){const t=[1014,4202,4201,6100],n=["tcpip","dns-client","dhcp","netbt","netlogon","rras"],a=e.filter(i=>t.includes(i.id)||n.some(o=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(o)})),s=[...new Set(a.map(i=>i.id))].join(", ");return a.length>=3?{match:!0,confidence:"medium",reason:`${a.length} network/DNS events in window (IDs: ${s})`}:a.length>=1?{match:!0,confidence:"low",reason:`1 network/DNS event in window (ID: ${s})`}:{match:!1}},what:"Network or DNS errors were recorded in the period leading up to the incident.",rootCause:"Network connectivity failure caused application or service faults.",nextSteps:["Check NIC driver version — update if outdated",'Disable NIC power management: Device Manager → NIC → Power Management → uncheck "Allow computer to turn off"',"Test DNS resolution: nslookup google.com","Review DHCP lease renewal logs","Check switch port, cable, and NIC hardware"],technicianHint:"Event 1014 = DNS client resolver timeout. If you see it, look at the DNS server IP in the event — a failing DC or DNS server is a common cause. Event 4201/4202 = NIC connection state changes = intermittent cable or switch issue."}],Le=15,Re={Critical:30,Error:20,Warning:10,Info:2,Verbose:0};function Ne(e){var r;if(!e.length)return{incidents:[],healthScore:100,computerName:"",stats:He()};const t=((r=e[0])==null?void 0:r.computer)||"",n=te(e),a=Pe(e),s=[];for(const l of a){const p=Oe(e,l,Le),g=Be(p,l).slice(0,8),h=qe(p,l),m=We(l,h,g);s.push({anchor:l,windowEvents:p,topContributors:g,signatureResult:h,report:m})}const i=Ve(s),o=_e(e,i);return{incidents:i,healthScore:o,computerName:t,stats:n}}function Pe(e){const t=[],n=new Set;for(const a of e){if(!Ae.has(a.id))continue;const s=`${a.id}-${Math.floor(a.timestamp/3e4)}`;n.has(s)||(n.add(s),t.push(a))}return t.sort((a,s)=>s.timestamp-a.timestamp).slice(0,5)}function Oe(e,t,n){const a=t.timestamp-n*6e4;return e.filter(s=>s.timestamp>=a&&s.timestamp<t.timestamp)}function Be(e,t){const n=e.map(s=>{let i=Re[s.severity]??0;G[s.id]&&(i+=G[s.id]),s.provider&&t.provider&&s.provider===t.provider&&(i+=8),Me.has(s.provider)&&(i=Math.max(0,i-15));const o=(t.timestamp-s.timestamp)/6e4;return o<2?i+=10:o<5&&(i+=5),{event:s,score:i}}),a=new Map;for(const{event:s}of n){const i=`${s.id}-${s.provider}`;a.set(i,(a.get(i)||0)+1)}for(const s of n){const i=`${s.event.id}-${s.event.provider}`,o=a.get(i)||1;o>=5?s.score+=15:o>=3?s.score+=8:o>=2&&(s.score+=4)}return n.filter(({score:s})=>s>0).sort((s,i)=>i.score-s.score).map(({event:s,score:i})=>({event:s,score:i}))}function qe(e,t){const n=[];for(const s of Te)try{const i=s.test(e,t);i.match&&n.push({signature:s,confidence:i.confidence,reason:i.reason||""})}catch{}const a={high:0,medium:1,low:2};return n.sort((s,i)=>(a[s.confidence]??3)-(a[i.confidence]??3)),n}function We(e,t,n,a){const s=t[0],i=s==null?void 0:s.signature,o=(s==null?void 0:s.confidence)??"low",r=(s==null?void 0:s.reason)||"",l=ee[e.id]??`Event ${e.id}`,p=(i==null?void 0:i.what)??`${l} occurred at ${ne(e.timestamp)}.`,v=(i==null?void 0:i.rootCause)??Ue(e,n),g=(i==null?void 0:i.nextSteps)??["Review event details for more information","Check System and Application logs for context"],h=i==null?void 0:i.technicianHint,m=je(e,i,n,o,r);return{what:p,rootCause:v,confidence:o,confidenceReason:r,nextSteps:g,technicianHint:h,psaSummary:m,alternateSignatures:t.slice(1,3),evidenceCount:n.length}}const ee={41:"Unexpected system reboot (Kernel-Power)",6008:"Unexpected previous shutdown (EventLog)",1001:"System crash / BSOD (BugCheck)",1e3:"Application crash (Application Error)",7024:"Critical service failure"};function Ue(e,t){if(!t.length)return"No significant preceding events identified in the lookback window.";const n=t[0].event;return`Leading event: ${n.provider||"Unknown"} Event ${n.id} (${n.severity}) recorded shortly before the incident.`}function je(e,t,n,a,s){return["INCIDENT SUMMARY","================",`Date/Time: ${e.timestamp.toLocaleString()}`,`Anchor Event: ${e.id} — ${ee[e.id]??"Unknown"}`,`Provider: ${e.provider||"Unknown"}`,`Computer: ${e.computer||"Unknown"}`,"","DIAGNOSIS","---------",t?`Pattern: ${t.name} (${t.category})`:"Pattern: No known pattern matched",`Confidence: ${a.toUpperCase()}${s?` — ${s}`:""}`,"",t?`What happened: ${t.what}`:"",t?`Root cause: ${t.rootCause}`:"","",`CONTRIBUTING EVENTS (top ${Math.min(n.length,5)})`,"------------------",...n.slice(0,5).map(({event:r})=>`  [${r.severity}] Event ${r.id} — ${r.provider||"Unknown"} @ ${ne(r.timestamp)}`),"","SUGGESTED NEXT STEPS","--------------------",...((t==null?void 0:t.nextSteps)??["Review event log for more context"]).map(r=>`  • ${r}`),"","Generated by Eventful Incident Analyzer"].filter(r=>r!==void 0).join(`
`)}function te(e){const t={Critical:0,Error:0,Warning:0,Info:0,Verbose:0};for(const n of e)t[n.severity]=(t[n.severity]||0)+1;return{total:e.length,...t}}function He(){return{total:0,Critical:0,Error:0,Warning:0,Info:0,Verbose:0}}function _e(e,t){let n=100;const a=te(e);n-=Math.min(a.Critical*15,40),n-=Math.min(a.Error*3,25),n-=Math.min(a.Warning*.5,10),n-=t.length*12;for(const s of t)s.report.confidence==="high"?n-=8:s.report.confidence==="medium"&&(n-=4);return Math.max(0,Math.min(100,Math.round(n)))}function Ve(e){const t=new Set;return e.filter(n=>{const a=`${n.anchor.id}-${Math.floor(n.anchor.timestamp/1e3)}`;return t.has(a)?!1:(t.add(a),!0)})}function ne(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}be();document.querySelectorAll(".theme-btn").forEach(e=>e.addEventListener("click",$e));const L=document.getElementById("upload-section"),se=document.getElementById("processing-section"),ie=document.getElementById("results-section"),w=document.getElementById("drop-zone"),A=document.getElementById("file-input"),z=document.getElementById("processing-text"),F=document.getElementById("overview-grid"),k=document.getElementById("incidents-section"),C=document.getElementById("event-table-wrap"),x=document.getElementById("event-log-filters-wrap"),P=document.getElementById("new-analysis-btn"),X=document.getElementById("results-sub");let I=[],D=new Map;A==null||A.addEventListener("change",e=>{var n;const t=(n=e.target.files)==null?void 0:n[0];t&&oe(t)});w==null||w.addEventListener("dragover",e=>{e.preventDefault(),w.classList.add("drag-over")});w==null||w.addEventListener("dragleave",()=>w.classList.remove("drag-over"));w==null||w.addEventListener("drop",e=>{var n;e.preventDefault(),w.classList.remove("drag-over");const t=(n=e.dataTransfer.files)==null?void 0:n[0];t&&oe(t)});P==null||P.addEventListener("click",Ke);var J;(J=document.getElementById("lp-backdrop"))==null||J.addEventListener("click",R);var Z;(Z=document.getElementById("lp-close"))==null||Z.addEventListener("click",R);document.addEventListener("keydown",e=>{e.key==="Escape"&&R()});async function oe(e){if(!e.name.toLowerCase().endsWith(".xml")&&e.type!=="text/xml"&&e.type!=="application/xml"){Q("Please upload an XML file exported from Windows Event Viewer.");return}T(`Reading ${e.name}…`);try{const t=await e.text();T("Parsing events…"),await O();const n=Ee(t);T(`Analysing ${n.length.toLocaleString()} events…`),await O();const a=Ne(n);I=n,D=new Map;for(const s of n)D.set(s.id,(D.get(s.id)||0)+1);T("Building report…"),await O(),Ge(a,e.name)}catch(t){Q(t.message||"Failed to parse file."),M(L)}}function O(){return new Promise(e=>setTimeout(e,16))}function M(e){[L,se,ie].forEach(t=>{t&&(t.hidden=!0)}),e&&(e.hidden=!1)}function T(e){z&&(z.textContent=e),M(se)}function Ke(){I=[],D=new Map,A&&(A.value=""),M(L)}function Ge(e,t){const{incidents:n,healthScore:a,computerName:s,stats:i}=e,o=document.querySelector(".results-title");if(o&&(o.textContent=t.replace(/\.xml$/i,"")),X){const p=[];s&&p.push(s),p.push(`${i.total.toLocaleString()} events`),n.length&&p.push(`${n.length} incident${n.length!==1?"s":""} detected`),X.textContent=p.join(" · ")}ze(a,i),Fe(n),Ze(I);const r=document.getElementById("tab-inc-count"),l=document.getElementById("tab-evt-count");r&&(r.textContent=n.length),l&&(l.textContent=i.total.toLocaleString()),document.querySelectorAll(".analyzer-tab").forEach(p=>{p.addEventListener("click",()=>{document.querySelectorAll(".analyzer-tab").forEach(g=>g.classList.remove("active")),p.classList.add("active");const v=p.dataset.tab;document.getElementById("incidents-section").hidden=v!=="incidents",document.getElementById("events-panel").hidden=v!=="events"})}),M(ie)}function ze(e,t){if(!F)return;const n=e>=80?"#34d399":e>=60?"#f59e0b":"#f43f5e",a=e>=80?"Good":e>=60?"Degraded":"Critical";F.innerHTML=`
    <div class="overview-bar">
      <div class="overview-health">
        <span class="ob-score" style="color:${n}">${e}</span>
        <span class="ob-denom">/100</span>
        <span class="ob-label">System Health</span>
        <span class="ob-status" style="color:${n}">${a}</span>
      </div>
      <div class="ob-divider"></div>
      <div class="ob-stats">
        <div class="ob-stat stat-critical"><span class="ob-stat-num">${t.Critical.toLocaleString()}</span><span class="ob-stat-label">Critical</span></div>
        <div class="ob-stat stat-error">   <span class="ob-stat-num">${t.Error.toLocaleString()}</span>   <span class="ob-stat-label">Error</span></div>
        <div class="ob-stat stat-warning"> <span class="ob-stat-num">${t.Warning.toLocaleString()}</span> <span class="ob-stat-label">Warning</span></div>
        <div class="ob-stat stat-info">    <span class="ob-stat-num">${t.Info.toLocaleString()}</span>    <span class="ob-stat-label">Info</span></div>
        <div class="ob-stat stat-total">   <span class="ob-stat-num">${t.total.toLocaleString()}</span>   <span class="ob-stat-label">Total</span></div>
      </div>
    </div>
  `}function Fe(e){if(k){if(!e.length){k.innerHTML=`
      <div class="no-incidents">
        <div class="no-incidents-icon"><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div>
        <div class="no-incidents-title">No incidents detected</div>
        <div class="no-incidents-sub">No known crash or failure anchor events were found in this log.</div>
      </div>
    `;return}k.innerHTML=e.map((t,n)=>Xe(t)).join(""),k.querySelectorAll(".incident-toggle").forEach(t=>{t.addEventListener("click",n=>{if(n.target.closest("[data-lookup-id]"))return;const s=t.closest(".incident-card").querySelector(".incident-body"),i=t.querySelector(".incident-chevron"),o=!s.hidden;s.hidden=o,i.classList.toggle("open",!o)})}),k.querySelectorAll(".copy-summary-btn").forEach(t=>{t.addEventListener("click",()=>{const n=t.dataset.summary;navigator.clipboard.writeText(n).then(()=>{t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy for ticket",t.classList.remove("copied")},2e3)})})}),k.querySelectorAll(".evidence-item").forEach(t=>{t.addEventListener("click",n=>{if(n.stopPropagation(),n.target.closest("[data-lookup-id]"))return;const s=t.closest(".evidence-wrap").querySelector(".evidence-detail"),i=t.querySelector(".ev-expand-chevron"),o=!s.hidden;s.hidden=o,t.classList.toggle("expanded",!o),i&&(i.textContent=o?"▶":"▼")})}),k.querySelectorAll(".timeline-item").forEach(t=>{t.addEventListener("click",n=>{if(n.stopPropagation(),n.target.closest("[data-lookup-id]"))return;const a=t.closest(".timeline-item-wrap");if(!a)return;const s=a.querySelector(".timeline-detail");if(!s)return;const i=t.querySelector(".tl-expand-chevron"),o=!s.hidden;s.hidden=o,i&&(i.textContent=o?"▶":"▼")})}),k.querySelectorAll(".ev-advanced-toggle").forEach(t=>{t.addEventListener("click",n=>{n.stopPropagation();const s=t.closest(".ev-inline-detail").querySelector(".ev-advanced-section").classList.toggle("ev-advanced-open");t.textContent=s?"Advanced ▲":"Advanced ▼"})}),k.querySelectorAll(".ev-copy-btn").forEach(t=>{t.addEventListener("click",n=>{var a;n.stopPropagation(),(a=navigator.clipboard)==null||a.writeText(t.dataset.copy).then(()=>{t.classList.add("copied"),setTimeout(()=>t.classList.remove("copied"),2e3)})})}),k.querySelectorAll("[data-lookup-id]").forEach(t=>{t.addEventListener("click",n=>{n.stopPropagation(),re(t.dataset.lookupId)})})}}function Xe(e,t){var g,h;const{anchor:n,windowEvents:a,topContributors:s,signatureResult:i,report:o}=e,r=(g=i[0])==null?void 0:g.signature,l=o.confidence,p=ct(n.severity),v=l==="high"?"conf-high":l==="medium"?"conf-medium":"conf-low";return`
    <div class="incident-card">
      <div class="incident-header ${p} incident-toggle">
        <div class="incident-header-left">
          <span class="incident-icon">${(r==null?void 0:r.icon)??'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'}</span>
          <div>
            <div class="incident-title">${(r==null?void 0:r.name)??dt(n)}</div>
            <div class="incident-meta">
              <span class="incident-time">${n.timestamp.toLocaleString()}</span>
              <span class="incident-provider">${u(n.provider)}</span>
              ${o.confidenceReason?`<span class="conf-reason">${u(o.confidenceReason)}</span>`:""}
            </div>
          </div>
        </div>
        <div class="incident-header-right">
          <span class="conf-badge ${v}">${l}</span>
          <span class="event-id-pill" data-lookup-id="${n.id}" title="Look up Event ${n.id}">
            EVT-${n.id}
          </span>
          <span class="incident-chevron">▶</span>
        </div>
      </div>

      <div class="incident-body" hidden>
        <!-- What happened -->
        <div class="incident-section">
          <div class="incident-section-label">What happened</div>
          <p class="incident-text">${u(o.what)}</p>
        </div>

        <!-- Root cause -->
        <div class="incident-section">
          <div class="incident-section-label">Likely root cause</div>
          <p class="incident-text">${u(o.rootCause)}</p>
        </div>

        <!-- Evidence events -->
        ${s.length?`
        <div class="incident-section">
          <div class="incident-section-label">Contributing events (${s.length} found)</div>
          <div class="evidence-list">
            ${s.slice(0,6).map(({event:m,score:b})=>`
              <div class="evidence-wrap">
                <div class="evidence-item">
                  <span class="ev-sev-dot sev-${m.severity.toLowerCase()}"></span>
                  <span class="ev-id" data-lookup-id="${m.id}" title="Look up Event ${m.id}">${m.id}</span>
                  <span class="ev-provider">${u(N(m.provider))}</span>
                  <span class="ev-time">${ve(m.timestamp)}</span>
                  <span class="ev-score" title="Relevance score">${b}</span>
                  <span class="ev-expand-chevron">▶</span>
                </div>
                <div class="evidence-detail" hidden>${ce(m)}</div>
              </div>
            `).join("")}
          </div>
        </div>
        `:""}

        <!-- Timeline -->
        ${a.length?Ye(a,n):""}

        <!-- Next steps -->
        ${o.nextSteps.length?`
        <div class="incident-section">
          <div class="incident-section-label">Suggested next steps</div>
          <ol class="next-steps-list">
            ${o.nextSteps.map(m=>`<li>${u(m)}</li>`).join("")}
          </ol>
        </div>
        `:""}

        <!-- Technician hint -->
        ${o.technicianHint?`
        <div class="incident-section">
          <div class="technician-hint">
            <span class="hint-label">Tech Hint</span>
            <span class="hint-text">${u(o.technicianHint)}</span>
          </div>
        </div>
        `:""}

        <!-- Copy for ticket -->
        <div class="incident-footer">
          <button class="copy-summary-btn" data-summary="${u(o.psaSummary)}">
            Copy for ticket
          </button>
          ${(h=o.alternateSignatures)!=null&&h.length?`
          <span class="alt-signatures">
            Also possible: ${o.alternateSignatures.map(m=>m.signature.name).join(", ")}
          </span>
          `:""}
        </div>
      </div>
    </div>
  `}function Ye(e,t){const n=[...e,t].sort((i,o)=>i.timestamp-o.timestamp),s=n.length>12?[...n.slice(0,6),{_ellipsis:!0,count:n.length-10},...n.slice(-4)]:n;return`
    <div class="incident-section">
      <div class="incident-section-label">Timeline (${e.length} events in ${Qe}-min window)</div>
      <div class="mini-timeline">
        ${s.map(i=>{var r;if(i._ellipsis)return`<div class="timeline-ellipsis">· · · ${i.count} more events · · ·</div>`;const o=i===t;return`
            <div class="timeline-item-wrap">
              <div class="timeline-item ${o?"timeline-anchor":""}">
                <div class="tl-dot sev-${(r=i.severity)==null?void 0:r.toLowerCase()}"></div>
                <div class="tl-content">
                  <span class="tl-time">${ve(i.timestamp)}</span>
                  <span class="tl-id" data-lookup-id="${i.id}" title="Look up Event ${i.id}">${i.id}</span>
                  <span class="tl-provider">${u(N(i.provider))}</span>
                  ${o?'<span class="tl-anchor-label">ANCHOR</span>':""}
                </div>
                <span class="tl-expand-chevron">▶</span>
              </div>
              <div class="timeline-detail" hidden>${ce(i)}</div>
            </div>
          `}).join("")}
      </div>
    </div>
  `}const Qe=15,Je=new Set(["Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting","Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-DistributedCOM","Microsoft-Windows-Security-SPP","Microsoft-Windows-Defrag","Microsoft-Windows-Power-Troubleshooter"]),Y={Critical:0,Error:1,Warning:2,Info:3,Verbose:4},d={sortCol:"timestamp",sortDir:"asc",page:0,pageSize:100,query:"",severities:new Set,providers:new Set,channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set};document.addEventListener("click",e=>{const t=document.getElementById("tbl-provider-panel"),n=document.getElementById("tbl-provider-btn");t&&!t.hidden&&!t.contains(e.target)&&!(n!=null&&n.contains(e.target))&&(t.hidden=!0,n==null||n.classList.remove("open"))});function Ze(e){var m,b;if(!x||!C)return;Object.assign(d,{sortCol:"timestamp",sortDir:"asc",page:0,query:"",severities:new Set,providers:new Set,channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set});const t=[...new Set(e.map(c=>c.provider).filter(Boolean))].sort(),n=[...new Set(e.map(c=>c.channel).filter(Boolean))].sort(),a=c=>c?new Date(c-c.getTimezoneOffset()*6e4).toISOString().slice(0,16):"",s=(m=e[0])==null?void 0:m.timestamp,i=(b=e[e.length-1])==null?void 0:b.timestamp;x.innerHTML=`
    <div class="event-log-filters">
      <input type="search" id="tbl-query" class="filter-control filter-control-search"
        placeholder="Search ID, provider, message…" autocomplete="off" spellcheck="false" />

      <div class="tbl-sev-chips">
        ${["Critical","Error","Warning","Info","Verbose"].map(c=>`
          <label class="sev-chip" data-severity="${c}">
            <input type="checkbox" class="sev-cb tbl-sev-cb" value="${c}" />
            <span class="chip-dot dot-${c}"></span>
            <span>${c}</span>
          </label>`).join("")}
      </div>

      <div class="provider-dropdown" id="tbl-provider-wrap">
        <button class="provider-dropdown-btn" id="tbl-provider-btn" type="button">
          <span id="tbl-provider-label">All providers</span>
          <span class="provider-dropdown-arrow">▾</span>
        </button>
        <div class="provider-dropdown-panel" id="tbl-provider-panel" hidden>
          <div class="provider-panel-header">
            <button class="provider-bulk-btn" id="tbl-provider-select-all" type="button">Select all</button>
            <button class="provider-bulk-btn" id="tbl-provider-clear" type="button">Clear</button>
          </div>
          ${t.length>6?'<input type="search" class="provider-search" id="tbl-provider-search" placeholder="Filter…" autocomplete="off" />':""}
          <div class="provider-option-list">
            ${t.map(c=>`
              <label class="provider-option">
                <input type="checkbox" class="provider-cb" value="${u(c)}" />
                <span class="provider-option-name" title="${u(c)}">${u(N(c))}</span>
              </label>`).join("")}
          </div>
        </div>
      </div>

      <select id="tbl-channel" class="filter-control filter-control-select">
        <option value="">All channels</option>
        ${n.map(c=>`<option value="${u(c)}">${u(c)}</option>`).join("")}
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
  `;const o=(c,y,f)=>{var $;return($=document.getElementById(c))==null?void 0:$.addEventListener(y,f)};o("tbl-query","input",c=>{d.query=c.target.value,d.page=0,S()}),x.querySelectorAll(".tbl-sev-cb").forEach(c=>{c.addEventListener("change",()=>{c.checked?d.severities.add(c.value):d.severities.delete(c.value),c.closest(".sev-chip").classList.toggle("active",c.checked),d.page=0,S()})});const r=document.getElementById("tbl-provider-btn"),l=document.getElementById("tbl-provider-panel"),p=document.getElementById("tbl-provider-label"),v=document.getElementById("tbl-provider-clear"),g=document.getElementById("tbl-provider-select-all");r==null||r.addEventListener("click",c=>{c.stopPropagation();const y=l.hidden;l.hidden=!y,r.classList.toggle("open",y)});function h(){const c=d.providers.size;p.textContent=c===0?"All providers":`${c} provider${c!==1?"s":""}`,r==null||r.classList.toggle("filtered",c>0)}x.querySelectorAll(".provider-cb").forEach(c=>{c.addEventListener("change",()=>{c.checked?d.providers.add(c.value):d.providers.delete(c.value),h(),d.page=0,S()})}),v==null||v.addEventListener("click",c=>{c.stopPropagation(),d.providers.clear(),x.querySelectorAll(".provider-cb").forEach(y=>y.checked=!1),h(),d.page=0,S()}),g==null||g.addEventListener("click",c=>{c.stopPropagation(),x.querySelectorAll(".provider-option:not([hidden]) .provider-cb").forEach(y=>{y.checked=!0,d.providers.add(y.value)}),h(),d.page=0,S()}),o("tbl-provider-search","input",c=>{const y=c.target.value.toLowerCase();x.querySelectorAll(".provider-option").forEach(f=>{f.hidden=y?!f.querySelector(".provider-option-name").textContent.toLowerCase().includes(y):!1})}),o("tbl-channel","change",c=>{d.channel=c.target.value,d.page=0,S()}),o("tbl-from","change",c=>{d.fromTime=c.target.value,d.page=0,S()}),o("tbl-to","change",c=>{d.toTime=c.target.value,d.page=0,S()}),o("tbl-noise","click",c=>{d.hideNoisy=!d.hideNoisy,d.page=0,c.target.classList.toggle("active",d.hideNoisy),c.target.textContent=d.hideNoisy?"Show noise":"Hide noise",S()}),o("tbl-csv","click",()=>tt(ae())),S()}function ae(){const e=d.query.toLowerCase(),t=d.fromTime?new Date(d.fromTime).getTime():null,n=d.toTime?new Date(d.toTime).getTime():null;let a=I.filter(s=>{if(d.severities.size>0&&!d.severities.has(s.severity)||d.providers.size>0&&!d.providers.has(s.provider)||d.channel&&s.channel!==d.channel||t!==null&&s.timestamp<t||n!==null&&s.timestamp>n||d.hideNoisy&&Je.has(s.provider))return!1;if(e){const i=/^\d+$/.test(e)?parseInt(e,10):null;if(i!==null){if(s.id!==i)return!1}else if(!`${s.id} ${s.provider} ${s.channel} ${s.message} ${s.severity}`.toLowerCase().includes(e))return!1}return!0});return a.sort((s,i)=>{let o=0;switch(d.sortCol){case"timestamp":o=s.timestamp-i.timestamp;break;case"severity":o=(Y[s.severity]??9)-(Y[i.severity]??9);break;case"id":o=s.id-i.id;break;case"provider":o=(s.provider||"").localeCompare(i.provider||"");break}return d.sortDir==="asc"?o:-o}),a}function S(){if(!C)return;const e=ae(),t=e.length,n=Math.max(0,Math.ceil(t/d.pageSize)-1);d.page=Math.min(d.page,n);const a=d.page*d.pageSize,s=e.slice(a,a+d.pageSize);if(!t){C.innerHTML='<div class="table-empty">No events match the current filters.</div>';return}const i=l=>`<span class="sort-arrow ${d.sortCol===l?"active":""}">${d.sortCol===l?d.sortDir==="asc"?"↑":"↓":"↕"}</span>`,o=l=>d.sortCol===l?"sort-active":"";C.innerHTML=`
    <div class="table-info-bar">
      <span class="table-count-text">
        ${(a+1).toLocaleString()}–${Math.min(a+d.pageSize,t).toLocaleString()} of ${t.toLocaleString()} event${t!==1?"s":""}
        ${t<I.length?` (${I.length.toLocaleString()} total)`:""}
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
      <tbody>${s.map(l=>et(l)).join("")}</tbody>
    </table>
  `,C.querySelectorAll("th[data-sort]").forEach(l=>{l.addEventListener("click",()=>{const p=l.dataset.sort;d.sortDir=d.sortCol===p&&d.sortDir==="asc"?"desc":"asc",d.sortCol=p,d.page=0,S()})});const r=(l,p)=>{var v;return(v=document.getElementById(l))==null?void 0:v.addEventListener("click",p)};r("pg-first",()=>{d.page=0,S()}),r("pg-prev",()=>{d.page--,S()}),r("pg-next",()=>{d.page++,S()}),r("pg-last",()=>{d.page=n,S()}),C.querySelectorAll("tbody tr[data-record]").forEach(l=>{l.addEventListener("click",p=>{if(p.target.closest(".table-event-id"))return;const v=parseInt(l.dataset.record,10);d.expandedIds.has(v)?d.expandedIds.delete(v):d.expandedIds.add(v),S()})}),C.querySelectorAll(".table-event-id").forEach(l=>{l.addEventListener("click",p=>{p.stopPropagation(),re(l.dataset.lookupId)})}),C.querySelectorAll(".ev-advanced-toggle").forEach(l=>{l.addEventListener("click",p=>{p.stopPropagation();const g=l.closest(".ev-detail-inner").querySelector(".ev-advanced-section").classList.toggle("ev-advanced-open");l.textContent=g?"Advanced ▲":"Advanced ▼"})}),C.querySelectorAll(".ev-copy-btn").forEach(l=>{l.addEventListener("click",p=>{var v;p.stopPropagation(),(v=navigator.clipboard)==null||v.writeText(l.dataset.copy).then(()=>{l.classList.add("copied"),setTimeout(()=>l.classList.remove("copied"),2e3)})})})}function et(e){const t=d.expandedIds.has(e.recordId),n=e.severity.toLowerCase(),a=Object.keys(e.data||{}),s=e.message?u(e.message.substring(0,150))+(e.message.length>150?"…":""):'<span style="color:var(--text3);font-style:italic">no message</span>',i=`
    <tr class="ev-row-${n}${t?" row-expanded":""}" data-record="${e.recordId}">
      <td class="ev-col-expand">${t?"▼":"▶"}</td>
      <td class="ev-col-time">${rt(e.timestamp)}</td>
      <td><span class="sev-badge sev-badge-${n}">${e.severity}</span></td>
      <td><span class="table-event-id" data-lookup-id="${e.id}" title="Look up Event ${e.id}">${e.id}</span></td>
      <td class="ev-col-provider" title="${u(e.provider)}">${u(N(e.provider))}</td>
      <td class="ev-col-channel">${u(e.channel)}</td>
      <td class="ev-col-message">${s}</td>
    </tr>`;if(!t)return i;const o=e.taskName||e.task||null,r=pe(e.opcode,e.opcodeName),l=ue(e.keywords,e.keywordNames),p=de(e.userSID),v=D.get(e.id)||1,g=I.filter(f=>f.recordId!==e.recordId&&Math.abs(f.timestamp-e.timestamp)<=3e4).length,h=[["Time (local)",e.timestamp.toLocaleString()],["Time (UTC)",e.timestamp.toISOString()],["Provider",e.provider],["Channel",e.channel],["Computer",e.computer],["Record ID",e.recordId||null],["User SID",p],["Process ID",e.processId||null],["Thread ID",e.threadId||null],["Activity ID",e.activityId],["Related Act. ID",e.relatedActivityId],["Task",o],["Opcode",r],["Keywords",l]].filter(([,f])=>f),m=[["Raw Level",String(e.levelNum)],["Raw Task",e.task],["Raw Opcode",e.opcode],["Raw Keywords",e.keywords],["Version",e.version],["Qualifiers",e.qualifiers],["Provider Desc.",e.providerDescription]].filter(([,f])=>f),b=le(e.message),c=b?`<div class="ev-detail-message-wrap">
        <div class="ev-detail-message">${u(b)}</div>
        <button class="ev-copy-btn" data-copy="${u(e.message)}" title="Copy message">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        </button>
       </div>`:`<div class="ev-detail-message ev-no-message">
        Message not rendered — Windows message templates are stored on the source machine.
        Export directly from the affected computer to see full event messages.
       </div>`,y=e.dataAnon||[];return i+`
    <tr class="ev-detail-row">
      <td colspan="7">
        <div class="ev-detail-inner">
          ${v>1||g>0?`
          <div class="ev-occurrence-bar">
            ${v>1?`Event ${e.id} appears <strong>${v}×</strong> in this log`:""}
            ${v>1&&g>0?" &nbsp;·&nbsp; ":""}
            ${g>0?`<strong>${g}</strong> other event${g!==1?"s":""} within ±30s`:""}
          </div>`:""}
          ${c}
          <div class="ev-detail-meta">
            ${h.map(([f,$])=>`
              <div class="ev-detail-field">
                <span class="ev-detail-key">${f}</span>
                <span class="ev-detail-val">${u(String($))}</span>
              </div>`).join("")}
          </div>
          ${a.length||y.length?`
          <div class="ev-detail-data">
            <div class="ev-detail-data-title">Event Data</div>
            ${a.map(f=>`
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key">${u(f)}</span>
                <span class="ev-detail-data-val">${u(String(e.data[f]))}</span>
              </div>`).join("")}
            ${y.map((f,$)=>`
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key ev-detail-data-key--anon">[${$}]</span>
                <span class="ev-detail-data-val">${u(String(f))}</span>
              </div>`).join("")}
          </div>`:""}
          <div class="ev-detail-actions">
            <span class="ev-detail-lookup-btn table-event-id" data-lookup-id="${e.id}">
              Look up Event ${e.id} →
            </span>
            ${m.length?'<button class="ev-advanced-toggle">Advanced ▼</button>':""}
          </div>
          ${m.length?`
          <div class="ev-advanced-section">
            <div class="ev-detail-data-title">Advanced / Raw</div>
            ${m.map(([f,$])=>`
              <div class="ev-detail-field">
                <span class="ev-detail-key">${f}</span>
                <span class="ev-detail-val">${u(String($))}</span>
              </div>`).join("")}
          </div>`:""}
        </div>
      </td>
    </tr>`}function tt(e){const t=["Time (UTC)","Severity","EventID","Provider","Channel","Computer","RecordID","ProcessID","ThreadID","UserSID","ActivityID","RelatedActivityID","Task","TaskName","Opcode","OpcodeName","Keywords","KeywordNames","Version","Qualifiers","ProviderDescription","Message","EventData","EventDataAnon"],n=r=>`"${String(r??"").replace(/"/g,'""').replace(/\r?\n/g," ")}"`,a=e.map(r=>[r.timestamp.toISOString(),r.severity,r.id,n(r.provider),n(r.channel),n(r.computer),r.recordId,r.processId||"",r.threadId||"",n(r.userSID),n(r.activityId),n(r.relatedActivityId),n(r.task),n(r.taskName),n(r.opcode),n(r.opcodeName),n(r.keywords),n((r.keywordNames||[]).join("; ")),n(r.version),n(r.qualifiers),n(r.providerDescription),n(r.message),n(Object.entries(r.data||{}).map(([l,p])=>`${l}=${p}`).join("; ")),n((r.dataAnon||[]).join("; "))].join(",")),s=[t.join(","),...a].join(`\r
`),i=URL.createObjectURL(new Blob([s],{type:"text/csv;charset=utf-8;"})),o=Object.assign(document.createElement("a"),{href:i,download:`eventful-${new Date().toISOString().slice(0,10)}.csv`});document.body.appendChild(o),o.click(),document.body.removeChild(o),URL.revokeObjectURL(i)}function re(e){const t=parseInt(e,10),n=document.getElementById("lookup-panel"),a=document.getElementById("lp-body");if(!n||!a)return;const s=ke.find(o=>o.id===t),i=I.filter(o=>o.id===t);a.innerHTML=nt(t,s,i),n.hidden=!1,a.querySelectorAll(".lp-copy-ps").forEach(o=>{o.addEventListener("click",()=>{navigator.clipboard.writeText(o.dataset.code).then(()=>{o.textContent="Copied!",setTimeout(()=>{o.textContent="Copy"},2e3)})})}),a.querySelectorAll(".lp-show-in-log").forEach(o=>{o.addEventListener("click",()=>{const r=o.dataset.filterId;R(),document.querySelectorAll(".analyzer-tab").forEach(v=>v.classList.remove("active"));const l=document.querySelector('.analyzer-tab[data-tab="events"]');l&&l.classList.add("active"),document.getElementById("incidents-section").hidden=!0,document.getElementById("events-panel").hidden=!1,d.query=r,d.page=0;const p=document.getElementById("tbl-query");p&&(p.value=r),S()})})}function R(){const e=document.getElementById("lookup-panel");e&&(e.hidden=!0)}function nt(e,t,n){var s,i,o;const a=n.length?`<button class="lp-show-in-log" data-filter-id="${e}">Show all ${n.length} occurrence${n.length!==1?"s":""} in All Events →</button>`:"";if(t){const r=((s=t.severity)==null?void 0:s.toLowerCase())??"info";return`
      <div class="lp-section">
        <div class="lp-section-label">Knowledge Base</div>
        <div class="lp-doc-header">
          <span class="lp-id-badge">${e}</span>
          <div>
            <div class="lp-doc-title">${u(t.title)}</div>
            <div class="lp-doc-meta">
              <span class="sev-badge sev-badge-${r}">${u(t.severity)}</span>
              <span class="lp-channel">${u(t.channel||t.source||"")}</span>
            </div>
          </div>
        </div>
        <p class="lp-description">${u(t.description||t.short_desc||"")}</p>
        ${(i=t.causes)!=null&&i.length?`
          <div class="lp-subsection-label">Causes</div>
          <ul class="lp-causes">
            ${t.causes.map(l=>`<li>${u(l)}</li>`).join("")}
          </ul>`:""}
        ${(o=t.steps)!=null&&o.length?`
          <div class="lp-subsection-label">Investigation Steps</div>
          <ol class="lp-steps">
            ${t.steps.map(l=>`<li>${u(l)}</li>`).join("")}
          </ol>`:""}
        ${t.powershell?`
          <div class="lp-subsection-label">PowerShell</div>
          <div class="lp-ps-block">
            <pre>${u(t.powershell)}</pre>
            <button class="lp-copy-ps" data-code="${u(t.powershell)}">Copy</button>
          </div>`:""}
        <div class="lp-doc-footer">
          <a href="results.html?q=${e}" target="_blank" rel="noopener" class="lp-full-docs-btn">
            Open full docs →
          </a>
          ${a}
        </div>
      </div>`}return`
    <div class="lp-section">
      <div class="lp-section-label">Knowledge Base</div>
      <div class="lp-no-doc-state">
        <div class="lp-no-doc-title">No documentation for Event ${e}</div>
        <div class="lp-no-doc-sub">This event ID is not in the Eventful knowledge base.</div>
      </div>
      ${a}
    </div>`}function ce(e){const t=e.taskName||e.task||null,n=pe(e.opcode,e.opcodeName),a=ue(e.keywords,e.keywordNames),s=de(e.userSID),i=e.dataAnon||[],o=Object.keys(e.data||{}),r=D.get(e.id)||1,l=I.filter(h=>h.recordId!==e.recordId&&Math.abs(h.timestamp-e.timestamp)<=3e4).length,p=le(e.message),v=[["Time (local)",e.timestamp.toLocaleString()],["Time (UTC)",e.timestamp.toISOString()],["Provider",e.provider],["Channel",e.channel],["Computer",e.computer],["Record ID",e.recordId||null],["User SID",s],["Process ID",e.processId||null],["Thread ID",e.threadId||null],["Activity ID",e.activityId],["Task",t],["Opcode",n],["Keywords",a]].filter(([,h])=>h),g=[["Raw Level",String(e.levelNum)],["Raw Task",e.task],["Raw Opcode",e.opcode],["Raw Keywords",e.keywords],["Version",e.version]].filter(([,h])=>h);return`
    <div class="ev-inline-detail">
      ${r>1||l>0?`
      <div class="ev-occurrence-bar">
        ${r>1?`Event ${e.id} fired <strong>${r}×</strong> in this log`:""}
        ${r>1&&l>0?" &nbsp;·&nbsp; ":""}
        ${l>0?`<strong>${l}</strong> other event${l!==1?"s":""} within ±30s`:""}
      </div>`:""}
      ${p?`<div class="ev-detail-message-wrap">
             <div class="ev-detail-message">${u(p)}</div>
             <button class="ev-copy-btn" data-copy="${u(e.message)}" title="Copy message">
               <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
             </button>
           </div>`:'<div class="ev-detail-message ev-no-message">Message not rendered — Windows message templates are stored on the source machine. Export from the affected computer to see full messages.</div>'}
      <div class="ev-inline-grid">
        <div class="ev-detail-meta">
          ${v.map(([h,m])=>`
            <div class="ev-detail-field">
              <span class="ev-detail-key">${h}</span>
              <span class="ev-detail-val">${u(String(m))}</span>
            </div>`).join("")}
        </div>
        ${o.length||i.length?`
        <div class="ev-detail-data">
          <div class="ev-detail-data-title">Event Data</div>
          ${o.map(h=>`
            <div class="ev-detail-data-row">
              <span class="ev-detail-data-key">${u(h)}</span>
              <span class="ev-detail-data-val">${u(String(e.data[h]))}</span>
            </div>`).join("")}
          ${i.map((h,m)=>`
            <div class="ev-detail-data-row">
              <span class="ev-detail-data-key ev-detail-data-key--anon">[${m}]</span>
              <span class="ev-detail-data-val">${u(String(h))}</span>
            </div>`).join("")}
        </div>`:""}
      </div>
      <div class="ev-detail-actions">
        <span class="ev-detail-lookup-btn" data-lookup-id="${e.id}">Look up Event ${e.id} →</span>
        ${g.length?'<button class="ev-advanced-toggle">Advanced ▼</button>':""}
      </div>
      ${g.length?`
      <div class="ev-advanced-section">
        <div class="ev-detail-data-title">Advanced / Raw</div>
        ${g.map(([h,m])=>`
          <div class="ev-detail-field">
            <span class="ev-detail-key">${h}</span>
            <span class="ev-detail-val">${u(String(m))}</span>
          </div>`).join("")}
      </div>`:""}
    </div>`}const st={"S-1-1-0":"Everyone","S-1-5-7":"Anonymous","S-1-5-18":"SYSTEM","S-1-5-19":"LOCAL SERVICE","S-1-5-20":"NETWORK SERVICE","S-1-5-32-544":"Administrators","S-1-5-32-545":"Users","S-1-5-32-546":"Guests"};function de(e){if(!e)return null;const t=st[e];return t?`${t} (${e})`:e}const it={2:"The system cannot find the file specified",3:"The system cannot find the path specified",5:"Access is denied",32:"The process cannot access the file because it is being used by another process",1053:"The service did not respond to the start or control request in a timely fashion",1055:"The service database is locked",1056:"An instance of the service is already running",1058:"The service cannot be started — it is disabled or has no enabled devices associated with it",1060:"The specified service does not exist as an installed service",1061:"The service cannot accept control messages at this time",1067:"The process terminated unexpectedly",1068:"The dependency service or group failed to start",1069:"The service did not start due to a logon failure",1072:"The specified service has been marked for deletion",1073:"The specified service already exists",1326:"Logon failure: unknown user name or bad password"};function le(e){return e&&e.replace(/%%(\d+)/g,(t,n)=>{const a=it[+n];return a?`${a} (%%${n})`:t})}const ot={0:"Info",1:"Start",2:"Stop",3:"DC Start",4:"DC Stop",5:"Extension",6:"Reply",7:"Resume",8:"Suspend",9:"Send",240:"Disconnect",241:"Connect"};function pe(e,t){return t||(e==null||e===""?null:ot[String(e)]||String(e))}const at={"0x8000000000000000":"Audit Failure","0x4000000000000000":"Audit Success","0x8080000000000000":"Classic, Audit Failure","0x4080000000000000":"Classic, Audit Success","0x0080000000000000":"Classic","0x0000000000000000":"None"};function ue(e,t){return t!=null&&t.length?t.join(", "):e?at[e.toLowerCase()]??e:null}function Q(e){const t=w==null?void 0:w.querySelector(".upload-error");t&&t.remove();const n=document.createElement("div");n.className="upload-error",n.textContent=e,w==null||w.appendChild(n),M(L)}function u(e){return e?String(e).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"):""}function N(e){return e?e.replace(/^Microsoft-Windows-/i,"").replace(/^Microsoft-/i,""):"—"}function ve(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}function rt(e){return e.toLocaleString([],{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})}function ct(e){return`sev-header-${(e==null?void 0:e.toLowerCase())??"info"}`}function dt(e){return{41:"Unexpected System Reboot",6008:"Unexpected Shutdown Detected",1001:"System Crash (BSOD)",1e3:"Application Crash",7024:"Critical Service Failure"}[e.id]??`Event ${e.id}`}
