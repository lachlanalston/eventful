import{s as be}from"./theme-BUo633SF.js";/* empty css                 */import{f as P,e as u,a as $e}from"./utils-BVYqMEs_.js";function ke(e){const n=new DOMParser().parseFromString(e,"text/xml"),a=n.querySelector("parsererror");if(a)throw new Error(`Invalid XML: ${a.textContent.substring(0,120)}`);const s=n.querySelectorAll("Event");if(s.length===0)throw new Error("No <Event> elements found. Make sure you exported in XML format from Event Viewer.");const i=[];for(const o of s)try{const r=Ee(o);!isNaN(r.id)&&r.id>0&&r.timestamp instanceof Date&&!isNaN(r.timestamp)&&i.push(r)}catch{}if(i.length===0)throw new Error("No valid events could be parsed. Check that the XML is a Windows Event Viewer export.");return i.sort((o,r)=>o.timestamp-r.timestamp)}function Ee(e){var j,H,_,V,K,G,z,F,X;const t=e.querySelector("System"),n=parseInt(I(t,"EventID"),10),a=parseInt(I(t,"Level"),10),s=t==null?void 0:t.querySelector("Provider"),i=(s==null?void 0:s.getAttribute("Name"))||(s==null?void 0:s.getAttribute("EventSourceName"))||"",o=I(t,"Channel"),r=I(t,"Computer"),d=parseInt(I(t,"EventRecordID"),10),p=t==null?void 0:t.querySelector("TimeCreated"),h=(p==null?void 0:p.getAttribute("SystemTime"))||(p==null?void 0:p.textContent)||"",g=new Date(h),m=t==null?void 0:t.querySelector("Execution"),v=t==null?void 0:t.querySelector("Correlation"),k=t==null?void 0:t.querySelector("Security"),w=e.querySelector("RenderingInfo"),l=(H=(j=w==null?void 0:w.querySelector("Level"))==null?void 0:j.textContent)==null?void 0:H.trim(),f=xe(a,l),$=((V=(_=w==null?void 0:w.querySelector("Task"))==null?void 0:_.textContent)==null?void 0:V.trim())||"",b=((G=(K=w==null?void 0:w.querySelector("Opcode"))==null?void 0:K.textContent)==null?void 0:G.trim())||"",A=[...(w==null?void 0:w.querySelectorAll("Keywords > Keyword"))??[]].map(Se=>Se.textContent.trim()).filter(Boolean),T=((F=(z=w==null?void 0:w.querySelector("Provider"))==null?void 0:z.textContent)==null?void 0:F.trim())||"",ge=Ce(e,w),{named:we,anon:ye}=Ie(e);return{id:n,provider:i,channel:o,levelNum:a,severity:f,timestamp:g,computer:r,message:ge,recordId:isNaN(d)?0:d,processId:parseInt(m==null?void 0:m.getAttribute("ProcessID"),10)||0,threadId:parseInt(m==null?void 0:m.getAttribute("ThreadID"),10)||0,activityId:(v==null?void 0:v.getAttribute("ActivityID"))||"",relatedActivityId:(v==null?void 0:v.getAttribute("RelatedActivityID"))||"",userSID:(k==null?void 0:k.getAttribute("UserID"))||"",task:I(t,"Task"),opcode:I(t,"Opcode"),keywords:I(t,"Keywords"),taskName:$,opcodeName:b,keywordNames:A,providerDescription:T,version:I(t,"Version"),qualifiers:((X=t==null?void 0:t.querySelector("EventID"))==null?void 0:X.getAttribute("Qualifiers"))||"",data:we,dataAnon:ye}}function I(e,t){var n,a;return((a=(n=e==null?void 0:e.querySelector(t))==null?void 0:n.textContent)==null?void 0:a.trim())||""}function Ce(e,t){var i,o;const n=(o=(i=t==null?void 0:t.querySelector("Message"))==null?void 0:i.textContent)==null?void 0:o.trim();if(n)return n;const a=e.querySelector("EventData");if(a){const r=[];for(const d of a.querySelectorAll("Data")){const p=d.getAttribute("Name"),h=d.textContent.trim();h&&h!=="-"&&r.push(p?`${p}: ${h}`:h)}if(r.length)return r.join(" | ")}const s=e.querySelector("UserData");return s?s.textContent.trim():""}function Ie(e){const t={},n=[],a=e.querySelector("EventData");if(!a)return{named:t,anon:n};for(const s of a.querySelectorAll("Data")){const i=s.getAttribute("Name"),o=s.textContent.trim();i?o&&(t[i]=o):o&&n.push(o)}return{named:t,anon:n}}function xe(e,t){if(t){const n=t.toLowerCase();if(n.includes("critical"))return"Critical";if(n.includes("error"))return"Error";if(n.includes("warning"))return"Warning";if(n.includes("information"))return"Info";if(n.includes("verbose"))return"Verbose";if(n.includes("audit"))return t.includes("Failure")?"Error":"Info"}switch(e){case 1:return"Critical";case 2:return"Error";case 3:return"Warning";case 4:return"Info";case 5:return"Verbose";case 0:return"Info";default:return"Info"}}const De=new Set([41,6008,1001,1e3,7024]),Y={7:40,11:30,51:40,52:30,55:35,57:25,129:20,153:20,4101:50,1001:45,1e3:35,1002:30,1026:20,7031:25,7034:25,7022:20,7023:20,7001:15,7011:15,1014:20,4202:20,4201:15,17:50,18:40,19:30,4625:10,4740:15},Ae=new Set(["Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting"]),Me=[{id:"gpu-driver-crash",name:"GPU Driver Crash",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',category:"Hardware Driver",test(e){const t=["nvlddmkm","amdkmdag","amd","igdkmd","dxgkrnl","atikmdag"],n=e.some(s=>s.id===4101),a=e.find(s=>t.some(i=>{var o;return(o=s.provider)==null?void 0:o.toLowerCase().includes(i)}));return n?{match:!0,confidence:"high",reason:"Event 4101 (display driver TDR timeout) found in window"}:a?{match:!0,confidence:"medium",reason:`GPU provider "${a.provider}" found in window — no Event 4101`}:{match:!1}},what:"The graphics card driver stopped responding and Windows could not recover it.",rootCause:"Display driver (TDR timeout) caused the system to become unresponsive.",nextSteps:["Update or roll back GPU drivers via Device Manager → Display Adapters","Use DDU (Display Driver Uninstaller) in Safe Mode for clean reinstall","Monitor GPU temperatures under load with GPU-Z or HWiNFO64","Run GPU stability test with FurMark or 3DMark","Check GPU power connector seating if system is recently assembled"],technicianHint:'NVIDIA: look for "nvlddmkm" in Event 4101 faulting module. AMD: "atikmpag" or "amdkmdag". DDU clean reinstall resolves driver corruption in ~70% of cases. If temps are fine and fresh driver fails, suspect hardware.'},{id:"disk-failure",name:"Storage / Disk Error",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/></svg>',category:"Storage",test(e){const t=[7,11,51,52,55,57,129,153],n=["disk","atapi","nvme","storport","ntfs","fastfat","stornvme"],a=e.filter(i=>t.includes(i.id)||n.some(o=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(o)})),s=[...new Set(a.map(i=>i.id))].join(", ");return a.length>=3?{match:!0,confidence:"high",reason:`${a.length} disk error events in window (IDs: ${s})`}:a.length>=1?{match:!0,confidence:"medium",reason:`${a.length} disk error event in window (ID: ${s})`}:{match:!1}},what:"The storage device reported I/O errors before the incident.",rootCause:"Disk hardware errors were detected — possible drive failure, bad sectors, or controller issue.",nextSteps:["Run CrystalDiskInfo — check SMART reallocated/pending/uncorrectable sectors","Run chkdsk /f /r /x on affected volume","Run manufacturer disk diagnostic (SeaTools, WD Dashboard, Samsung Magician)","Check SATA/power cable connections","Consider imaging and replacing drive if SMART shows degradation"],technicianHint:"Event 7 = hardware error from disk.sys. Event 51 = error during paging (system swapping to bad sectors — urgent). Event 55 = NTFS filesystem corruption. Multiple Event 7 in a short window usually means imminent failure."},{id:"bsod-kernel-crash",name:"Blue Screen of Death (BSOD)",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',category:"Kernel Crash",test(e,t){return t.id===1001?{match:!0,confidence:"high",reason:"Event 1001 (BugCheck) is the anchor — BSOD confirmed"}:e.some(n=>n.id===1001)?{match:!0,confidence:"high",reason:"Event 1001 (BugCheck/BSOD) found in window events"}:{match:!1}},what:"Windows detected an unrecoverable kernel error and created a memory dump.",rootCause:"A kernel or driver-level fault caused Windows to stop to prevent data corruption.",nextSteps:["Note the BugCheck code from Event 1001 details","Analyse minidump with WhoCrashed (free) or WinDbg (!analyze -v)","Run SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth","Run Windows Memory Diagnostic for MEMORY_MANAGEMENT (0x1A) stops","Update all drivers — especially GPU, NIC, and chipset"],technicianHint:"Common stop codes: 0x50 PAGE_FAULT (bad RAM or driver), 0x3B SYSTEM_SERVICE_EXCEPTION (driver), 0x1A MEMORY_MANAGEMENT (RAM), 0x7E SYSTEM_THREAD_EXCEPTION (driver), 0x0A IRQL_NOT_LESS_OR_EQUAL (driver/RAM). WhoCrashed gives the culprit driver in seconds."},{id:"service-crash-chain",name:"Service Crash Loop",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',category:"Windows Services",test(e){const t=[7031,7034,7022,7023,7024,7001,7011],n=e.filter(s=>t.includes(s.id)),a=[...new Set(n.map(s=>s.id))].join(", ");return n.length>=5?{match:!0,confidence:"high",reason:`${n.length} service failure events in window (IDs: ${a})`}:n.length>=2?{match:!0,confidence:"medium",reason:`${n.length} service failure events in window (IDs: ${a})`}:{match:!1}},what:"One or more Windows services crashed or failed to start repeatedly.",rootCause:"Service instability — possibly caused by a failed update, corrupted binary, or missing dependency.",nextSteps:["Identify which service(s) crashed from the event messages","Check service recovery settings: Services → right-click service → Properties → Recovery","Verify the service executable exists and is not corrupted","Check for related Application log events (Event 1000) for the service host","Review recent Windows Updates that may have changed the service"],technicianHint:"Event 7031 = service terminated unexpectedly (count tells you how many times). Event 7034 = crashed without telling SCM. The service name is in the event message. If it's svchost-hosted, check the service group."},{id:"application-crash-loop",name:"Application Crash Loop",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',category:"Application",test(e){const t=e.filter(n=>n.id===1e3);return t.length>=3?{match:!0,confidence:"high",reason:`${t.length} Event 1000 (application crash) in window`}:t.length>=1?{match:!0,confidence:"medium",reason:"1 Event 1000 (application crash) in window"}:{match:!1}},what:"An application was crashing repeatedly before the incident.",rootCause:"Application instability — possible corrupt installation, missing runtime, or incompatible update.",nextSteps:["Identify the crashing application from the Event 1000 message","Note the faulting module — it often identifies a specific DLL","Update or reinstall the application","Install/repair Visual C++ Redistributables if a runtime DLL faults","Check crash dumps in %LocalAppData%\\CrashDumps or the application's folder"],technicianHint:'The faulting module in Event 1000 is gold — "ntdll.dll" = OS issue or heap corruption, "msvcp140.dll" / "vcruntime140.dll" = missing C++ runtime, "AppName.exe" itself = bad binary. Repeated same app + same module = deterministic, reproducible fault.'},{id:"memory-hardware",name:"Memory / RAM Issue",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/></svg>',category:"Hardware",test(e){const t=["microsoft-windows-memoryd","whea-logger","microsoft-windows-whea"],n=[17,18,19,1],a=e.find(i=>n.includes(i.id)||t.some(o=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(o)}));return e.some(i=>{var o,r;return i.id===1001&&(((o=i.data)==null?void 0:o.BugcheckCode)==="26"||((r=i.data)==null?void 0:r.BugcheckCode)==="80")})?{match:!0,confidence:"medium",reason:"BSOD stop code indicates memory fault (0x1A MEMORY_MANAGEMENT or 0x50 PAGE_FAULT)"}:a?{match:!0,confidence:"medium",reason:`Memory/WHEA event detected (Event ${a.id} from ${a.provider||"unknown provider"})`}:{match:!1}},what:"Hardware memory errors or RAM-related faults were detected.",rootCause:"Defective or misconfigured RAM caused uncorrectable memory errors.",nextSteps:["Run MemTest86+ overnight (at least 2 passes)","Test RAM sticks one at a time to isolate the faulty module","Reseat RAM modules and clean contacts","Check XMP/EXPO profile stability — reset to JEDEC spec in BIOS","Check WHEA-Logger events for corrected/uncorrected error counts"],technicianHint:`WHEA Event 17/18/19 = hardware error framework caught a hardware error. Check the ErrorSource field — "MCE" (Machine Check Exception) = hardware fault, usually RAM or CPU. MemTest86+ is the definitive test. Don't trust Windows Memory Diagnostic for subtle faults.`},{id:"unexpected-power",name:"Unexpected Power Loss",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',category:"Power",test(e,t){var n;return t.id===41&&((n=t.data)==null?void 0:n.BugcheckCode)==="0"?{match:!0,confidence:"high",reason:"Event 41 BugcheckCode=0 — hard power loss confirmed (not a software crash)"}:(t.id===41||t.id===6008)&&e.length<=3?{match:!0,confidence:"medium",reason:`Only ${e.length} event(s) before anchor — abrupt stop, no software lead-up`}:{match:!1}},what:"The system lost power without going through a normal shutdown.",rootCause:"Hard power loss — possible PSU failure, power outage, or UPS failure.",nextSteps:["Check UPS health, battery test, and log — replace battery if > 3 years old","Test PSU voltage rails with PC Power Supply Tester or multimeter","Check power outlet and surge protector for faults","Review Event 41 BugcheckCode: 0 = power loss, non-0 = software crash","Install UPS with AVR if not present — protects against brownouts"],technicianHint:"Event 41 BugcheckCode=0 is definitive: the machine lost power while running (no BSOD, no clean shutdown). Very few preceding events confirms sudden loss. Multiple occurrences = PSU is failing. Check 12V rail — HDD-heavy systems are sensitive."},{id:"network-failure",name:"Network / Connectivity Failure",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',category:"Network",test(e){const t=[1014,4202,4201,6100],n=["tcpip","dns-client","dhcp","netbt","netlogon","rras"],a=e.filter(i=>t.includes(i.id)||n.some(o=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(o)})),s=[...new Set(a.map(i=>i.id))].join(", ");return a.length>=3?{match:!0,confidence:"medium",reason:`${a.length} network/DNS events in window (IDs: ${s})`}:a.length>=1?{match:!0,confidence:"low",reason:`1 network/DNS event in window (ID: ${s})`}:{match:!1}},what:"Network or DNS errors were recorded in the period leading up to the incident.",rootCause:"Network connectivity failure caused application or service faults.",nextSteps:["Check NIC driver version — update if outdated",'Disable NIC power management: Device Manager → NIC → Power Management → uncheck "Allow computer to turn off"',"Test DNS resolution: nslookup google.com","Review DHCP lease renewal logs","Check switch port, cable, and NIC hardware"],technicianHint:"Event 1014 = DNS client resolver timeout. If you see it, look at the DNS server IP in the event — a failing DC or DNS server is a common cause. Event 4201/4202 = NIC connection state changes = intermittent cable or switch issue."}],Te=15,Le={Critical:30,Error:20,Warning:10,Info:2,Verbose:0};function Re(e){var r;if(!e.length)return{incidents:[],healthScore:100,computerName:"",stats:je()};const t=((r=e[0])==null?void 0:r.computer)||"",n=oe(e),a=Ne(e),s=[];for(const d of a){const p=Pe(e,d,Te),g=Be(p,d).slice(0,8),m=Oe(p,d),v=qe(d,m,g);s.push({anchor:d,windowEvents:p,topContributors:g,signatureResult:m,report:v})}const i=_e(s),o=He(e,i);return{incidents:i,healthScore:o,computerName:t,stats:n}}function Ne(e){const t=[],n=new Set;for(const a of e){if(!De.has(a.id))continue;const s=`${a.id}-${Math.floor(a.timestamp/3e4)}`;n.has(s)||(n.add(s),t.push(a))}return t.sort((a,s)=>s.timestamp-a.timestamp).slice(0,5)}function Pe(e,t,n){const a=t.timestamp-n*6e4;return e.filter(s=>s.timestamp>=a&&s.timestamp<t.timestamp)}function Be(e,t){const n=e.map(s=>{let i=Le[s.severity]??0;Y[s.id]&&(i+=Y[s.id]),s.provider&&t.provider&&s.provider===t.provider&&(i+=8),Ae.has(s.provider)&&(i=Math.max(0,i-15));const o=(t.timestamp-s.timestamp)/6e4;return o<2?i+=10:o<5&&(i+=5),{event:s,score:i}}),a=new Map;for(const{event:s}of n){const i=`${s.id}-${s.provider}`;a.set(i,(a.get(i)||0)+1)}for(const s of n){const i=`${s.event.id}-${s.event.provider}`,o=a.get(i)||1;o>=5?s.score+=15:o>=3?s.score+=8:o>=2&&(s.score+=4)}return n.filter(({score:s})=>s>0).sort((s,i)=>i.score-s.score).map(({event:s,score:i})=>({event:s,score:i}))}function Oe(e,t){const n=[];for(const s of Me)try{const i=s.test(e,t);i.match&&n.push({signature:s,confidence:i.confidence,reason:i.reason||""})}catch{}const a={high:0,medium:1,low:2};return n.sort((s,i)=>(a[s.confidence]??3)-(a[i.confidence]??3)),n}function qe(e,t,n,a){const s=t[0],i=s==null?void 0:s.signature,o=(s==null?void 0:s.confidence)??"low",r=(s==null?void 0:s.reason)||"",d=ie[e.id]??`Event ${e.id}`,p=(i==null?void 0:i.what)??`${d} occurred at ${P(e.timestamp)}.`,h=(i==null?void 0:i.rootCause)??We(e,n),g=(i==null?void 0:i.nextSteps)??["Review event details for more information","Check System and Application logs for context"],m=i==null?void 0:i.technicianHint,v=Ue(e,i,n,o,r);return{what:p,rootCause:h,confidence:o,confidenceReason:r,nextSteps:g,technicianHint:m,psaSummary:v,alternateSignatures:t.slice(1,3),evidenceCount:n.length}}const ie={41:"Unexpected system reboot (Kernel-Power)",6008:"Unexpected previous shutdown (EventLog)",1001:"System crash / BSOD (BugCheck)",1e3:"Application crash (Application Error)",7024:"Critical service failure"};function We(e,t){if(!t.length)return"No significant preceding events identified in the lookback window.";const n=t[0].event;return`Leading event: ${n.provider||"Unknown"} Event ${n.id} (${n.severity}) recorded shortly before the incident.`}function Ue(e,t,n,a,s){return["INCIDENT SUMMARY","================",`Date/Time: ${e.timestamp.toLocaleString()}`,`Anchor Event: ${e.id} — ${ie[e.id]??"Unknown"}`,`Provider: ${e.provider||"Unknown"}`,`Computer: ${e.computer||"Unknown"}`,"","DIAGNOSIS","---------",t?`Pattern: ${t.name} (${t.category})`:"Pattern: No known pattern matched",`Confidence: ${a.toUpperCase()}${s?` — ${s}`:""}`,"",t?`What happened: ${t.what}`:"",t?`Root cause: ${t.rootCause}`:"","",`CONTRIBUTING EVENTS (top ${Math.min(n.length,5)})`,"------------------",...n.slice(0,5).map(({event:r})=>`  [${r.severity}] Event ${r.id} — ${r.provider||"Unknown"} @ ${P(r.timestamp)}`),"","SUGGESTED NEXT STEPS","--------------------",...((t==null?void 0:t.nextSteps)??["Review event log for more context"]).map(r=>`  • ${r}`),"","Generated by Eventful Incident Analyzer"].filter(r=>r!==void 0).join(`
`)}function oe(e){const t={Critical:0,Error:0,Warning:0,Info:0,Verbose:0};for(const n of e)t[n.severity]=(t[n.severity]||0)+1;return{total:e.length,...t}}function je(){return{total:0,Critical:0,Error:0,Warning:0,Info:0,Verbose:0}}function He(e,t){let n=100;const a=oe(e);n-=Math.min(a.Critical*15,40),n-=Math.min(a.Error*3,25),n-=Math.min(a.Warning*.5,10),n-=t.length*12;for(const s of t)s.report.confidence==="high"?n-=8:s.report.confidence==="medium"&&(n-=4);return Math.max(0,Math.min(100,Math.round(n)))}function _e(e){const t=new Set;return e.filter(n=>{const a=`${n.anchor.id}-${Math.floor(n.anchor.timestamp/1e3)}`;return t.has(a)?!1:(t.add(a),!0)})}be();const B=document.getElementById("upload-section"),ae=document.getElementById("processing-section"),re=document.getElementById("results-section"),y=document.getElementById("drop-zone"),L=document.getElementById("file-input"),Q=document.getElementById("processing-text"),J=document.getElementById("overview-grid"),E=document.getElementById("incidents-section"),x=document.getElementById("event-table-wrap"),D=document.getElementById("event-log-filters-wrap"),W=document.getElementById("new-analysis-btn"),Z=document.getElementById("results-sub");let C=[],M=new Map;L==null||L.addEventListener("change",e=>{var n;const t=(n=e.target.files)==null?void 0:n[0];t&&ce(t)});y==null||y.addEventListener("dragover",e=>{e.preventDefault(),y.classList.add("drag-over")});y==null||y.addEventListener("dragleave",()=>y.classList.remove("drag-over"));y==null||y.addEventListener("drop",e=>{var n;e.preventDefault(),y.classList.remove("drag-over");const t=(n=e.dataTransfer.files)==null?void 0:n[0];t&&ce(t)});W==null||W.addEventListener("click",Ve);var ne;(ne=document.getElementById("lp-backdrop"))==null||ne.addEventListener("click",O);var se;(se=document.getElementById("lp-close"))==null||se.addEventListener("click",O);document.addEventListener("keydown",e=>{e.key==="Escape"&&O()});async function ce(e){if(!e.name.toLowerCase().endsWith(".xml")&&e.type!=="text/xml"&&e.type!=="application/xml"){te("Please upload an XML file exported from Windows Event Viewer.");return}N(`Reading ${e.name}…`);try{const t=await e.text();N("Parsing events…"),await U();const n=ke(t);N(`Analysing ${n.length.toLocaleString()} events…`),await U();const a=Re(n);C=n,M=new Map;for(const s of n)M.set(s.id,(M.get(s.id)||0)+1);N("Building report…"),await U(),Ke(a,e.name)}catch(t){te(t.message||"Failed to parse file."),R(B)}}function U(){return new Promise(e=>setTimeout(e,16))}function R(e){[B,ae,re].forEach(t=>{t&&(t.hidden=!0)}),e&&(e.hidden=!1)}function N(e){Q&&(Q.textContent=e),R(ae)}function Ve(){C=[],M=new Map,L&&(L.value=""),R(B)}function Ke(e,t){const{incidents:n,healthScore:a,computerName:s,stats:i}=e,o=document.querySelector(".results-title");if(o&&(o.textContent=t.replace(/\.xml$/i,"")),Z){const p=[];s&&p.push(s),p.push(`${i.total.toLocaleString()} events`),n.length&&p.push(`${n.length} incident${n.length!==1?"s":""} detected`),Z.textContent=p.join(" · ")}Ge(a,i),ze(n),Qe(C);const r=document.getElementById("tab-inc-count"),d=document.getElementById("tab-evt-count");r&&(r.textContent=n.length),d&&(d.textContent=i.total.toLocaleString()),document.querySelectorAll(".analyzer-tab").forEach(p=>{p.addEventListener("click",()=>{document.querySelectorAll(".analyzer-tab").forEach(g=>g.classList.remove("active")),p.classList.add("active");const h=p.dataset.tab;document.getElementById("incidents-section").hidden=h!=="incidents",document.getElementById("events-panel").hidden=h!=="events"})}),R(re)}function Ge(e,t){if(!J)return;const n=e>=80?"#34d399":e>=60?"#f59e0b":"#f43f5e",a=e>=80?"Good":e>=60?"Degraded":"Critical";J.innerHTML=`
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
  `}function ze(e){if(E){if(!e.length){E.innerHTML=`
      <div class="no-incidents">
        <div class="no-incidents-icon"><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div>
        <div class="no-incidents-title">No incidents detected</div>
        <div class="no-incidents-sub">No known crash or failure anchor events were found in this log.</div>
      </div>
    `;return}E.innerHTML=e.map((t,n)=>Fe(t)).join(""),E.querySelectorAll(".incident-toggle").forEach(t=>{t.addEventListener("click",n=>{if(n.target.closest("[data-lookup-id]"))return;const s=t.closest(".incident-card").querySelector(".incident-body"),i=t.querySelector(".incident-chevron"),o=!s.hidden;s.hidden=o,i.classList.toggle("open",!o)})}),E.querySelectorAll(".copy-summary-btn").forEach(t=>{t.addEventListener("click",()=>{const n=t.dataset.summary;navigator.clipboard.writeText(n).then(()=>{t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy for ticket",t.classList.remove("copied")},2e3)})})}),E.querySelectorAll(".evidence-item").forEach(t=>{t.addEventListener("click",n=>{if(n.stopPropagation(),n.target.closest("[data-lookup-id]"))return;const s=t.closest(".evidence-wrap").querySelector(".evidence-detail"),i=t.querySelector(".ev-expand-chevron"),o=!s.hidden;s.hidden=o,t.classList.toggle("expanded",!o),i&&(i.textContent=o?"▶":"▼")})}),E.querySelectorAll(".timeline-item").forEach(t=>{t.addEventListener("click",n=>{if(n.stopPropagation(),n.target.closest("[data-lookup-id]"))return;const a=t.closest(".timeline-item-wrap");if(!a)return;const s=a.querySelector(".timeline-detail");if(!s)return;const i=t.querySelector(".tl-expand-chevron"),o=!s.hidden;s.hidden=o,i&&(i.textContent=o?"▶":"▼")})}),E.querySelectorAll(".ev-advanced-toggle").forEach(t=>{t.addEventListener("click",n=>{n.stopPropagation();const s=t.closest(".ev-inline-detail").querySelector(".ev-advanced-section").classList.toggle("ev-advanced-open");t.textContent=s?"Advanced ▲":"Advanced ▼"})}),E.querySelectorAll(".ev-copy-btn").forEach(t=>{t.addEventListener("click",n=>{var a;n.stopPropagation(),(a=navigator.clipboard)==null||a.writeText(t.dataset.copy).then(()=>{t.classList.add("copied"),setTimeout(()=>t.classList.remove("copied"),2e3)})})}),E.querySelectorAll("[data-lookup-id]").forEach(t=>{t.addEventListener("click",n=>{n.stopPropagation(),pe(t.dataset.lookupId)})})}}function Fe(e,t){var g,m;const{anchor:n,windowEvents:a,topContributors:s,signatureResult:i,report:o}=e,r=(g=i[0])==null?void 0:g.signature,d=o.confidence,p=at(n.severity),h=d==="high"?"conf-high":d==="medium"?"conf-medium":"conf-low";return`
    <div class="incident-card">
      <div class="incident-header ${p} incident-toggle">
        <div class="incident-header-left">
          <span class="incident-icon">${(r==null?void 0:r.icon)??'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'}</span>
          <div>
            <div class="incident-title">${(r==null?void 0:r.name)??rt(n)}</div>
            <div class="incident-meta">
              <span class="incident-time">${n.timestamp.toLocaleString()}</span>
              <span class="incident-provider">${u(n.provider)}</span>
              ${o.confidenceReason?`<span class="conf-reason">${u(o.confidenceReason)}</span>`:""}
            </div>
          </div>
        </div>
        <div class="incident-header-right">
          <span class="conf-badge ${h}">${d}</span>
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
            ${s.slice(0,6).map(({event:v,score:k})=>`
              <div class="evidence-wrap">
                <div class="evidence-item">
                  <span class="ev-sev-dot sev-${v.severity.toLowerCase()}"></span>
                  <span class="ev-id" data-lookup-id="${v.id}" title="Look up Event ${v.id}">${v.id}</span>
                  <span class="ev-provider">${u(q(v.provider))}</span>
                  <span class="ev-time">${P(v.timestamp)}</span>
                  <span class="ev-score" title="Relevance score">${k}</span>
                  <span class="ev-expand-chevron">▶</span>
                </div>
                <div class="evidence-detail" hidden>${ue(v)}</div>
              </div>
            `).join("")}
          </div>
        </div>
        `:""}

        <!-- Timeline -->
        ${a.length?Xe(a,n):""}

        <!-- Next steps -->
        ${o.nextSteps.length?`
        <div class="incident-section">
          <div class="incident-section-label">Suggested next steps</div>
          <ol class="next-steps-list">
            ${o.nextSteps.map(v=>`<li>${u(v)}</li>`).join("")}
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
          ${(m=o.alternateSignatures)!=null&&m.length?`
          <span class="alt-signatures">
            Also possible: ${o.alternateSignatures.map(v=>v.signature.name).join(", ")}
          </span>
          `:""}
        </div>
      </div>
    </div>
  `}function Xe(e,t){const n=[...e,t].sort((i,o)=>i.timestamp-o.timestamp),s=n.length>12?[...n.slice(0,6),{_ellipsis:!0,count:n.length-10},...n.slice(-4)]:n;return`
    <div class="incident-section">
      <div class="incident-section-label">Timeline (${e.length} events in ${Ye}-min window)</div>
      <div class="mini-timeline">
        ${s.map(i=>{var r;if(i._ellipsis)return`<div class="timeline-ellipsis">· · · ${i.count} more events · · ·</div>`;const o=i===t;return`
            <div class="timeline-item-wrap">
              <div class="timeline-item ${o?"timeline-anchor":""}">
                <div class="tl-dot sev-${(r=i.severity)==null?void 0:r.toLowerCase()}"></div>
                <div class="tl-content">
                  <span class="tl-time">${P(i.timestamp)}</span>
                  <span class="tl-id" data-lookup-id="${i.id}" title="Look up Event ${i.id}">${i.id}</span>
                  <span class="tl-provider">${u(q(i.provider))}</span>
                  ${o?'<span class="tl-anchor-label">ANCHOR</span>':""}
                </div>
                <span class="tl-expand-chevron">▶</span>
              </div>
              <div class="timeline-detail" hidden>${ue(i)}</div>
            </div>
          `}).join("")}
      </div>
    </div>
  `}const Ye=15,de=new Set(["Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting","Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-DistributedCOM","Microsoft-Windows-Security-SPP","Microsoft-Windows-Defrag","Microsoft-Windows-Power-Troubleshooter"]),ee={Critical:0,Error:1,Warning:2,Info:3,Verbose:4},c={sortCol:"timestamp",sortDir:"asc",page:0,pageSize:100,query:"",severities:new Set,providers:new Set,channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set};document.addEventListener("click",e=>{const t=document.getElementById("tbl-provider-panel"),n=document.getElementById("tbl-provider-btn");t&&!t.hidden&&!t.contains(e.target)&&!(n!=null&&n.contains(e.target))&&(t.hidden=!0,n==null||n.classList.remove("open"))});function Qe(e){var k,w;if(!D||!x)return;Object.assign(c,{sortCol:"timestamp",sortDir:"asc",page:0,query:"",severities:new Set,providers:new Set,channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set});const t=[...new Set(e.map(l=>l.provider).filter(Boolean))].sort(),n=[...new Set(e.map(l=>l.channel).filter(Boolean))].sort(),a=l=>l?new Date(l-l.getTimezoneOffset()*6e4).toISOString().slice(0,16):"",s=(k=e[0])==null?void 0:k.timestamp,i=(w=e[e.length-1])==null?void 0:w.timestamp;D.innerHTML=`
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
            ${t.map(l=>`
              <label class="provider-option">
                <input type="checkbox" class="provider-cb" value="${u(l)}" />
                <span class="provider-option-name" title="${u(l)}">${u(q(l))}</span>
              </label>`).join("")}
          </div>
        </div>
      </div>

      <select id="tbl-channel" class="filter-control filter-control-select">
        <option value="">All channels</option>
        ${n.map(l=>`<option value="${u(l)}">${u(l)}</option>`).join("")}
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
  `;const o=(l,f,$)=>{var b;return(b=document.getElementById(l))==null?void 0:b.addEventListener(f,$)};o("tbl-query","input",l=>{c.query=l.target.value,c.page=0,S()}),D.querySelectorAll(".tbl-sev-cb").forEach(l=>{l.addEventListener("change",()=>{l.checked?c.severities.add(l.value):c.severities.delete(l.value),l.closest(".sev-chip").classList.toggle("active",l.checked),c.page=0,v(),S()})});const r=document.getElementById("tbl-provider-btn"),d=document.getElementById("tbl-provider-panel"),p=document.getElementById("tbl-provider-label"),h=document.getElementById("tbl-provider-clear"),g=document.getElementById("tbl-provider-select-all");r==null||r.addEventListener("click",l=>{l.stopPropagation();const f=d.hidden;d.hidden=!f,r.classList.toggle("open",f)});function m(){const l=c.providers.size;p.textContent=l===0?"All providers":`${l} provider${l!==1?"s":""}`,r==null||r.classList.toggle("filtered",l>0)}function v(){const l=c.fromTime?new Date(c.fromTime).getTime():null,f=c.toTime?new Date(c.toTime).getTime():null,$=new Set(C.filter(b=>!(c.severities.size>0&&!c.severities.has(b.severity)||c.channel&&b.channel!==c.channel||l!==null&&b.timestamp<l||f!==null&&b.timestamp>f||c.hideNoisy&&de.has(b.provider))).map(b=>b.provider).filter(Boolean));D.querySelectorAll(".provider-option").forEach(b=>{const A=b.querySelector(".provider-cb"),T=$.has(A.value);b.classList.toggle("provider-option-unavailable",!T),A.disabled=!T,!T&&A.checked&&(A.checked=!1,c.providers.delete(A.value))}),m()}D.querySelectorAll(".provider-cb").forEach(l=>{l.addEventListener("change",()=>{l.checked?c.providers.add(l.value):c.providers.delete(l.value),m(),c.page=0,S()})}),h==null||h.addEventListener("click",l=>{l.stopPropagation(),c.providers.clear(),D.querySelectorAll(".provider-cb").forEach(f=>f.checked=!1),m(),c.page=0,S()}),g==null||g.addEventListener("click",l=>{l.stopPropagation(),D.querySelectorAll(".provider-option:not([hidden]) .provider-cb").forEach(f=>{f.checked=!0,c.providers.add(f.value)}),m(),c.page=0,S()}),o("tbl-provider-search","input",l=>{const f=l.target.value.toLowerCase();D.querySelectorAll(".provider-option").forEach($=>{$.hidden=f?!$.querySelector(".provider-option-name").textContent.toLowerCase().includes(f):!1})}),o("tbl-channel","change",l=>{c.channel=l.target.value,c.page=0,v(),S()}),o("tbl-from","change",l=>{c.fromTime=l.target.value,c.page=0,v(),S()}),o("tbl-to","change",l=>{c.toTime=l.target.value,c.page=0,v(),S()}),o("tbl-noise","click",l=>{c.hideNoisy=!c.hideNoisy,c.page=0,l.target.classList.toggle("active",c.hideNoisy),l.target.textContent=c.hideNoisy?"Show noise":"Hide noise",v(),S()}),o("tbl-csv","click",()=>Ze(le())),v(),S()}function le(){const e=c.query.toLowerCase(),t=c.fromTime?new Date(c.fromTime).getTime():null,n=c.toTime?new Date(c.toTime).getTime():null;let a=C.filter(s=>{if(c.severities.size>0&&!c.severities.has(s.severity)||c.providers.size>0&&!c.providers.has(s.provider)||c.channel&&s.channel!==c.channel||t!==null&&s.timestamp<t||n!==null&&s.timestamp>n||c.hideNoisy&&de.has(s.provider))return!1;if(e){const i=/^\d+$/.test(e)?parseInt(e,10):null;if(i!==null){if(s.id!==i)return!1}else if(!`${s.id} ${s.provider} ${s.channel} ${s.message} ${s.severity}`.toLowerCase().includes(e))return!1}return!0});return a.sort((s,i)=>{let o=0;switch(c.sortCol){case"timestamp":o=s.timestamp-i.timestamp;break;case"severity":o=(ee[s.severity]??9)-(ee[i.severity]??9);break;case"id":o=s.id-i.id;break;case"provider":o=(s.provider||"").localeCompare(i.provider||"");break}return c.sortDir==="asc"?o:-o}),a}function S(){if(!x)return;const e=le(),t=e.length,n=Math.max(0,Math.ceil(t/c.pageSize)-1);c.page=Math.min(c.page,n);const a=c.page*c.pageSize,s=e.slice(a,a+c.pageSize);if(!t){x.innerHTML='<div class="table-empty">No events match the current filters.</div>';return}const i=d=>`<span class="sort-arrow ${c.sortCol===d?"active":""}">${c.sortCol===d?c.sortDir==="asc"?"↑":"↓":"↕"}</span>`,o=d=>c.sortCol===d?"sort-active":"";x.innerHTML=`
    <div class="table-info-bar">
      <span class="table-count-text">
        ${(a+1).toLocaleString()}–${Math.min(a+c.pageSize,t).toLocaleString()} of ${t.toLocaleString()} event${t!==1?"s":""}
        ${t<C.length?` (${C.length.toLocaleString()} total)`:""}
      </span>
      <div class="table-pagination">
        <button class="page-btn" id="pg-first" ${c.page===0?"disabled":""}>«</button>
        <button class="page-btn" id="pg-prev"  ${c.page===0?"disabled":""}>‹ Prev</button>
        <span class="page-info">Page ${c.page+1} / ${n+1}</span>
        <button class="page-btn" id="pg-next"  ${c.page>=n?"disabled":""}>Next ›</button>
        <button class="page-btn" id="pg-last"  ${c.page>=n?"disabled":""}>»</button>
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
      <tbody>${s.map(d=>Je(d)).join("")}</tbody>
    </table>
  `,x.querySelectorAll("th[data-sort]").forEach(d=>{d.addEventListener("click",()=>{const p=d.dataset.sort;c.sortDir=c.sortCol===p&&c.sortDir==="asc"?"desc":"asc",c.sortCol=p,c.page=0,S()})});const r=(d,p)=>{var h;return(h=document.getElementById(d))==null?void 0:h.addEventListener("click",p)};r("pg-first",()=>{c.page=0,S()}),r("pg-prev",()=>{c.page--,S()}),r("pg-next",()=>{c.page++,S()}),r("pg-last",()=>{c.page=n,S()}),x.querySelectorAll("tbody tr[data-record]").forEach(d=>{d.addEventListener("click",p=>{if(p.target.closest(".table-event-id"))return;const h=parseInt(d.dataset.record,10);c.expandedIds.has(h)?c.expandedIds.delete(h):c.expandedIds.add(h),S()})}),x.querySelectorAll(".table-event-id").forEach(d=>{d.addEventListener("click",p=>{p.stopPropagation(),pe(d.dataset.lookupId)})}),x.querySelectorAll(".ev-advanced-toggle").forEach(d=>{d.addEventListener("click",p=>{p.stopPropagation();const g=d.closest(".ev-detail-inner").querySelector(".ev-advanced-section").classList.toggle("ev-advanced-open");d.textContent=g?"Advanced ▲":"Advanced ▼"})}),x.querySelectorAll(".ev-copy-btn").forEach(d=>{d.addEventListener("click",p=>{var h;p.stopPropagation(),(h=navigator.clipboard)==null||h.writeText(d.dataset.copy).then(()=>{d.classList.add("copied"),setTimeout(()=>d.classList.remove("copied"),2e3)})})})}function Je(e){const t=c.expandedIds.has(e.recordId),n=e.severity.toLowerCase(),a=Object.keys(e.data||{}),s=e.message?u(e.message.substring(0,150))+(e.message.length>150?"…":""):'<span style="color:var(--text3);font-style:italic">no message</span>',i=`
    <tr class="ev-row-${n}${t?" row-expanded":""}" data-record="${e.recordId}">
      <td class="ev-col-expand">${t?"▼":"▶"}</td>
      <td class="ev-col-time">${ot(e.timestamp)}</td>
      <td><span class="sev-badge sev-badge-${n}">${e.severity}</span></td>
      <td><span class="table-event-id" data-lookup-id="${e.id}" title="Look up Event ${e.id}">${e.id}</span></td>
      <td class="ev-col-provider" title="${u(e.provider)}">${u(q(e.provider))}</td>
      <td class="ev-col-channel">${u(e.channel)}</td>
      <td class="ev-col-message">${s}</td>
    </tr>`;if(!t)return i;const o=e.taskName||e.task||null,r=me(e.opcode,e.opcodeName),d=fe(e.keywords,e.keywordNames),p=ve(e.userSID),h=M.get(e.id)||1,g=C.filter(f=>f.recordId!==e.recordId&&Math.abs(f.timestamp-e.timestamp)<=3e4).length,m=[["Time (local)",e.timestamp.toLocaleString()],["Time (UTC)",e.timestamp.toISOString()],["Provider",e.provider],["Channel",e.channel],["Computer",e.computer],["Record ID",e.recordId||null],["User SID",p],["Process ID",e.processId||null],["Thread ID",e.threadId||null],["Activity ID",e.activityId],["Related Act. ID",e.relatedActivityId],["Task",o],["Opcode",r],["Keywords",d]].filter(([,f])=>f),v=[["Raw Level",String(e.levelNum)],["Raw Task",e.task],["Raw Opcode",e.opcode],["Raw Keywords",e.keywords],["Version",e.version],["Qualifiers",e.qualifiers],["Provider Desc.",e.providerDescription]].filter(([,f])=>f),k=he(e.message),w=k?`<div class="ev-detail-message-wrap">
        <div class="ev-detail-message">${u(k)}</div>
        <button class="ev-copy-btn" data-copy="${u(e.message)}" title="Copy message">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        </button>
       </div>`:`<div class="ev-detail-message ev-no-message">
        Message not rendered — Windows message templates are stored on the source machine.
        Export directly from the affected computer to see full event messages.
       </div>`,l=e.dataAnon||[];return i+`
    <tr class="ev-detail-row">
      <td colspan="7">
        <div class="ev-detail-inner">
          ${h>1||g>0?`
          <div class="ev-occurrence-bar">
            ${h>1?`Event ${e.id} appears <strong>${h}×</strong> in this log`:""}
            ${h>1&&g>0?" &nbsp;·&nbsp; ":""}
            ${g>0?`<strong>${g}</strong> other event${g!==1?"s":""} within ±30s`:""}
          </div>`:""}
          ${w}
          <div class="ev-detail-meta">
            ${m.map(([f,$])=>`
              <div class="ev-detail-field">
                <span class="ev-detail-key">${f}</span>
                <span class="ev-detail-val">${u(String($))}</span>
              </div>`).join("")}
          </div>
          ${a.length||l.length?`
          <div class="ev-detail-data">
            <div class="ev-detail-data-title">Event Data</div>
            ${a.map(f=>`
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key">${u(f)}</span>
                <span class="ev-detail-data-val">${u(String(e.data[f]))}</span>
              </div>`).join("")}
            ${l.map((f,$)=>`
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key ev-detail-data-key--anon">[${$}]</span>
                <span class="ev-detail-data-val">${u(String(f))}</span>
              </div>`).join("")}
          </div>`:""}
          <div class="ev-detail-actions">
            <span class="ev-detail-lookup-btn table-event-id" data-lookup-id="${e.id}">
              Look up Event ${e.id} →
            </span>
            ${v.length?'<button class="ev-advanced-toggle">Advanced ▼</button>':""}
          </div>
          ${v.length?`
          <div class="ev-advanced-section">
            <div class="ev-detail-data-title">Advanced / Raw</div>
            ${v.map(([f,$])=>`
              <div class="ev-detail-field">
                <span class="ev-detail-key">${f}</span>
                <span class="ev-detail-val">${u(String($))}</span>
              </div>`).join("")}
          </div>`:""}
        </div>
      </td>
    </tr>`}function Ze(e){const t=["Time (UTC)","Severity","EventID","Provider","Channel","Computer","RecordID","ProcessID","ThreadID","UserSID","ActivityID","RelatedActivityID","Task","TaskName","Opcode","OpcodeName","Keywords","KeywordNames","Version","Qualifiers","ProviderDescription","Message","EventData","EventDataAnon"],n=r=>`"${String(r??"").replace(/"/g,'""').replace(/\r?\n/g," ")}"`,a=e.map(r=>[r.timestamp.toISOString(),r.severity,r.id,n(r.provider),n(r.channel),n(r.computer),r.recordId,r.processId||"",r.threadId||"",n(r.userSID),n(r.activityId),n(r.relatedActivityId),n(r.task),n(r.taskName),n(r.opcode),n(r.opcodeName),n(r.keywords),n((r.keywordNames||[]).join("; ")),n(r.version),n(r.qualifiers),n(r.providerDescription),n(r.message),n(Object.entries(r.data||{}).map(([d,p])=>`${d}=${p}`).join("; ")),n((r.dataAnon||[]).join("; "))].join(",")),s=[t.join(","),...a].join(`\r
`),i=URL.createObjectURL(new Blob([s],{type:"text/csv;charset=utf-8;"})),o=Object.assign(document.createElement("a"),{href:i,download:`eventful-${new Date().toISOString().slice(0,10)}.csv`});document.body.appendChild(o),o.click(),document.body.removeChild(o),URL.revokeObjectURL(i)}function pe(e){const t=parseInt(e,10),n=document.getElementById("lookup-panel"),a=document.getElementById("lp-body");if(!n||!a)return;const s=$e.find(o=>o.id===t),i=C.filter(o=>o.id===t);a.innerHTML=et(t,s,i),n.hidden=!1,a.querySelectorAll(".lp-copy-ps").forEach(o=>{o.addEventListener("click",()=>{navigator.clipboard.writeText(o.dataset.code).then(()=>{o.textContent="Copied!",setTimeout(()=>{o.textContent="Copy"},2e3)})})}),a.querySelectorAll(".lp-show-in-log").forEach(o=>{o.addEventListener("click",()=>{const r=o.dataset.filterId;O(),document.querySelectorAll(".analyzer-tab").forEach(h=>h.classList.remove("active"));const d=document.querySelector('.analyzer-tab[data-tab="events"]');d&&d.classList.add("active"),document.getElementById("incidents-section").hidden=!0,document.getElementById("events-panel").hidden=!1,c.query=r,c.page=0;const p=document.getElementById("tbl-query");p&&(p.value=r),S()})})}function O(){const e=document.getElementById("lookup-panel");e&&(e.hidden=!0)}function et(e,t,n){var s,i,o;const a=n.length?`<button class="lp-show-in-log" data-filter-id="${e}">Show all ${n.length} occurrence${n.length!==1?"s":""} in All Events →</button>`:"";if(t){const r=((s=t.severity)==null?void 0:s.toLowerCase())??"info";return`
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
            ${t.causes.map(d=>`<li>${u(d)}</li>`).join("")}
          </ul>`:""}
        ${(o=t.steps)!=null&&o.length?`
          <div class="lp-subsection-label">Investigation Steps</div>
          <ol class="lp-steps">
            ${t.steps.map(d=>`<li>${u(d)}</li>`).join("")}
          </ol>`:""}
        ${t.powershell?`
          <div class="lp-subsection-label">PowerShell</div>
          <div class="lp-ps-block">
            <pre>${u(t.powershell)}</pre>
            <button class="lp-copy-ps" data-code="${u(t.powershell)}">Copy</button>
          </div>`:""}
        <div class="lp-doc-footer">
          <a href="event-results.html?q=${e}" target="_blank" rel="noopener" class="lp-full-docs-btn">
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
    </div>`}function ue(e){const t=e.taskName||e.task||null,n=me(e.opcode,e.opcodeName),a=fe(e.keywords,e.keywordNames),s=ve(e.userSID),i=e.dataAnon||[],o=Object.keys(e.data||{}),r=M.get(e.id)||1,d=C.filter(m=>m.recordId!==e.recordId&&Math.abs(m.timestamp-e.timestamp)<=3e4).length,p=he(e.message),h=[["Time (local)",e.timestamp.toLocaleString()],["Time (UTC)",e.timestamp.toISOString()],["Provider",e.provider],["Channel",e.channel],["Computer",e.computer],["Record ID",e.recordId||null],["User SID",s],["Process ID",e.processId||null],["Thread ID",e.threadId||null],["Activity ID",e.activityId],["Task",t],["Opcode",n],["Keywords",a]].filter(([,m])=>m),g=[["Raw Level",String(e.levelNum)],["Raw Task",e.task],["Raw Opcode",e.opcode],["Raw Keywords",e.keywords],["Version",e.version]].filter(([,m])=>m);return`
    <div class="ev-inline-detail">
      ${r>1||d>0?`
      <div class="ev-occurrence-bar">
        ${r>1?`Event ${e.id} fired <strong>${r}×</strong> in this log`:""}
        ${r>1&&d>0?" &nbsp;·&nbsp; ":""}
        ${d>0?`<strong>${d}</strong> other event${d!==1?"s":""} within ±30s`:""}
      </div>`:""}
      ${p?`<div class="ev-detail-message-wrap">
             <div class="ev-detail-message">${u(p)}</div>
             <button class="ev-copy-btn" data-copy="${u(e.message)}" title="Copy message">
               <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
             </button>
           </div>`:'<div class="ev-detail-message ev-no-message">Message not rendered — Windows message templates are stored on the source machine. Export from the affected computer to see full messages.</div>'}
      <div class="ev-inline-grid">
        <div class="ev-detail-meta">
          ${h.map(([m,v])=>`
            <div class="ev-detail-field">
              <span class="ev-detail-key">${m}</span>
              <span class="ev-detail-val">${u(String(v))}</span>
            </div>`).join("")}
        </div>
        ${o.length||i.length?`
        <div class="ev-detail-data">
          <div class="ev-detail-data-title">Event Data</div>
          ${o.map(m=>`
            <div class="ev-detail-data-row">
              <span class="ev-detail-data-key">${u(m)}</span>
              <span class="ev-detail-data-val">${u(String(e.data[m]))}</span>
            </div>`).join("")}
          ${i.map((m,v)=>`
            <div class="ev-detail-data-row">
              <span class="ev-detail-data-key ev-detail-data-key--anon">[${v}]</span>
              <span class="ev-detail-data-val">${u(String(m))}</span>
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
        ${g.map(([m,v])=>`
          <div class="ev-detail-field">
            <span class="ev-detail-key">${m}</span>
            <span class="ev-detail-val">${u(String(v))}</span>
          </div>`).join("")}
      </div>`:""}
    </div>`}const tt={"S-1-1-0":"Everyone","S-1-5-7":"Anonymous","S-1-5-18":"SYSTEM","S-1-5-19":"LOCAL SERVICE","S-1-5-20":"NETWORK SERVICE","S-1-5-32-544":"Administrators","S-1-5-32-545":"Users","S-1-5-32-546":"Guests"};function ve(e){if(!e)return null;const t=tt[e];return t?`${t} (${e})`:e}const nt={2:"The system cannot find the file specified",3:"The system cannot find the path specified",5:"Access is denied",32:"The process cannot access the file because it is being used by another process",1053:"The service did not respond to the start or control request in a timely fashion",1055:"The service database is locked",1056:"An instance of the service is already running",1058:"The service cannot be started — it is disabled or has no enabled devices associated with it",1060:"The specified service does not exist as an installed service",1061:"The service cannot accept control messages at this time",1067:"The process terminated unexpectedly",1068:"The dependency service or group failed to start",1069:"The service did not start due to a logon failure",1072:"The specified service has been marked for deletion",1073:"The specified service already exists",1326:"Logon failure: unknown user name or bad password"};function he(e){return e&&e.replace(/%%(\d+)/g,(t,n)=>{const a=nt[+n];return a?`${a} (%%${n})`:t})}const st={0:"Info",1:"Start",2:"Stop",3:"DC Start",4:"DC Stop",5:"Extension",6:"Reply",7:"Resume",8:"Suspend",9:"Send",240:"Disconnect",241:"Connect"};function me(e,t){return t||(e==null||e===""?null:st[String(e)]||String(e))}const it={"0x8000000000000000":"Audit Failure","0x4000000000000000":"Audit Success","0x8080000000000000":"Classic, Audit Failure","0x4080000000000000":"Classic, Audit Success","0x0080000000000000":"Classic","0x0000000000000000":"None"};function fe(e,t){return t!=null&&t.length?t.join(", "):e?it[e.toLowerCase()]??e:null}function te(e){const t=y==null?void 0:y.querySelector(".upload-error");t&&t.remove();const n=document.createElement("div");n.className="upload-error",n.textContent=e,y==null||y.appendChild(n),R(B)}function q(e){return e?e.replace(/^Microsoft-Windows-/i,"").replace(/^Microsoft-/i,""):"—"}function ot(e){return e.toLocaleString([],{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})}function at(e){return`sev-header-${(e==null?void 0:e.toLowerCase())??"info"}`}function rt(e){return{41:"Unexpected System Reboot",6008:"Unexpected Shutdown Detected",1001:"System Crash (BSOD)",1e3:"Application Crash",7024:"Critical Service Failure"}[e.id]??`Event ${e.id}`}
