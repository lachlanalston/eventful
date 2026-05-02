import{i as ge,t as we}from"./theme-gEBc2EcC.js";import{a as ye}from"./index-BAM9NZ7H.js";function Se(e){const n=new DOMParser().parseFromString(e,"text/xml"),a=n.querySelector("parsererror");if(a)throw new Error(`Invalid XML: ${a.textContent.substring(0,120)}`);const s=n.querySelectorAll("Event");if(s.length===0)throw new Error("No <Event> elements found. Make sure you exported in XML format from Event Viewer.");const i=[];for(const o of s)try{const r=$e(o);!isNaN(r.id)&&r.id>0&&r.timestamp instanceof Date&&!isNaN(r.timestamp)&&i.push(r)}catch{}if(i.length===0)throw new Error("No valid events could be parsed. Check that the XML is a Windows Event Viewer export.");return i.sort((o,r)=>o.timestamp-r.timestamp)}function $e(e){var R,P,B,O,q,W,U,j,H;const t=e.querySelector("System"),n=parseInt($(t,"EventID"),10),a=parseInt($(t,"Level"),10),s=t==null?void 0:t.querySelector("Provider"),i=(s==null?void 0:s.getAttribute("Name"))||(s==null?void 0:s.getAttribute("EventSourceName"))||"",o=$(t,"Channel"),r=$(t,"Computer"),d=parseInt($(t,"EventRecordID"),10),c=t==null?void 0:t.querySelector("TimeCreated"),u=(c==null?void 0:c.getAttribute("SystemTime"))||(c==null?void 0:c.textContent)||"",w=new Date(u),h=t==null?void 0:t.querySelector("Execution"),v=t==null?void 0:t.querySelector("Correlation"),f=t==null?void 0:t.querySelector("Security"),m=e.querySelector("RenderingInfo"),re=(P=(R=m==null?void 0:m.querySelector("Level"))==null?void 0:R.textContent)==null?void 0:P.trim(),ce=Ee(a,re),le=((O=(B=m==null?void 0:m.querySelector("Task"))==null?void 0:B.textContent)==null?void 0:O.trim())||"",de=((W=(q=m==null?void 0:m.querySelector("Opcode"))==null?void 0:q.textContent)==null?void 0:W.trim())||"",pe=[...(m==null?void 0:m.querySelectorAll("Keywords > Keyword"))??[]].map(fe=>fe.textContent.trim()).filter(Boolean),ue=((j=(U=m==null?void 0:m.querySelector("Provider"))==null?void 0:U.textContent)==null?void 0:j.trim())||"",ve=ke(e,m),{named:me,anon:he}=be(e);return{id:n,provider:i,channel:o,levelNum:a,severity:ce,timestamp:w,computer:r,message:ve,recordId:isNaN(d)?0:d,processId:parseInt(h==null?void 0:h.getAttribute("ProcessID"),10)||0,threadId:parseInt(h==null?void 0:h.getAttribute("ThreadID"),10)||0,activityId:(v==null?void 0:v.getAttribute("ActivityID"))||"",relatedActivityId:(v==null?void 0:v.getAttribute("RelatedActivityID"))||"",userSID:(f==null?void 0:f.getAttribute("UserID"))||"",task:$(t,"Task"),opcode:$(t,"Opcode"),keywords:$(t,"Keywords"),taskName:le,opcodeName:de,keywordNames:pe,providerDescription:ue,version:$(t,"Version"),qualifiers:((H=t==null?void 0:t.querySelector("EventID"))==null?void 0:H.getAttribute("Qualifiers"))||"",data:me,dataAnon:he}}function $(e,t){var n,a;return((a=(n=e==null?void 0:e.querySelector(t))==null?void 0:n.textContent)==null?void 0:a.trim())||""}function ke(e,t){var i,o;const n=(o=(i=t==null?void 0:t.querySelector("Message"))==null?void 0:i.textContent)==null?void 0:o.trim();if(n)return n;const a=e.querySelector("EventData");if(a){const r=[];for(const d of a.querySelectorAll("Data")){const c=d.getAttribute("Name"),u=d.textContent.trim();u&&u!=="-"&&r.push(c?`${c}: ${u}`:u)}if(r.length)return r.join(" | ")}const s=e.querySelector("UserData");return s?s.textContent.trim():""}function be(e){const t={},n=[],a=e.querySelector("EventData");if(!a)return{named:t,anon:n};for(const s of a.querySelectorAll("Data")){const i=s.getAttribute("Name"),o=s.textContent.trim();i?o&&(t[i]=o):o&&n.push(o)}return{named:t,anon:n}}function Ee(e,t){if(t){const n=t.toLowerCase();if(n.includes("critical"))return"Critical";if(n.includes("error"))return"Error";if(n.includes("warning"))return"Warning";if(n.includes("information"))return"Info";if(n.includes("verbose"))return"Verbose";if(n.includes("audit"))return t.includes("Failure")?"Error":"Info"}switch(e){case 1:return"Critical";case 2:return"Error";case 3:return"Warning";case 4:return"Info";case 5:return"Verbose";case 0:return"Info";default:return"Info"}}const Ce=new Set([41,6008,1001,1e3,7024]),_={7:40,11:30,51:40,52:30,55:35,57:25,129:20,153:20,4101:50,1001:45,1e3:35,1002:30,1026:20,7031:25,7034:25,7022:20,7023:20,7001:15,7011:15,1014:20,4202:20,4201:15,17:50,18:40,19:30,4625:10,4740:15},Ie=new Set(["Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting"]),xe=[{id:"gpu-driver-crash",name:"GPU Driver Crash",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',category:"Hardware Driver",test(e){const t=["nvlddmkm","amdkmdag","amd","igdkmd","dxgkrnl","atikmdag"],n=e.some(s=>s.id===4101),a=e.find(s=>t.some(i=>{var o;return(o=s.provider)==null?void 0:o.toLowerCase().includes(i)}));return n?{match:!0,confidence:"high",reason:"Event 4101 (display driver TDR timeout) found in window"}:a?{match:!0,confidence:"medium",reason:`GPU provider "${a.provider}" found in window — no Event 4101`}:{match:!1}},what:"The graphics card driver stopped responding and Windows could not recover it.",rootCause:"Display driver (TDR timeout) caused the system to become unresponsive.",nextSteps:["Update or roll back GPU drivers via Device Manager → Display Adapters","Use DDU (Display Driver Uninstaller) in Safe Mode for clean reinstall","Monitor GPU temperatures under load with GPU-Z or HWiNFO64","Run GPU stability test with FurMark or 3DMark","Check GPU power connector seating if system is recently assembled"],technicianHint:'NVIDIA: look for "nvlddmkm" in Event 4101 faulting module. AMD: "atikmpag" or "amdkmdag". DDU clean reinstall resolves driver corruption in ~70% of cases. If temps are fine and fresh driver fails, suspect hardware.'},{id:"disk-failure",name:"Storage / Disk Error",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/></svg>',category:"Storage",test(e){const t=[7,11,51,52,55,57,129,153],n=["disk","atapi","nvme","storport","ntfs","fastfat","stornvme"],a=e.filter(i=>t.includes(i.id)||n.some(o=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(o)})),s=[...new Set(a.map(i=>i.id))].join(", ");return a.length>=3?{match:!0,confidence:"high",reason:`${a.length} disk error events in window (IDs: ${s})`}:a.length>=1?{match:!0,confidence:"medium",reason:`${a.length} disk error event in window (ID: ${s})`}:{match:!1}},what:"The storage device reported I/O errors before the incident.",rootCause:"Disk hardware errors were detected — possible drive failure, bad sectors, or controller issue.",nextSteps:["Run CrystalDiskInfo — check SMART reallocated/pending/uncorrectable sectors","Run chkdsk /f /r /x on affected volume","Run manufacturer disk diagnostic (SeaTools, WD Dashboard, Samsung Magician)","Check SATA/power cable connections","Consider imaging and replacing drive if SMART shows degradation"],technicianHint:"Event 7 = hardware error from disk.sys. Event 51 = error during paging (system swapping to bad sectors — urgent). Event 55 = NTFS filesystem corruption. Multiple Event 7 in a short window usually means imminent failure."},{id:"bsod-kernel-crash",name:"Blue Screen of Death (BSOD)",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',category:"Kernel Crash",test(e,t){return t.id===1001?{match:!0,confidence:"high",reason:"Event 1001 (BugCheck) is the anchor — BSOD confirmed"}:e.some(n=>n.id===1001)?{match:!0,confidence:"high",reason:"Event 1001 (BugCheck/BSOD) found in window events"}:{match:!1}},what:"Windows detected an unrecoverable kernel error and created a memory dump.",rootCause:"A kernel or driver-level fault caused Windows to stop to prevent data corruption.",nextSteps:["Note the BugCheck code from Event 1001 details","Analyse minidump with WhoCrashed (free) or WinDbg (!analyze -v)","Run SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth","Run Windows Memory Diagnostic for MEMORY_MANAGEMENT (0x1A) stops","Update all drivers — especially GPU, NIC, and chipset"],technicianHint:"Common stop codes: 0x50 PAGE_FAULT (bad RAM or driver), 0x3B SYSTEM_SERVICE_EXCEPTION (driver), 0x1A MEMORY_MANAGEMENT (RAM), 0x7E SYSTEM_THREAD_EXCEPTION (driver), 0x0A IRQL_NOT_LESS_OR_EQUAL (driver/RAM). WhoCrashed gives the culprit driver in seconds."},{id:"service-crash-chain",name:"Service Crash Loop",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',category:"Windows Services",test(e){const t=[7031,7034,7022,7023,7024,7001,7011],n=e.filter(s=>t.includes(s.id)),a=[...new Set(n.map(s=>s.id))].join(", ");return n.length>=5?{match:!0,confidence:"high",reason:`${n.length} service failure events in window (IDs: ${a})`}:n.length>=2?{match:!0,confidence:"medium",reason:`${n.length} service failure events in window (IDs: ${a})`}:{match:!1}},what:"One or more Windows services crashed or failed to start repeatedly.",rootCause:"Service instability — possibly caused by a failed update, corrupted binary, or missing dependency.",nextSteps:["Identify which service(s) crashed from the event messages","Check service recovery settings: Services → right-click service → Properties → Recovery","Verify the service executable exists and is not corrupted","Check for related Application log events (Event 1000) for the service host","Review recent Windows Updates that may have changed the service"],technicianHint:"Event 7031 = service terminated unexpectedly (count tells you how many times). Event 7034 = crashed without telling SCM. The service name is in the event message. If it's svchost-hosted, check the service group."},{id:"application-crash-loop",name:"Application Crash Loop",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',category:"Application",test(e){const t=e.filter(n=>n.id===1e3);return t.length>=3?{match:!0,confidence:"high",reason:`${t.length} Event 1000 (application crash) in window`}:t.length>=1?{match:!0,confidence:"medium",reason:"1 Event 1000 (application crash) in window"}:{match:!1}},what:"An application was crashing repeatedly before the incident.",rootCause:"Application instability — possible corrupt installation, missing runtime, or incompatible update.",nextSteps:["Identify the crashing application from the Event 1000 message","Note the faulting module — it often identifies a specific DLL","Update or reinstall the application","Install/repair Visual C++ Redistributables if a runtime DLL faults","Check crash dumps in %LocalAppData%\\CrashDumps or the application's folder"],technicianHint:'The faulting module in Event 1000 is gold — "ntdll.dll" = OS issue or heap corruption, "msvcp140.dll" / "vcruntime140.dll" = missing C++ runtime, "AppName.exe" itself = bad binary. Repeated same app + same module = deterministic, reproducible fault.'},{id:"memory-hardware",name:"Memory / RAM Issue",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/></svg>',category:"Hardware",test(e){const t=["microsoft-windows-memoryd","whea-logger","microsoft-windows-whea"],n=[17,18,19,1],a=e.find(i=>n.includes(i.id)||t.some(o=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(o)}));return e.some(i=>{var o,r;return i.id===1001&&(((o=i.data)==null?void 0:o.BugcheckCode)==="26"||((r=i.data)==null?void 0:r.BugcheckCode)==="80")})?{match:!0,confidence:"medium",reason:"BSOD stop code indicates memory fault (0x1A MEMORY_MANAGEMENT or 0x50 PAGE_FAULT)"}:a?{match:!0,confidence:"medium",reason:`Memory/WHEA event detected (Event ${a.id} from ${a.provider||"unknown provider"})`}:{match:!1}},what:"Hardware memory errors or RAM-related faults were detected.",rootCause:"Defective or misconfigured RAM caused uncorrectable memory errors.",nextSteps:["Run MemTest86+ overnight (at least 2 passes)","Test RAM sticks one at a time to isolate the faulty module","Reseat RAM modules and clean contacts","Check XMP/EXPO profile stability — reset to JEDEC spec in BIOS","Check WHEA-Logger events for corrected/uncorrected error counts"],technicianHint:`WHEA Event 17/18/19 = hardware error framework caught a hardware error. Check the ErrorSource field — "MCE" (Machine Check Exception) = hardware fault, usually RAM or CPU. MemTest86+ is the definitive test. Don't trust Windows Memory Diagnostic for subtle faults.`},{id:"unexpected-power",name:"Unexpected Power Loss",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',category:"Power",test(e,t){var n;return t.id===41&&((n=t.data)==null?void 0:n.BugcheckCode)==="0"?{match:!0,confidence:"high",reason:"Event 41 BugcheckCode=0 — hard power loss confirmed (not a software crash)"}:(t.id===41||t.id===6008)&&e.length<=3?{match:!0,confidence:"medium",reason:`Only ${e.length} event(s) before anchor — abrupt stop, no software lead-up`}:{match:!1}},what:"The system lost power without going through a normal shutdown.",rootCause:"Hard power loss — possible PSU failure, power outage, or UPS failure.",nextSteps:["Check UPS health, battery test, and log — replace battery if > 3 years old","Test PSU voltage rails with PC Power Supply Tester or multimeter","Check power outlet and surge protector for faults","Review Event 41 BugcheckCode: 0 = power loss, non-0 = software crash","Install UPS with AVR if not present — protects against brownouts"],technicianHint:"Event 41 BugcheckCode=0 is definitive: the machine lost power while running (no BSOD, no clean shutdown). Very few preceding events confirms sudden loss. Multiple occurrences = PSU is failing. Check 12V rail — HDD-heavy systems are sensitive."},{id:"network-failure",name:"Network / Connectivity Failure",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',category:"Network",test(e){const t=[1014,4202,4201,6100],n=["tcpip","dns-client","dhcp","netbt","netlogon","rras"],a=e.filter(i=>t.includes(i.id)||n.some(o=>{var r;return(r=i.provider)==null?void 0:r.toLowerCase().includes(o)})),s=[...new Set(a.map(i=>i.id))].join(", ");return a.length>=3?{match:!0,confidence:"medium",reason:`${a.length} network/DNS events in window (IDs: ${s})`}:a.length>=1?{match:!0,confidence:"low",reason:`1 network/DNS event in window (ID: ${s})`}:{match:!1}},what:"Network or DNS errors were recorded in the period leading up to the incident.",rootCause:"Network connectivity failure caused application or service faults.",nextSteps:["Check NIC driver version — update if outdated",'Disable NIC power management: Device Manager → NIC → Power Management → uncheck "Allow computer to turn off"',"Test DNS resolution: nslookup google.com","Review DHCP lease renewal logs","Check switch port, cable, and NIC hardware"],technicianHint:"Event 1014 = DNS client resolver timeout. If you see it, look at the DNS server IP in the event — a failing DC or DNS server is a common cause. Event 4201/4202 = NIC connection state changes = intermittent cable or switch issue."}],De=15,Me={Critical:30,Error:20,Warning:10,Info:2,Verbose:0};function Ae(e){var r;if(!e.length)return{incidents:[],healthScore:100,computerName:"",stats:qe()};const t=((r=e[0])==null?void 0:r.computer)||"",n=J(e),a=Te(e),s=[];for(const d of a){const c=Le(e,d,De),w=Ne(c,d).slice(0,8),h=Re(c,d),v=Pe(d,h,w);s.push({anchor:d,windowEvents:c,topContributors:w,signatureResult:h,report:v})}const i=Ue(s),o=We(e,i);return{incidents:i,healthScore:o,computerName:t,stats:n}}function Te(e){const t=[],n=new Set;for(const a of e){if(!Ce.has(a.id))continue;const s=`${a.id}-${Math.floor(a.timestamp/3e4)}`;n.has(s)||(n.add(s),t.push(a))}return t.sort((a,s)=>s.timestamp-a.timestamp).slice(0,5)}function Le(e,t,n){const a=t.timestamp-n*6e4;return e.filter(s=>s.timestamp>=a&&s.timestamp<t.timestamp)}function Ne(e,t){const n=e.map(s=>{let i=Me[s.severity]??0;_[s.id]&&(i+=_[s.id]),s.provider&&t.provider&&s.provider===t.provider&&(i+=8),Ie.has(s.provider)&&(i=Math.max(0,i-15));const o=(t.timestamp-s.timestamp)/6e4;return o<2?i+=10:o<5&&(i+=5),{event:s,score:i}}),a=new Map;for(const{event:s}of n){const i=`${s.id}-${s.provider}`;a.set(i,(a.get(i)||0)+1)}for(const s of n){const i=`${s.event.id}-${s.event.provider}`,o=a.get(i)||1;o>=5?s.score+=15:o>=3?s.score+=8:o>=2&&(s.score+=4)}return n.filter(({score:s})=>s>0).sort((s,i)=>i.score-s.score).map(({event:s,score:i})=>({event:s,score:i}))}function Re(e,t){const n=[];for(const s of xe)try{const i=s.test(e,t);i.match&&n.push({signature:s,confidence:i.confidence,reason:i.reason||""})}catch{}const a={high:0,medium:1,low:2};return n.sort((s,i)=>(a[s.confidence]??3)-(a[i.confidence]??3)),n}function Pe(e,t,n,a){const s=t[0],i=s==null?void 0:s.signature,o=(s==null?void 0:s.confidence)??"low",r=(s==null?void 0:s.reason)||"",d=Q[e.id]??`Event ${e.id}`,c=(i==null?void 0:i.what)??`${d} occurred at ${Z(e.timestamp)}.`,u=(i==null?void 0:i.rootCause)??Be(e,n),w=(i==null?void 0:i.nextSteps)??["Review event details for more information","Check System and Application logs for context"],h=i==null?void 0:i.technicianHint,v=Oe(e,i,n,o,r);return{what:c,rootCause:u,confidence:o,confidenceReason:r,nextSteps:w,technicianHint:h,psaSummary:v,alternateSignatures:t.slice(1,3),evidenceCount:n.length}}const Q={41:"Unexpected system reboot (Kernel-Power)",6008:"Unexpected previous shutdown (EventLog)",1001:"System crash / BSOD (BugCheck)",1e3:"Application crash (Application Error)",7024:"Critical service failure"};function Be(e,t){if(!t.length)return"No significant preceding events identified in the lookback window.";const n=t[0].event;return`Leading event: ${n.provider||"Unknown"} Event ${n.id} (${n.severity}) recorded shortly before the incident.`}function Oe(e,t,n,a,s){return["INCIDENT SUMMARY","================",`Date/Time: ${e.timestamp.toLocaleString()}`,`Anchor Event: ${e.id} — ${Q[e.id]??"Unknown"}`,`Provider: ${e.provider||"Unknown"}`,`Computer: ${e.computer||"Unknown"}`,"","DIAGNOSIS","---------",t?`Pattern: ${t.name} (${t.category})`:"Pattern: No known pattern matched",`Confidence: ${a.toUpperCase()}${s?` — ${s}`:""}`,"",t?`What happened: ${t.what}`:"",t?`Root cause: ${t.rootCause}`:"","",`CONTRIBUTING EVENTS (top ${Math.min(n.length,5)})`,"------------------",...n.slice(0,5).map(({event:r})=>`  [${r.severity}] Event ${r.id} — ${r.provider||"Unknown"} @ ${Z(r.timestamp)}`),"","SUGGESTED NEXT STEPS","--------------------",...((t==null?void 0:t.nextSteps)??["Review event log for more context"]).map(r=>`  • ${r}`),"","Generated by Eventful Incident Analyzer"].filter(r=>r!==void 0).join(`
`)}function J(e){const t={Critical:0,Error:0,Warning:0,Info:0,Verbose:0};for(const n of e)t[n.severity]=(t[n.severity]||0)+1;return{total:e.length,...t}}function qe(){return{total:0,Critical:0,Error:0,Warning:0,Info:0,Verbose:0}}function We(e,t){let n=100;const a=J(e);n-=Math.min(a.Critical*15,40),n-=Math.min(a.Error*3,25),n-=Math.min(a.Warning*.5,10),n-=t.length*12;for(const s of t)s.report.confidence==="high"?n-=8:s.report.confidence==="medium"&&(n-=4);return Math.max(0,Math.min(100,Math.round(n)))}function Ue(e){const t=new Set;return e.filter(n=>{const a=`${n.anchor.id}-${Math.floor(n.anchor.timestamp/1e3)}`;return t.has(a)?!1:(t.add(a),!0)})}function Z(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}ge();document.querySelectorAll(".theme-btn").forEach(e=>e.addEventListener("click",we));const D=document.getElementById("upload-section"),ee=document.getElementById("processing-section"),te=document.getElementById("results-section"),g=document.getElementById("drop-zone"),C=document.getElementById("file-input"),V=document.getElementById("processing-text"),G=document.getElementById("overview-grid"),k=document.getElementById("incidents-section"),b=document.getElementById("event-table-wrap"),T=document.getElementById("event-log-filters-wrap"),L=document.getElementById("new-analysis-btn"),K=document.getElementById("results-sub");let E=[];C==null||C.addEventListener("change",e=>{var n;const t=(n=e.target.files)==null?void 0:n[0];t&&ne(t)});g==null||g.addEventListener("dragover",e=>{e.preventDefault(),g.classList.add("drag-over")});g==null||g.addEventListener("dragleave",()=>g.classList.remove("drag-over"));g==null||g.addEventListener("drop",e=>{var n;e.preventDefault(),g.classList.remove("drag-over");const t=(n=e.dataTransfer.files)==null?void 0:n[0];t&&ne(t)});L==null||L.addEventListener("click",je);var X;(X=document.getElementById("lp-backdrop"))==null||X.addEventListener("click",M);var Y;(Y=document.getElementById("lp-close"))==null||Y.addEventListener("click",M);document.addEventListener("keydown",e=>{e.key==="Escape"&&M()});async function ne(e){if(!e.name.toLowerCase().endsWith(".xml")&&e.type!=="text/xml"&&e.type!=="application/xml"){F("Please upload an XML file exported from Windows Event Viewer.");return}x(`Reading ${e.name}…`);try{const t=await e.text();x("Parsing events…"),await N();const n=Se(t);x(`Analysing ${n.length.toLocaleString()} events…`),await N();const a=Ae(n);E=n,x("Building report…"),await N(),He(a,e.name)}catch(t){F(t.message||"Failed to parse file."),I(D)}}function N(){return new Promise(e=>setTimeout(e,16))}function I(e){[D,ee,te].forEach(t=>{t&&(t.hidden=!0)}),e&&(e.hidden=!1)}function x(e){V&&(V.textContent=e),I(ee)}function je(){E=[],C&&(C.value=""),I(D)}function He(e,t){const{incidents:n,healthScore:a,computerName:s,stats:i}=e,o=document.querySelector(".results-title");if(o&&(o.textContent=t.replace(/\.xml$/i,"")),K){const c=[];s&&c.push(s),c.push(`${i.total.toLocaleString()} events`),n.length&&c.push(`${n.length} incident${n.length!==1?"s":""} detected`),K.textContent=c.join(" · ")}_e(a,i),Ve(n),Xe(E);const r=document.getElementById("tab-inc-count"),d=document.getElementById("tab-evt-count");r&&(r.textContent=n.length),d&&(d.textContent=i.total.toLocaleString()),document.querySelectorAll(".analyzer-tab").forEach(c=>{c.addEventListener("click",()=>{document.querySelectorAll(".analyzer-tab").forEach(w=>w.classList.remove("active")),c.classList.add("active");const u=c.dataset.tab;document.getElementById("incidents-section").hidden=u!=="incidents",document.getElementById("events-panel").hidden=u!=="events"})}),I(te)}function _e(e,t){if(!G)return;const n=e>=80?"#34d399":e>=60?"#f59e0b":"#f43f5e",a=e>=80?"Good":e>=60?"Degraded":"Critical";G.innerHTML=`
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
  `}function Ve(e){if(k){if(!e.length){k.innerHTML=`
      <div class="no-incidents">
        <div class="no-incidents-icon"><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div>
        <div class="no-incidents-title">No incidents detected</div>
        <div class="no-incidents-sub">No known crash or failure anchor events were found in this log.</div>
      </div>
    `;return}k.innerHTML=e.map((t,n)=>Ge(t)).join(""),k.querySelectorAll(".incident-toggle").forEach(t=>{t.addEventListener("click",n=>{if(n.target.closest("[data-lookup-id]"))return;const s=t.closest(".incident-card").querySelector(".incident-body"),i=t.querySelector(".incident-chevron"),o=!s.hidden;s.hidden=o,i.classList.toggle("open",!o)})}),k.querySelectorAll(".copy-summary-btn").forEach(t=>{t.addEventListener("click",()=>{const n=t.dataset.summary;navigator.clipboard.writeText(n).then(()=>{t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy for ticket",t.classList.remove("copied")},2e3)})})}),k.querySelectorAll(".evidence-item").forEach(t=>{t.addEventListener("click",n=>{if(n.stopPropagation(),n.target.closest("[data-lookup-id]"))return;const s=t.closest(".evidence-wrap").querySelector(".evidence-detail"),i=t.querySelector(".ev-expand-chevron"),o=!s.hidden;s.hidden=o,t.classList.toggle("expanded",!o),i&&(i.textContent=o?"▶":"▼")})}),k.querySelectorAll(".timeline-item").forEach(t=>{t.addEventListener("click",n=>{if(n.stopPropagation(),n.target.closest("[data-lookup-id]"))return;const a=t.closest(".timeline-item-wrap");if(!a)return;const s=a.querySelector(".timeline-detail");if(!s)return;const i=t.querySelector(".tl-expand-chevron"),o=!s.hidden;s.hidden=o,i&&(i.textContent=o?"▶":"▼")})}),k.querySelectorAll("[data-lookup-id]").forEach(t=>{t.addEventListener("click",n=>{n.stopPropagation(),ie(t.dataset.lookupId)})})}}function Ge(e,t){var w,h;const{anchor:n,windowEvents:a,topContributors:s,signatureResult:i,report:o}=e,r=(w=i[0])==null?void 0:w.signature,d=o.confidence,c=et(n.severity),u=d==="high"?"conf-high":d==="medium"?"conf-medium":"conf-low";return`
    <div class="incident-card">
      <div class="incident-header ${c} incident-toggle">
        <div class="incident-header-left">
          <span class="incident-icon">${(r==null?void 0:r.icon)??'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'}</span>
          <div>
            <div class="incident-title">${(r==null?void 0:r.name)??tt(n)}</div>
            <div class="incident-meta">
              <span class="incident-time">${n.timestamp.toLocaleString()}</span>
              <span class="incident-provider">${p(n.provider)}</span>
              ${o.confidenceReason?`<span class="conf-reason">${p(o.confidenceReason)}</span>`:""}
            </div>
          </div>
        </div>
        <div class="incident-header-right">
          <span class="conf-badge ${u}">${d}</span>
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
              <div class="evidence-wrap">
                <div class="evidence-item">
                  <span class="ev-sev-dot sev-${v.severity.toLowerCase()}"></span>
                  <span class="ev-id" data-lookup-id="${v.id}" title="Look up Event ${v.id}">${v.id}</span>
                  <span class="ev-provider">${p(A(v.provider))}</span>
                  <span class="ev-time">${ae(v.timestamp)}</span>
                  <span class="ev-score" title="Relevance score">${f}</span>
                  <span class="ev-expand-chevron">▶</span>
                </div>
                <div class="evidence-detail" hidden>${oe(v)}</div>
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
      <div class="incident-section-label">Timeline (${e.length} events in ${ze}-min window)</div>
      <div class="mini-timeline">
        ${s.map(i=>{var r;if(i._ellipsis)return`<div class="timeline-ellipsis">· · · ${i.count} more events · · ·</div>`;const o=i===t;return`
            <div class="timeline-item-wrap">
              <div class="timeline-item ${o?"timeline-anchor":""}">
                <div class="tl-dot sev-${(r=i.severity)==null?void 0:r.toLowerCase()}"></div>
                <div class="tl-content">
                  <span class="tl-time">${ae(i.timestamp)}</span>
                  <span class="tl-id" data-lookup-id="${i.id}" title="Look up Event ${i.id}">${i.id}</span>
                  <span class="tl-provider">${p(A(i.provider))}</span>
                  ${o?'<span class="tl-anchor-label">ANCHOR</span>':""}
                </div>
                <span class="tl-expand-chevron">▶</span>
              </div>
              <div class="timeline-detail" hidden>${oe(i)}</div>
            </div>
          `}).join("")}
      </div>
    </div>
  `}const ze=15,Fe=new Set(["Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting","Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-DistributedCOM","Microsoft-Windows-Security-SPP","Microsoft-Windows-Defrag","Microsoft-Windows-Power-Troubleshooter"]),z={Critical:0,Error:1,Warning:2,Info:3,Verbose:4},l={sortCol:"timestamp",sortDir:"asc",page:0,pageSize:100,query:"",severities:new Set,provider:"",channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set};function Xe(e){var r,d;if(!T||!b)return;Object.assign(l,{sortCol:"timestamp",sortDir:"asc",page:0,query:"",severities:new Set,provider:"",channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set});const t=[...new Set(e.map(c=>c.provider).filter(Boolean))].sort(),n=[...new Set(e.map(c=>c.channel).filter(Boolean))].sort(),a=c=>c?new Date(c-c.getTimezoneOffset()*6e4).toISOString().slice(0,16):"",s=(r=e[0])==null?void 0:r.timestamp,i=(d=e[e.length-1])==null?void 0:d.timestamp;T.innerHTML=`
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

      <select id="tbl-provider" class="filter-control filter-control-select">
        <option value="">All providers</option>
        ${t.map(c=>`<option value="${p(c)}">${p(A(c))}</option>`).join("")}
      </select>

      <select id="tbl-channel" class="filter-control filter-control-select">
        <option value="">All channels</option>
        ${n.map(c=>`<option value="${p(c)}">${p(c)}</option>`).join("")}
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
  `;const o=(c,u,w)=>{var h;return(h=document.getElementById(c))==null?void 0:h.addEventListener(u,w)};o("tbl-query","input",c=>{l.query=c.target.value,l.page=0,y()}),T.querySelectorAll(".tbl-sev-cb").forEach(c=>{c.addEventListener("change",()=>{c.checked?l.severities.add(c.value):l.severities.delete(c.value),c.closest(".sev-chip").classList.toggle("active",c.checked),l.page=0,y()})}),o("tbl-provider","change",c=>{l.provider=c.target.value,l.page=0,y()}),o("tbl-channel","change",c=>{l.channel=c.target.value,l.page=0,y()}),o("tbl-from","change",c=>{l.fromTime=c.target.value,l.page=0,y()}),o("tbl-to","change",c=>{l.toTime=c.target.value,l.page=0,y()}),o("tbl-noise","click",c=>{l.hideNoisy=!l.hideNoisy,l.page=0,c.target.classList.toggle("active",l.hideNoisy),c.target.textContent=l.hideNoisy?"Show noise":"Hide noise",y()}),o("tbl-csv","click",()=>Qe(se())),y()}function se(){const e=l.query.toLowerCase(),t=l.fromTime?new Date(l.fromTime).getTime():null,n=l.toTime?new Date(l.toTime).getTime():null;let a=E.filter(s=>{if(l.severities.size>0&&!l.severities.has(s.severity)||l.provider&&s.provider!==l.provider||l.channel&&s.channel!==l.channel||t!==null&&s.timestamp<t||n!==null&&s.timestamp>n||l.hideNoisy&&Fe.has(s.provider))return!1;if(e){const i=/^\d+$/.test(e)?parseInt(e,10):null;if(i!==null){if(s.id!==i)return!1}else if(!`${s.id} ${s.provider} ${s.channel} ${s.message} ${s.severity}`.toLowerCase().includes(e))return!1}return!0});return a.sort((s,i)=>{let o=0;switch(l.sortCol){case"timestamp":o=s.timestamp-i.timestamp;break;case"severity":o=(z[s.severity]??9)-(z[i.severity]??9);break;case"id":o=s.id-i.id;break;case"provider":o=(s.provider||"").localeCompare(i.provider||"");break}return l.sortDir==="asc"?o:-o}),a}function y(){if(!b)return;const e=se(),t=e.length,n=Math.max(0,Math.ceil(t/l.pageSize)-1);l.page=Math.min(l.page,n);const a=l.page*l.pageSize,s=e.slice(a,a+l.pageSize);if(!t){b.innerHTML='<div class="table-empty">No events match the current filters.</div>';return}const i=d=>`<span class="sort-arrow ${l.sortCol===d?"active":""}">${l.sortCol===d?l.sortDir==="asc"?"↑":"↓":"↕"}</span>`,o=d=>l.sortCol===d?"sort-active":"";b.innerHTML=`
    <div class="table-info-bar">
      <span class="table-count-text">
        ${(a+1).toLocaleString()}–${Math.min(a+l.pageSize,t).toLocaleString()} of ${t.toLocaleString()} event${t!==1?"s":""}
        ${t<E.length?` (${E.length.toLocaleString()} total)`:""}
      </span>
      <div class="table-pagination">
        <button class="page-btn" id="pg-first" ${l.page===0?"disabled":""}>«</button>
        <button class="page-btn" id="pg-prev"  ${l.page===0?"disabled":""}>‹ Prev</button>
        <span class="page-info">Page ${l.page+1} / ${n+1}</span>
        <button class="page-btn" id="pg-next"  ${l.page>=n?"disabled":""}>Next ›</button>
        <button class="page-btn" id="pg-last"  ${l.page>=n?"disabled":""}>»</button>
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
      <tbody>${s.map(d=>Ye(d)).join("")}</tbody>
    </table>
  `,b.querySelectorAll("th[data-sort]").forEach(d=>{d.addEventListener("click",()=>{const c=d.dataset.sort;l.sortDir=l.sortCol===c&&l.sortDir==="asc"?"desc":"asc",l.sortCol=c,l.page=0,y()})});const r=(d,c)=>{var u;return(u=document.getElementById(d))==null?void 0:u.addEventListener("click",c)};r("pg-first",()=>{l.page=0,y()}),r("pg-prev",()=>{l.page--,y()}),r("pg-next",()=>{l.page++,y()}),r("pg-last",()=>{l.page=n,y()}),b.querySelectorAll("tbody tr[data-record]").forEach(d=>{d.addEventListener("click",c=>{if(c.target.closest(".table-event-id"))return;const u=parseInt(d.dataset.record,10);l.expandedIds.has(u)?l.expandedIds.delete(u):l.expandedIds.add(u),y()})}),b.querySelectorAll(".table-event-id").forEach(d=>{d.addEventListener("click",c=>{c.stopPropagation(),ie(d.dataset.lookupId)})}),b.querySelectorAll(".ev-advanced-toggle").forEach(d=>{d.addEventListener("click",c=>{c.stopPropagation();const w=d.closest(".ev-detail-inner").querySelector(".ev-advanced-section").classList.toggle("ev-advanced-open");d.textContent=w?"Advanced ▲":"Advanced ▼"})})}function Ye(e){var v;const t=l.expandedIds.has(e.recordId),n=e.severity.toLowerCase(),a=Object.keys(e.data||{}),s=e.message?p(e.message.substring(0,150))+(e.message.length>150?"…":""):'<span style="color:var(--text3);font-style:italic">no message</span>',i=`
    <tr class="ev-row-${n}${t?" row-expanded":""}" data-record="${e.recordId}">
      <td class="ev-col-expand">${t?"▼":"▶"}</td>
      <td class="ev-col-time">${Ze(e.timestamp)}</td>
      <td><span class="sev-badge sev-badge-${n}">${e.severity}</span></td>
      <td><span class="table-event-id" data-lookup-id="${e.id}" title="Look up Event ${e.id}">${e.id}</span></td>
      <td class="ev-col-provider" title="${p(e.provider)}">${p(A(e.provider))}</td>
      <td class="ev-col-channel">${p(e.channel)}</td>
      <td class="ev-col-message">${s}</td>
    </tr>`;if(!t)return i;const o=e.taskName||e.task||null,r=e.opcodeName||e.opcode||null,d=(v=e.keywordNames)!=null&&v.length?e.keywordNames.join(", "):e.keywords||null,c=[["Time (local)",e.timestamp.toLocaleString()],["Time (UTC)",e.timestamp.toISOString()],["Provider",e.provider],["Channel",e.channel],["Computer",e.computer],["Record ID",e.recordId||null],["User SID",e.userSID],["Process ID",e.processId||null],["Thread ID",e.threadId||null],["Activity ID",e.activityId],["Related Act. ID",e.relatedActivityId],["Task",o],["Opcode",r],["Keywords",d]].filter(([,f])=>f),u=[["Raw Level",String(e.levelNum)],["Raw Task",e.task],["Raw Opcode",e.opcode],["Raw Keywords",e.keywords],["Version",e.version],["Qualifiers",e.qualifiers],["Provider Desc.",e.providerDescription]].filter(([,f])=>f),w=e.message?`<div class="ev-detail-message">${p(e.message)}</div>`:`<div class="ev-detail-message ev-no-message">
        Message not rendered — Windows message templates are stored on the source machine.
        Export directly from the affected computer to see full event messages.
       </div>`,h=e.dataAnon||[];return i+`
    <tr class="ev-detail-row">
      <td colspan="7">
        <div class="ev-detail-inner">
          ${w}
          <div class="ev-detail-meta">
            ${c.map(([f,m])=>`
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
    </tr>`}function Qe(e){const t=["Time (UTC)","Severity","EventID","Provider","Channel","Computer","RecordID","ProcessID","ThreadID","UserSID","ActivityID","RelatedActivityID","Task","TaskName","Opcode","OpcodeName","Keywords","KeywordNames","Version","Qualifiers","ProviderDescription","Message","EventData","EventDataAnon"],n=r=>`"${String(r??"").replace(/"/g,'""').replace(/\r?\n/g," ")}"`,a=e.map(r=>[r.timestamp.toISOString(),r.severity,r.id,n(r.provider),n(r.channel),n(r.computer),r.recordId,r.processId||"",r.threadId||"",n(r.userSID),n(r.activityId),n(r.relatedActivityId),n(r.task),n(r.taskName),n(r.opcode),n(r.opcodeName),n(r.keywords),n((r.keywordNames||[]).join("; ")),n(r.version),n(r.qualifiers),n(r.providerDescription),n(r.message),n(Object.entries(r.data||{}).map(([d,c])=>`${d}=${c}`).join("; ")),n((r.dataAnon||[]).join("; "))].join(",")),s=[t.join(","),...a].join(`\r
`),i=URL.createObjectURL(new Blob([s],{type:"text/csv;charset=utf-8;"})),o=Object.assign(document.createElement("a"),{href:i,download:`eventful-${new Date().toISOString().slice(0,10)}.csv`});document.body.appendChild(o),o.click(),document.body.removeChild(o),URL.revokeObjectURL(i)}function ie(e){const t=parseInt(e,10),n=document.getElementById("lookup-panel"),a=document.getElementById("lp-body");if(!n||!a)return;const s=ye.find(o=>o.id===t),i=E.filter(o=>o.id===t);a.innerHTML=Je(t,s,i),n.hidden=!1,a.querySelectorAll(".lp-copy-ps").forEach(o=>{o.addEventListener("click",()=>{navigator.clipboard.writeText(o.dataset.code).then(()=>{o.textContent="Copied!",setTimeout(()=>{o.textContent="Copy"},2e3)})})}),a.querySelectorAll(".lp-show-in-log").forEach(o=>{o.addEventListener("click",()=>{const r=o.dataset.filterId;M(),document.querySelectorAll(".analyzer-tab").forEach(u=>u.classList.remove("active"));const d=document.querySelector('.analyzer-tab[data-tab="events"]');d&&d.classList.add("active"),document.getElementById("incidents-section").hidden=!0,document.getElementById("events-panel").hidden=!1,l.query=r,l.page=0;const c=document.getElementById("tbl-query");c&&(c.value=r),y()})})}function M(){const e=document.getElementById("lookup-panel");e&&(e.hidden=!0)}function Je(e,t,n){var s,i,o;const a=n.length?`<button class="lp-show-in-log" data-filter-id="${e}">Show all ${n.length} occurrence${n.length!==1?"s":""} in All Events →</button>`:"";if(t){const r=((s=t.severity)==null?void 0:s.toLowerCase())??"info";return`
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
            ${t.causes.map(d=>`<li>${p(d)}</li>`).join("")}
          </ul>`:""}
        ${(o=t.steps)!=null&&o.length?`
          <div class="lp-subsection-label">Investigation Steps</div>
          <ol class="lp-steps">
            ${t.steps.map(d=>`<li>${p(d)}</li>`).join("")}
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
    </div>`}function oe(e){var o;const t=e.taskName||e.task||null,n=e.opcodeName||e.opcode||null,a=(o=e.keywordNames)!=null&&o.length?e.keywordNames.join(", "):e.keywords||null,s=e.dataAnon||[],i=Object.keys(e.data||{});return`
    <div class="ev-inline-detail">
      <div class="lp-raw-fields">
        ${S("Time",e.timestamp.toLocaleString())}
        ${S("Severity",`<span class="sev-badge sev-badge-${e.severity.toLowerCase()}">${e.severity}</span>`)}
        ${S("Provider",p(e.provider||"—"))}
        ${S("Channel",p(e.channel||"—"))}
        ${e.computer?S("Computer",p(e.computer)):""}
        ${e.recordId?S("Record ID",String(e.recordId)):""}
        ${e.processId?S("Process ID",String(e.processId)):""}
        ${e.userSID?S("User SID",p(e.userSID)):""}
        ${t?S("Task",p(t)):""}
        ${n?S("Opcode",p(n)):""}
        ${a?S("Keywords",p(a)):""}
      </div>
      <div class="lp-raw-message-label">Message</div>
      ${e.message?`<div class="lp-raw-message">${p(e.message)}</div>`:'<div class="lp-raw-message lp-no-message">Message not rendered — Windows message templates are stored on the source machine. Export from the affected computer to see full messages.</div>'}
      ${i.length||s.length?`
        <div class="lp-raw-message-label">Event Data</div>
        <div class="lp-raw-data">
          ${i.map(r=>`
            <div class="lp-raw-data-row">
              <span class="lp-raw-data-key">${p(r)}</span>
              <span class="lp-raw-data-val">${p(String(e.data[r]))}</span>
            </div>`).join("")}
          ${s.map((r,d)=>`
            <div class="lp-raw-data-row">
              <span class="lp-raw-data-key lp-raw-data-key--anon">[${d}]</span>
              <span class="lp-raw-data-val">${p(String(r))}</span>
            </div>`).join("")}
        </div>`:""}
      <div class="ev-detail-actions">
        <span class="ev-detail-lookup-btn" data-lookup-id="${e.id}">Look up Event ${e.id} →</span>
      </div>
    </div>`}function S(e,t){return`
    <div class="lp-raw-field">
      <span class="lp-raw-key">${e}</span>
      <span class="lp-raw-val">${t}</span>
    </div>`}function F(e){const t=g==null?void 0:g.querySelector(".upload-error");t&&t.remove();const n=document.createElement("div");n.className="upload-error",n.textContent=e,g==null||g.appendChild(n),I(D)}function p(e){return e?String(e).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"):""}function A(e){return e?e.replace(/^Microsoft-Windows-/i,"").replace(/^Microsoft-/i,""):"—"}function ae(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}function Ze(e){return e.toLocaleString([],{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})}function et(e){return`sev-header-${(e==null?void 0:e.toLowerCase())??"info"}`}function tt(e){return{41:"Unexpected System Reboot",6008:"Unexpected Shutdown Detected",1001:"System Crash (BSOD)",1e3:"Application Crash",7024:"Critical Service Failure"}[e.id]??`Event ${e.id}`}
