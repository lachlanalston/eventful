import{i as ge,t as fe}from"./theme-gEBc2EcC.js";import{a as we}from"./index-BAM9NZ7H.js";function ye(e){const n=new DOMParser().parseFromString(e,"text/xml"),r=n.querySelector("parsererror");if(r)throw new Error(`Invalid XML: ${r.textContent.substring(0,120)}`);const s=n.querySelectorAll("Event");if(s.length===0)throw new Error("No <Event> elements found. Make sure you exported in XML format from Event Viewer.");const o=[];for(const a of s)try{const c=Se(a);!isNaN(c.id)&&c.id>0&&c.timestamp instanceof Date&&!isNaN(c.timestamp)&&o.push(c)}catch{}if(o.length===0)throw new Error("No valid events could be parsed. Check that the XML is a Windows Event Viewer export.");return o.sort((a,c)=>a.timestamp-c.timestamp)}function Se(e){var O,W,q,U,j,H,_,V,G;const t=e.querySelector("System"),n=parseInt(k(t,"EventID"),10),r=parseInt(k(t,"Level"),10),s=t==null?void 0:t.querySelector("Provider"),o=(s==null?void 0:s.getAttribute("Name"))||(s==null?void 0:s.getAttribute("EventSourceName"))||"",a=k(t,"Channel"),c=k(t,"Computer"),d=parseInt(k(t,"EventRecordID"),10),i=t==null?void 0:t.querySelector("TimeCreated"),u=(i==null?void 0:i.getAttribute("SystemTime"))||(i==null?void 0:i.textContent)||"",f=new Date(u),h=t==null?void 0:t.querySelector("Execution"),v=t==null?void 0:t.querySelector("Correlation"),g=t==null?void 0:t.querySelector("Security"),m=e.querySelector("RenderingInfo"),M=(W=(O=m==null?void 0:m.querySelector("Level"))==null?void 0:O.textContent)==null?void 0:W.trim(),$=be(r,M),E=((U=(q=m==null?void 0:m.querySelector("Task"))==null?void 0:q.textContent)==null?void 0:U.trim())||"",le=((H=(j=m==null?void 0:m.querySelector("Opcode"))==null?void 0:j.textContent)==null?void 0:H.trim())||"",de=[...(m==null?void 0:m.querySelectorAll("Keywords > Keyword"))??[]].map(he=>he.textContent.trim()).filter(Boolean),pe=((V=(_=m==null?void 0:m.querySelector("Provider"))==null?void 0:_.textContent)==null?void 0:V.trim())||"",ue=$e(e,m),{named:ve,anon:me}=ke(e);return{id:n,provider:o,channel:a,levelNum:r,severity:$,timestamp:f,computer:c,message:ue,recordId:isNaN(d)?0:d,processId:parseInt(h==null?void 0:h.getAttribute("ProcessID"),10)||0,threadId:parseInt(h==null?void 0:h.getAttribute("ThreadID"),10)||0,activityId:(v==null?void 0:v.getAttribute("ActivityID"))||"",relatedActivityId:(v==null?void 0:v.getAttribute("RelatedActivityID"))||"",userSID:(g==null?void 0:g.getAttribute("UserID"))||"",task:k(t,"Task"),opcode:k(t,"Opcode"),keywords:k(t,"Keywords"),taskName:E,opcodeName:le,keywordNames:de,providerDescription:pe,version:k(t,"Version"),qualifiers:((G=t==null?void 0:t.querySelector("EventID"))==null?void 0:G.getAttribute("Qualifiers"))||"",data:ve,dataAnon:me}}function k(e,t){var n,r;return((r=(n=e==null?void 0:e.querySelector(t))==null?void 0:n.textContent)==null?void 0:r.trim())||""}function $e(e,t){var o,a;const n=(a=(o=t==null?void 0:t.querySelector("Message"))==null?void 0:o.textContent)==null?void 0:a.trim();if(n)return n;const r=e.querySelector("EventData");if(r){const c=[];for(const d of r.querySelectorAll("Data")){const i=d.getAttribute("Name"),u=d.textContent.trim();u&&u!=="-"&&c.push(i?`${i}: ${u}`:u)}if(c.length)return c.join(" | ")}const s=e.querySelector("UserData");return s?s.textContent.trim():""}function ke(e){const t={},n=[],r=e.querySelector("EventData");if(!r)return{named:t,anon:n};for(const s of r.querySelectorAll("Data")){const o=s.getAttribute("Name"),a=s.textContent.trim();o?a&&(t[o]=a):a&&n.push(a)}return{named:t,anon:n}}function be(e,t){if(t){const n=t.toLowerCase();if(n.includes("critical"))return"Critical";if(n.includes("error"))return"Error";if(n.includes("warning"))return"Warning";if(n.includes("information"))return"Info";if(n.includes("verbose"))return"Verbose";if(n.includes("audit"))return t.includes("Failure")?"Error":"Info"}switch(e){case 1:return"Critical";case 2:return"Error";case 3:return"Warning";case 4:return"Info";case 5:return"Verbose";case 0:return"Info";default:return"Info"}}const Ee=new Set([41,6008,1001,1e3,7024]),K={7:40,11:30,51:40,52:30,55:35,57:25,129:20,153:20,4101:50,1001:45,1e3:35,1002:30,1026:20,7031:25,7034:25,7022:20,7023:20,7001:15,7011:15,1014:20,4202:20,4201:15,17:50,18:40,19:30,4625:10,4740:15},Ce=new Set(["Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting"]),Ie=[{id:"gpu-driver-crash",name:"GPU Driver Crash",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',category:"Hardware Driver",test(e){const t=["nvlddmkm","amdkmdag","amd","igdkmd","dxgkrnl","atikmdag"],n=e.some(s=>s.id===4101),r=e.find(s=>t.some(o=>{var a;return(a=s.provider)==null?void 0:a.toLowerCase().includes(o)}));return n?{match:!0,confidence:"high",reason:"Event 4101 (display driver TDR timeout) found in window"}:r?{match:!0,confidence:"medium",reason:`GPU provider "${r.provider}" found in window — no Event 4101`}:{match:!1}},what:"The graphics card driver stopped responding and Windows could not recover it.",rootCause:"Display driver (TDR timeout) caused the system to become unresponsive.",nextSteps:["Update or roll back GPU drivers via Device Manager → Display Adapters","Use DDU (Display Driver Uninstaller) in Safe Mode for clean reinstall","Monitor GPU temperatures under load with GPU-Z or HWiNFO64","Run GPU stability test with FurMark or 3DMark","Check GPU power connector seating if system is recently assembled"],technicianHint:'NVIDIA: look for "nvlddmkm" in Event 4101 faulting module. AMD: "atikmpag" or "amdkmdag". DDU clean reinstall resolves driver corruption in ~70% of cases. If temps are fine and fresh driver fails, suspect hardware.'},{id:"disk-failure",name:"Storage / Disk Error",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/></svg>',category:"Storage",test(e){const t=[7,11,51,52,55,57,129,153],n=["disk","atapi","nvme","storport","ntfs","fastfat","stornvme"],r=e.filter(o=>t.includes(o.id)||n.some(a=>{var c;return(c=o.provider)==null?void 0:c.toLowerCase().includes(a)})),s=[...new Set(r.map(o=>o.id))].join(", ");return r.length>=3?{match:!0,confidence:"high",reason:`${r.length} disk error events in window (IDs: ${s})`}:r.length>=1?{match:!0,confidence:"medium",reason:`${r.length} disk error event in window (ID: ${s})`}:{match:!1}},what:"The storage device reported I/O errors before the incident.",rootCause:"Disk hardware errors were detected — possible drive failure, bad sectors, or controller issue.",nextSteps:["Run CrystalDiskInfo — check SMART reallocated/pending/uncorrectable sectors","Run chkdsk /f /r /x on affected volume","Run manufacturer disk diagnostic (SeaTools, WD Dashboard, Samsung Magician)","Check SATA/power cable connections","Consider imaging and replacing drive if SMART shows degradation"],technicianHint:"Event 7 = hardware error from disk.sys. Event 51 = error during paging (system swapping to bad sectors — urgent). Event 55 = NTFS filesystem corruption. Multiple Event 7 in a short window usually means imminent failure."},{id:"bsod-kernel-crash",name:"Blue Screen of Death (BSOD)",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',category:"Kernel Crash",test(e,t){return t.id===1001?{match:!0,confidence:"high",reason:"Event 1001 (BugCheck) is the anchor — BSOD confirmed"}:e.some(n=>n.id===1001)?{match:!0,confidence:"high",reason:"Event 1001 (BugCheck/BSOD) found in window events"}:{match:!1}},what:"Windows detected an unrecoverable kernel error and created a memory dump.",rootCause:"A kernel or driver-level fault caused Windows to stop to prevent data corruption.",nextSteps:["Note the BugCheck code from Event 1001 details","Analyse minidump with WhoCrashed (free) or WinDbg (!analyze -v)","Run SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth","Run Windows Memory Diagnostic for MEMORY_MANAGEMENT (0x1A) stops","Update all drivers — especially GPU, NIC, and chipset"],technicianHint:"Common stop codes: 0x50 PAGE_FAULT (bad RAM or driver), 0x3B SYSTEM_SERVICE_EXCEPTION (driver), 0x1A MEMORY_MANAGEMENT (RAM), 0x7E SYSTEM_THREAD_EXCEPTION (driver), 0x0A IRQL_NOT_LESS_OR_EQUAL (driver/RAM). WhoCrashed gives the culprit driver in seconds."},{id:"service-crash-chain",name:"Service Crash Loop",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',category:"Windows Services",test(e){const t=[7031,7034,7022,7023,7024,7001,7011],n=e.filter(s=>t.includes(s.id)),r=[...new Set(n.map(s=>s.id))].join(", ");return n.length>=5?{match:!0,confidence:"high",reason:`${n.length} service failure events in window (IDs: ${r})`}:n.length>=2?{match:!0,confidence:"medium",reason:`${n.length} service failure events in window (IDs: ${r})`}:{match:!1}},what:"One or more Windows services crashed or failed to start repeatedly.",rootCause:"Service instability — possibly caused by a failed update, corrupted binary, or missing dependency.",nextSteps:["Identify which service(s) crashed from the event messages","Check service recovery settings: Services → right-click service → Properties → Recovery","Verify the service executable exists and is not corrupted","Check for related Application log events (Event 1000) for the service host","Review recent Windows Updates that may have changed the service"],technicianHint:"Event 7031 = service terminated unexpectedly (count tells you how many times). Event 7034 = crashed without telling SCM. The service name is in the event message. If it's svchost-hosted, check the service group."},{id:"application-crash-loop",name:"Application Crash Loop",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',category:"Application",test(e){const t=e.filter(n=>n.id===1e3);return t.length>=3?{match:!0,confidence:"high",reason:`${t.length} Event 1000 (application crash) in window`}:t.length>=1?{match:!0,confidence:"medium",reason:"1 Event 1000 (application crash) in window"}:{match:!1}},what:"An application was crashing repeatedly before the incident.",rootCause:"Application instability — possible corrupt installation, missing runtime, or incompatible update.",nextSteps:["Identify the crashing application from the Event 1000 message","Note the faulting module — it often identifies a specific DLL","Update or reinstall the application","Install/repair Visual C++ Redistributables if a runtime DLL faults","Check crash dumps in %LocalAppData%\\CrashDumps or the application's folder"],technicianHint:'The faulting module in Event 1000 is gold — "ntdll.dll" = OS issue or heap corruption, "msvcp140.dll" / "vcruntime140.dll" = missing C++ runtime, "AppName.exe" itself = bad binary. Repeated same app + same module = deterministic, reproducible fault.'},{id:"memory-hardware",name:"Memory / RAM Issue",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/></svg>',category:"Hardware",test(e){const t=["microsoft-windows-memoryd","whea-logger","microsoft-windows-whea"],n=[17,18,19,1],r=e.find(o=>n.includes(o.id)||t.some(a=>{var c;return(c=o.provider)==null?void 0:c.toLowerCase().includes(a)}));return e.some(o=>{var a,c;return o.id===1001&&(((a=o.data)==null?void 0:a.BugcheckCode)==="26"||((c=o.data)==null?void 0:c.BugcheckCode)==="80")})?{match:!0,confidence:"medium",reason:"BSOD stop code indicates memory fault (0x1A MEMORY_MANAGEMENT or 0x50 PAGE_FAULT)"}:r?{match:!0,confidence:"medium",reason:`Memory/WHEA event detected (Event ${r.id} from ${r.provider||"unknown provider"})`}:{match:!1}},what:"Hardware memory errors or RAM-related faults were detected.",rootCause:"Defective or misconfigured RAM caused uncorrectable memory errors.",nextSteps:["Run MemTest86+ overnight (at least 2 passes)","Test RAM sticks one at a time to isolate the faulty module","Reseat RAM modules and clean contacts","Check XMP/EXPO profile stability — reset to JEDEC spec in BIOS","Check WHEA-Logger events for corrected/uncorrected error counts"],technicianHint:`WHEA Event 17/18/19 = hardware error framework caught a hardware error. Check the ErrorSource field — "MCE" (Machine Check Exception) = hardware fault, usually RAM or CPU. MemTest86+ is the definitive test. Don't trust Windows Memory Diagnostic for subtle faults.`},{id:"unexpected-power",name:"Unexpected Power Loss",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',category:"Power",test(e,t){var n;return t.id===41&&((n=t.data)==null?void 0:n.BugcheckCode)==="0"?{match:!0,confidence:"high",reason:"Event 41 BugcheckCode=0 — hard power loss confirmed (not a software crash)"}:(t.id===41||t.id===6008)&&e.length<=3?{match:!0,confidence:"medium",reason:`Only ${e.length} event(s) before anchor — abrupt stop, no software lead-up`}:{match:!1}},what:"The system lost power without going through a normal shutdown.",rootCause:"Hard power loss — possible PSU failure, power outage, or UPS failure.",nextSteps:["Check UPS health, battery test, and log — replace battery if > 3 years old","Test PSU voltage rails with PC Power Supply Tester or multimeter","Check power outlet and surge protector for faults","Review Event 41 BugcheckCode: 0 = power loss, non-0 = software crash","Install UPS with AVR if not present — protects against brownouts"],technicianHint:"Event 41 BugcheckCode=0 is definitive: the machine lost power while running (no BSOD, no clean shutdown). Very few preceding events confirms sudden loss. Multiple occurrences = PSU is failing. Check 12V rail — HDD-heavy systems are sensitive."},{id:"network-failure",name:"Network / Connectivity Failure",icon:'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',category:"Network",test(e){const t=[1014,4202,4201,6100],n=["tcpip","dns-client","dhcp","netbt","netlogon","rras"],r=e.filter(o=>t.includes(o.id)||n.some(a=>{var c;return(c=o.provider)==null?void 0:c.toLowerCase().includes(a)})),s=[...new Set(r.map(o=>o.id))].join(", ");return r.length>=3?{match:!0,confidence:"medium",reason:`${r.length} network/DNS events in window (IDs: ${s})`}:r.length>=1?{match:!0,confidence:"low",reason:`1 network/DNS event in window (ID: ${s})`}:{match:!1}},what:"Network or DNS errors were recorded in the period leading up to the incident.",rootCause:"Network connectivity failure caused application or service faults.",nextSteps:["Check NIC driver version — update if outdated",'Disable NIC power management: Device Manager → NIC → Power Management → uncheck "Allow computer to turn off"',"Test DNS resolution: nslookup google.com","Review DHCP lease renewal logs","Check switch port, cable, and NIC hardware"],technicianHint:"Event 1014 = DNS client resolver timeout. If you see it, look at the DNS server IP in the event — a failing DC or DNS server is a common cause. Event 4201/4202 = NIC connection state changes = intermittent cable or switch issue."}],De=15,xe={Critical:30,Error:20,Warning:10,Info:2,Verbose:0};function Ae(e){var c;if(!e.length)return{incidents:[],healthScore:100,computerName:"",stats:Oe()};const t=((c=e[0])==null?void 0:c.computer)||"",n=te(e),r=Me(e),s=[];for(const d of r){const i=Te(e,d,De),f=Le(i,d).slice(0,8),h=Ne(i,d),v=Re(d,h,f);s.push({anchor:d,windowEvents:i,topContributors:f,signatureResult:h,report:v})}const o=qe(s),a=We(e,o);return{incidents:o,healthScore:a,computerName:t,stats:n}}function Me(e){const t=[],n=new Set;for(const r of e){if(!Ee.has(r.id))continue;const s=`${r.id}-${Math.floor(r.timestamp/3e4)}`;n.has(s)||(n.add(s),t.push(r))}return t.sort((r,s)=>s.timestamp-r.timestamp).slice(0,5)}function Te(e,t,n){const r=t.timestamp-n*6e4;return e.filter(s=>s.timestamp>=r&&s.timestamp<t.timestamp)}function Le(e,t){const n=e.map(s=>{let o=xe[s.severity]??0;K[s.id]&&(o+=K[s.id]),s.provider&&t.provider&&s.provider===t.provider&&(o+=8),Ce.has(s.provider)&&(o=Math.max(0,o-15));const a=(t.timestamp-s.timestamp)/6e4;return a<2?o+=10:a<5&&(o+=5),{event:s,score:o}}),r=new Map;for(const{event:s}of n){const o=`${s.id}-${s.provider}`;r.set(o,(r.get(o)||0)+1)}for(const s of n){const o=`${s.event.id}-${s.event.provider}`,a=r.get(o)||1;a>=5?s.score+=15:a>=3?s.score+=8:a>=2&&(s.score+=4)}return n.filter(({score:s})=>s>0).sort((s,o)=>o.score-s.score).map(({event:s,score:o})=>({event:s,score:o}))}function Ne(e,t){const n=[];for(const s of Ie)try{const o=s.test(e,t);o.match&&n.push({signature:s,confidence:o.confidence,reason:o.reason||""})}catch{}const r={high:0,medium:1,low:2};return n.sort((s,o)=>(r[s.confidence]??3)-(r[o.confidence]??3)),n}function Re(e,t,n,r){const s=t[0],o=s==null?void 0:s.signature,a=(s==null?void 0:s.confidence)??"low",c=(s==null?void 0:s.reason)||"",d=ee[e.id]??`Event ${e.id}`,i=(o==null?void 0:o.what)??`${d} occurred at ${ne(e.timestamp)}.`,u=(o==null?void 0:o.rootCause)??Pe(e,n),f=(o==null?void 0:o.nextSteps)??["Review event details for more information","Check System and Application logs for context"],h=o==null?void 0:o.technicianHint,v=Be(e,o,n,a,c);return{what:i,rootCause:u,confidence:a,confidenceReason:c,nextSteps:f,technicianHint:h,psaSummary:v,alternateSignatures:t.slice(1,3),evidenceCount:n.length}}const ee={41:"Unexpected system reboot (Kernel-Power)",6008:"Unexpected previous shutdown (EventLog)",1001:"System crash / BSOD (BugCheck)",1e3:"Application crash (Application Error)",7024:"Critical service failure"};function Pe(e,t){if(!t.length)return"No significant preceding events identified in the lookback window.";const n=t[0].event;return`Leading event: ${n.provider||"Unknown"} Event ${n.id} (${n.severity}) recorded shortly before the incident.`}function Be(e,t,n,r,s){return["INCIDENT SUMMARY","================",`Date/Time: ${e.timestamp.toLocaleString()}`,`Anchor Event: ${e.id} — ${ee[e.id]??"Unknown"}`,`Provider: ${e.provider||"Unknown"}`,`Computer: ${e.computer||"Unknown"}`,"","DIAGNOSIS","---------",t?`Pattern: ${t.name} (${t.category})`:"Pattern: No known pattern matched",`Confidence: ${r.toUpperCase()}${s?` — ${s}`:""}`,"",t?`What happened: ${t.what}`:"",t?`Root cause: ${t.rootCause}`:"","",`CONTRIBUTING EVENTS (top ${Math.min(n.length,5)})`,"------------------",...n.slice(0,5).map(({event:c})=>`  [${c.severity}] Event ${c.id} — ${c.provider||"Unknown"} @ ${ne(c.timestamp)}`),"","SUGGESTED NEXT STEPS","--------------------",...((t==null?void 0:t.nextSteps)??["Review event log for more context"]).map(c=>`  • ${c}`),"","Generated by Eventful Incident Analyzer"].filter(c=>c!==void 0).join(`
`)}function te(e){const t={Critical:0,Error:0,Warning:0,Info:0,Verbose:0};for(const n of e)t[n.severity]=(t[n.severity]||0)+1;return{total:e.length,...t}}function Oe(){return{total:0,Critical:0,Error:0,Warning:0,Info:0,Verbose:0}}function We(e,t){let n=100;const r=te(e);n-=Math.min(r.Critical*15,40),n-=Math.min(r.Error*3,25),n-=Math.min(r.Warning*.5,10),n-=t.length*12;for(const s of t)s.report.confidence==="high"?n-=8:s.report.confidence==="medium"&&(n-=4);return Math.max(0,Math.min(100,Math.round(n)))}function qe(e){const t=new Set;return e.filter(n=>{const r=`${n.anchor.id}-${Math.floor(n.anchor.timestamp/1e3)}`;return t.has(r)?!1:(t.add(r),!0)})}function ne(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}ge();document.querySelectorAll(".theme-btn").forEach(e=>e.addEventListener("click",fe));const L=document.getElementById("upload-section"),se=document.getElementById("processing-section"),ie=document.getElementById("results-section"),w=document.getElementById("drop-zone"),D=document.getElementById("file-input"),F=document.getElementById("processing-text"),z=document.getElementById("overview-grid"),I=document.getElementById("incidents-section"),b=document.getElementById("event-table-wrap"),R=document.getElementById("event-log-filters-wrap"),P=document.getElementById("new-analysis-btn"),X=document.getElementById("results-sub");let C=[];D==null||D.addEventListener("change",e=>{var n;const t=(n=e.target.files)==null?void 0:n[0];t&&oe(t)});w==null||w.addEventListener("dragover",e=>{e.preventDefault(),w.classList.add("drag-over")});w==null||w.addEventListener("dragleave",()=>w.classList.remove("drag-over"));w==null||w.addEventListener("drop",e=>{var n;e.preventDefault(),w.classList.remove("drag-over");const t=(n=e.dataTransfer.files)==null?void 0:n[0];t&&oe(t)});P==null||P.addEventListener("click",Ue);var J;(J=document.getElementById("lp-backdrop"))==null||J.addEventListener("click",N);var Z;(Z=document.getElementById("lp-close"))==null||Z.addEventListener("click",N);document.addEventListener("keydown",e=>{e.key==="Escape"&&N()});async function oe(e){if(!e.name.toLowerCase().endsWith(".xml")&&e.type!=="text/xml"&&e.type!=="application/xml"){Q("Please upload an XML file exported from Windows Event Viewer.");return}T(`Reading ${e.name}…`);try{const t=await e.text();T("Parsing events…"),await B();const n=ye(t);T(`Analysing ${n.length.toLocaleString()} events…`),await B();const r=Ae(n);C=n,T("Building report…"),await B(),je(r,e.name)}catch(t){Q(t.message||"Failed to parse file."),x(L)}}function B(){return new Promise(e=>setTimeout(e,16))}function x(e){[L,se,ie].forEach(t=>{t&&(t.hidden=!0)}),e&&(e.hidden=!1)}function T(e){F&&(F.textContent=e),x(se)}function Ue(){C=[],D&&(D.value=""),x(L)}function je(e,t){const{incidents:n,healthScore:r,computerName:s,stats:o}=e,a=document.querySelector(".results-title");if(a&&(a.textContent=t.replace(/\.xml$/i,"")),X){const i=[];s&&i.push(s),i.push(`${o.total.toLocaleString()} events`),n.length&&i.push(`${n.length} incident${n.length!==1?"s":""} detected`),X.textContent=i.join(" · ")}He(r,o),_e(n),ze(C);const c=document.getElementById("tab-inc-count"),d=document.getElementById("tab-evt-count");c&&(c.textContent=n.length),d&&(d.textContent=o.total.toLocaleString()),document.querySelectorAll(".analyzer-tab").forEach(i=>{i.addEventListener("click",()=>{document.querySelectorAll(".analyzer-tab").forEach(f=>f.classList.remove("active")),i.classList.add("active");const u=i.dataset.tab;document.getElementById("incidents-section").hidden=u!=="incidents",document.getElementById("events-panel").hidden=u!=="events"})}),x(ie)}function He(e,t){if(!z)return;const n=e>=80?"#34d399":e>=60?"#f59e0b":"#f43f5e",r=e>=80?"Good":e>=60?"Degraded":"Critical";z.innerHTML=`
    <div class="overview-bar">
      <div class="overview-health">
        <span class="ob-score" style="color:${n}">${e}</span>
        <span class="ob-denom">/100</span>
        <span class="ob-label">System Health</span>
        <span class="ob-status" style="color:${n}">${r}</span>
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
  `}function _e(e){if(I){if(!e.length){I.innerHTML=`
      <div class="no-incidents">
        <div class="no-incidents-icon"><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div>
        <div class="no-incidents-title">No incidents detected</div>
        <div class="no-incidents-sub">No known crash or failure anchor events were found in this log.</div>
      </div>
    `;return}I.innerHTML=e.map((t,n)=>Ve(t)).join(""),I.querySelectorAll(".incident-toggle").forEach(t=>{t.addEventListener("click",n=>{if(n.target.closest("[data-lookup-id]"))return;const s=t.closest(".incident-card").querySelector(".incident-body"),o=t.querySelector(".incident-chevron"),a=!s.hidden;s.hidden=a,o.classList.toggle("open",!a)})}),I.querySelectorAll(".copy-summary-btn").forEach(t=>{t.addEventListener("click",()=>{const n=t.dataset.summary;navigator.clipboard.writeText(n).then(()=>{t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy for ticket",t.classList.remove("copied")},2e3)})})}),I.querySelectorAll("[data-lookup-id]").forEach(t=>{t.addEventListener("click",()=>re(t.dataset.lookupId))})}}function Ve(e,t){var f,h;const{anchor:n,windowEvents:r,topContributors:s,signatureResult:o,report:a}=e,c=(f=o[0])==null?void 0:f.signature,d=a.confidence,i=Ze(n.severity),u=d==="high"?"conf-high":d==="medium"?"conf-medium":"conf-low";return`
    <div class="incident-card">
      <div class="incident-header ${i} incident-toggle">
        <div class="incident-header-left">
          <span class="incident-icon">${(c==null?void 0:c.icon)??'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'}</span>
          <div>
            <div class="incident-title">${(c==null?void 0:c.name)??et(n)}</div>
            <div class="incident-meta">
              <span class="incident-time">${n.timestamp.toLocaleString()}</span>
              <span class="incident-provider">${p(n.provider)}</span>
              ${a.confidenceReason?`<span class="conf-reason">${p(a.confidenceReason)}</span>`:""}
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
          <p class="incident-text">${p(a.what)}</p>
        </div>

        <!-- Root cause -->
        <div class="incident-section">
          <div class="incident-section-label">Likely root cause</div>
          <p class="incident-text">${p(a.rootCause)}</p>
        </div>

        <!-- Evidence events -->
        ${s.length?`
        <div class="incident-section">
          <div class="incident-section-label">Contributing events (${s.length} found)</div>
          <div class="evidence-list">
            ${s.slice(0,6).map(({event:v,score:g})=>`
              <div class="evidence-item" data-lookup-id="${v.id}" title="Look up Event ${v.id}">
                <span class="ev-sev-dot sev-${v.severity.toLowerCase()}"></span>
                <span class="ev-id">${v.id}</span>
                <span class="ev-provider">${p(A(v.provider))}</span>
                <span class="ev-time">${ce(v.timestamp)}</span>
                <span class="ev-score" title="Relevance score">${g}</span>
              </div>
            `).join("")}
          </div>
        </div>
        `:""}

        <!-- Timeline -->
        ${r.length?Ge(r,n):""}

        <!-- Next steps -->
        ${a.nextSteps.length?`
        <div class="incident-section">
          <div class="incident-section-label">Suggested next steps</div>
          <ol class="next-steps-list">
            ${a.nextSteps.map(v=>`<li>${p(v)}</li>`).join("")}
          </ol>
        </div>
        `:""}

        <!-- Technician hint -->
        ${a.technicianHint?`
        <div class="incident-section">
          <div class="technician-hint">
            <span class="hint-label">Tech Hint</span>
            <span class="hint-text">${p(a.technicianHint)}</span>
          </div>
        </div>
        `:""}

        <!-- Copy for ticket -->
        <div class="incident-footer">
          <button class="copy-summary-btn" data-summary="${p(a.psaSummary)}">
            Copy for ticket
          </button>
          ${(h=a.alternateSignatures)!=null&&h.length?`
          <span class="alt-signatures">
            Also possible: ${a.alternateSignatures.map(v=>v.signature.name).join(", ")}
          </span>
          `:""}
        </div>
      </div>
    </div>
  `}function Ge(e,t){const n=[...e,t].sort((o,a)=>o.timestamp-a.timestamp),s=n.length>12?[...n.slice(0,6),{_ellipsis:!0,count:n.length-10},...n.slice(-4)]:n;return`
    <div class="incident-section">
      <div class="incident-section-label">Timeline (${e.length} events in ${Ke}-min window)</div>
      <div class="mini-timeline">
        ${s.map(o=>{var c;if(o._ellipsis)return`<div class="timeline-ellipsis">· · · ${o.count} more events · · ·</div>`;const a=o===t;return`
            <div class="timeline-item ${a?"timeline-anchor":""}" data-lookup-id="${o.id}" title="Look up Event ${o.id}">
              <div class="tl-dot sev-${(c=o.severity)==null?void 0:c.toLowerCase()}"></div>
              <div class="tl-content">
                <span class="tl-time">${ce(o.timestamp)}</span>
                <span class="tl-id">${o.id}</span>
                <span class="tl-provider">${p(A(o.provider))}</span>
                ${a?'<span class="tl-anchor-label">ANCHOR</span>':""}
              </div>
            </div>
          `}).join("")}
      </div>
    </div>
  `}const Ke=15,Fe=new Set(["Microsoft-Windows-TaskScheduler","Microsoft-Windows-WindowsUpdateClient","Microsoft-Windows-Bits-Client","Microsoft-Windows-GroupPolicy","Microsoft-Windows-UserPnp","Microsoft-Windows-WER-SystemErrorReporting","Microsoft-Windows-Diagnostics-Performance","Microsoft-Windows-DistributedCOM","Microsoft-Windows-Security-SPP","Microsoft-Windows-Defrag","Microsoft-Windows-Power-Troubleshooter"]),Y={Critical:0,Error:1,Warning:2,Info:3,Verbose:4},l={sortCol:"timestamp",sortDir:"asc",page:0,pageSize:100,query:"",severities:new Set,provider:"",channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set};function ze(e){var c,d;if(!R||!b)return;Object.assign(l,{sortCol:"timestamp",sortDir:"asc",page:0,query:"",severities:new Set,provider:"",channel:"",fromTime:"",toTime:"",hideNoisy:!1,expandedIds:new Set});const t=[...new Set(e.map(i=>i.provider).filter(Boolean))].sort(),n=[...new Set(e.map(i=>i.channel).filter(Boolean))].sort(),r=i=>i?new Date(i-i.getTimezoneOffset()*6e4).toISOString().slice(0,16):"",s=(c=e[0])==null?void 0:c.timestamp,o=(d=e[e.length-1])==null?void 0:d.timestamp;R.innerHTML=`
    <div class="event-log-filters">
      <input type="search" id="tbl-query" class="filter-control filter-control-search"
        placeholder="Search ID, provider, message…" autocomplete="off" spellcheck="false" />

      <div class="tbl-sev-chips">
        ${["Critical","Error","Warning","Info","Verbose"].map(i=>`
          <label class="sev-chip" data-severity="${i}">
            <input type="checkbox" class="sev-cb tbl-sev-cb" value="${i}" />
            <span class="chip-dot dot-${i}"></span>
            <span>${i}</span>
          </label>`).join("")}
      </div>

      <select id="tbl-provider" class="filter-control filter-control-select">
        <option value="">All providers</option>
        ${t.map(i=>`<option value="${p(i)}">${p(A(i))}</option>`).join("")}
      </select>

      <select id="tbl-channel" class="filter-control filter-control-select">
        <option value="">All channels</option>
        ${n.map(i=>`<option value="${p(i)}">${p(i)}</option>`).join("")}
      </select>

      <div class="filter-date-group">
        <span class="filter-date-label">From</span>
        <input type="datetime-local" id="tbl-from" class="filter-control filter-control-date"
          value="${r(s)}" />
      </div>
      <div class="filter-date-group">
        <span class="filter-date-label">To</span>
        <input type="datetime-local" id="tbl-to" class="filter-control filter-control-date"
          value="${r(o)}" />
      </div>

      <div class="filter-spacer"></div>
      <button id="tbl-noise" class="filter-noise-btn">Hide noise</button>
      <button id="tbl-csv"   class="filter-csv-btn">↓ CSV</button>
    </div>
  `;const a=(i,u,f)=>{var h;return(h=document.getElementById(i))==null?void 0:h.addEventListener(u,f)};a("tbl-query","input",i=>{l.query=i.target.value,l.page=0,y()}),R.querySelectorAll(".tbl-sev-cb").forEach(i=>{i.addEventListener("change",()=>{i.checked?l.severities.add(i.value):l.severities.delete(i.value),i.closest(".sev-chip").classList.toggle("active",i.checked),l.page=0,y()})}),a("tbl-provider","change",i=>{l.provider=i.target.value,l.page=0,y()}),a("tbl-channel","change",i=>{l.channel=i.target.value,l.page=0,y()}),a("tbl-from","change",i=>{l.fromTime=i.target.value,l.page=0,y()}),a("tbl-to","change",i=>{l.toTime=i.target.value,l.page=0,y()}),a("tbl-noise","click",i=>{l.hideNoisy=!l.hideNoisy,l.page=0,i.target.classList.toggle("active",l.hideNoisy),i.target.textContent=l.hideNoisy?"Show noise":"Hide noise",y()}),a("tbl-csv","click",()=>Ye(ae())),y()}function ae(){const e=l.query.toLowerCase(),t=l.fromTime?new Date(l.fromTime).getTime():null,n=l.toTime?new Date(l.toTime).getTime():null;let r=C.filter(s=>{if(l.severities.size>0&&!l.severities.has(s.severity)||l.provider&&s.provider!==l.provider||l.channel&&s.channel!==l.channel||t!==null&&s.timestamp<t||n!==null&&s.timestamp>n||l.hideNoisy&&Fe.has(s.provider))return!1;if(e){const o=/^\d+$/.test(e)?parseInt(e,10):null;if(o!==null){if(s.id!==o)return!1}else if(!`${s.id} ${s.provider} ${s.channel} ${s.message} ${s.severity}`.toLowerCase().includes(e))return!1}return!0});return r.sort((s,o)=>{let a=0;switch(l.sortCol){case"timestamp":a=s.timestamp-o.timestamp;break;case"severity":a=(Y[s.severity]??9)-(Y[o.severity]??9);break;case"id":a=s.id-o.id;break;case"provider":a=(s.provider||"").localeCompare(o.provider||"");break}return l.sortDir==="asc"?a:-a}),r}function y(){if(!b)return;const e=ae(),t=e.length,n=Math.max(0,Math.ceil(t/l.pageSize)-1);l.page=Math.min(l.page,n);const r=l.page*l.pageSize,s=e.slice(r,r+l.pageSize);if(!t){b.innerHTML='<div class="table-empty">No events match the current filters.</div>';return}const o=d=>`<span class="sort-arrow ${l.sortCol===d?"active":""}">${l.sortCol===d?l.sortDir==="asc"?"↑":"↓":"↕"}</span>`,a=d=>l.sortCol===d?"sort-active":"";b.innerHTML=`
    <div class="table-info-bar">
      <span class="table-count-text">
        ${(r+1).toLocaleString()}–${Math.min(r+l.pageSize,t).toLocaleString()} of ${t.toLocaleString()} event${t!==1?"s":""}
        ${t<C.length?` (${C.length.toLocaleString()} total)`:""}
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
        <th data-sort="timestamp" class="${a("timestamp")}">Time ${o("timestamp")}</th>
        <th data-sort="severity"  class="${a("severity")}">Sev ${o("severity")}</th>
        <th data-sort="id"        class="${a("id")}">ID ${o("id")}</th>
        <th data-sort="provider"  class="${a("provider")}">Provider ${o("provider")}</th>
        <th>Channel</th>
        <th>Message</th>
      </tr></thead>
      <tbody>${s.map(d=>Xe(d)).join("")}</tbody>
    </table>
  `,b.querySelectorAll("th[data-sort]").forEach(d=>{d.addEventListener("click",()=>{const i=d.dataset.sort;l.sortDir=l.sortCol===i&&l.sortDir==="asc"?"desc":"asc",l.sortCol=i,l.page=0,y()})});const c=(d,i)=>{var u;return(u=document.getElementById(d))==null?void 0:u.addEventListener("click",i)};c("pg-first",()=>{l.page=0,y()}),c("pg-prev",()=>{l.page--,y()}),c("pg-next",()=>{l.page++,y()}),c("pg-last",()=>{l.page=n,y()}),b.querySelectorAll("tbody tr[data-record]").forEach(d=>{d.addEventListener("click",i=>{if(i.target.closest(".table-event-id"))return;const u=parseInt(d.dataset.record,10);l.expandedIds.has(u)?l.expandedIds.delete(u):l.expandedIds.add(u),y()})}),b.querySelectorAll(".table-event-id").forEach(d=>{d.addEventListener("click",i=>{i.stopPropagation(),re(d.dataset.lookupId)})}),b.querySelectorAll(".ev-advanced-toggle").forEach(d=>{d.addEventListener("click",i=>{i.stopPropagation();const f=d.closest(".ev-detail-inner").querySelector(".ev-advanced-section").classList.toggle("ev-advanced-open");d.textContent=f?"Advanced ▲":"Advanced ▼"})})}function Xe(e){var v;const t=l.expandedIds.has(e.recordId),n=e.severity.toLowerCase(),r=Object.keys(e.data||{}),s=e.message?p(e.message.substring(0,150))+(e.message.length>150?"…":""):'<span style="color:var(--text3);font-style:italic">no message</span>',o=`
    <tr class="ev-row-${n}${t?" row-expanded":""}" data-record="${e.recordId}">
      <td class="ev-col-expand">${t?"▼":"▶"}</td>
      <td class="ev-col-time">${Je(e.timestamp)}</td>
      <td><span class="sev-badge sev-badge-${n}">${e.severity}</span></td>
      <td><span class="table-event-id" data-lookup-id="${e.id}" title="Look up Event ${e.id}">${e.id}</span></td>
      <td class="ev-col-provider" title="${p(e.provider)}">${p(A(e.provider))}</td>
      <td class="ev-col-channel">${p(e.channel)}</td>
      <td class="ev-col-message">${s}</td>
    </tr>`;if(!t)return o;const a=e.taskName||e.task||null,c=e.opcodeName||e.opcode||null,d=(v=e.keywordNames)!=null&&v.length?e.keywordNames.join(", "):e.keywords||null,i=[["Time (local)",e.timestamp.toLocaleString()],["Time (UTC)",e.timestamp.toISOString()],["Provider",e.provider],["Channel",e.channel],["Computer",e.computer],["Record ID",e.recordId||null],["User SID",e.userSID],["Process ID",e.processId||null],["Thread ID",e.threadId||null],["Activity ID",e.activityId],["Related Act. ID",e.relatedActivityId],["Task",a],["Opcode",c],["Keywords",d]].filter(([,g])=>g),u=[["Raw Level",String(e.levelNum)],["Raw Task",e.task],["Raw Opcode",e.opcode],["Raw Keywords",e.keywords],["Version",e.version],["Qualifiers",e.qualifiers],["Provider Desc.",e.providerDescription]].filter(([,g])=>g),f=e.message?`<div class="ev-detail-message">${p(e.message)}</div>`:`<div class="ev-detail-message ev-no-message">
        Message not rendered — Windows message templates are stored on the source machine.
        Export directly from the affected computer to see full event messages.
       </div>`,h=e.dataAnon||[];return o+`
    <tr class="ev-detail-row">
      <td colspan="7">
        <div class="ev-detail-inner">
          ${f}
          <div class="ev-detail-meta">
            ${i.map(([g,m])=>`
              <div class="ev-detail-field">
                <span class="ev-detail-key">${g}</span>
                <span class="ev-detail-val">${p(String(m))}</span>
              </div>`).join("")}
          </div>
          ${r.length||h.length?`
          <div class="ev-detail-data">
            <div class="ev-detail-data-title">Event Data</div>
            ${r.map(g=>`
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key">${p(g)}</span>
                <span class="ev-detail-data-val">${p(String(e.data[g]))}</span>
              </div>`).join("")}
            ${h.map((g,m)=>`
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key ev-detail-data-key--anon">[${m}]</span>
                <span class="ev-detail-data-val">${p(String(g))}</span>
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
            ${u.map(([g,m])=>`
              <div class="ev-detail-field">
                <span class="ev-detail-key">${g}</span>
                <span class="ev-detail-val">${p(String(m))}</span>
              </div>`).join("")}
          </div>`:""}
        </div>
      </td>
    </tr>`}function Ye(e){const t=["Time (UTC)","Severity","EventID","Provider","Channel","Computer","RecordID","ProcessID","ThreadID","UserSID","ActivityID","RelatedActivityID","Task","TaskName","Opcode","OpcodeName","Keywords","KeywordNames","Version","Qualifiers","ProviderDescription","Message","EventData","EventDataAnon"],n=c=>`"${String(c??"").replace(/"/g,'""').replace(/\r?\n/g," ")}"`,r=e.map(c=>[c.timestamp.toISOString(),c.severity,c.id,n(c.provider),n(c.channel),n(c.computer),c.recordId,c.processId||"",c.threadId||"",n(c.userSID),n(c.activityId),n(c.relatedActivityId),n(c.task),n(c.taskName),n(c.opcode),n(c.opcodeName),n(c.keywords),n((c.keywordNames||[]).join("; ")),n(c.version),n(c.qualifiers),n(c.providerDescription),n(c.message),n(Object.entries(c.data||{}).map(([d,i])=>`${d}=${i}`).join("; ")),n((c.dataAnon||[]).join("; "))].join(",")),s=[t.join(","),...r].join(`\r
`),o=URL.createObjectURL(new Blob([s],{type:"text/csv;charset=utf-8;"})),a=Object.assign(document.createElement("a"),{href:o,download:`eventful-${new Date().toISOString().slice(0,10)}.csv`});document.body.appendChild(a),a.click(),document.body.removeChild(a),URL.revokeObjectURL(o)}function re(e){const t=parseInt(e,10),n=document.getElementById("lookup-panel"),r=document.getElementById("lp-body");if(!n||!r)return;const s=we.find(a=>a.id===t),o=C.filter(a=>a.id===t);r.innerHTML=Qe(t,s,o),n.hidden=!1,r.querySelectorAll(".lp-copy-ps").forEach(a=>{a.addEventListener("click",()=>{navigator.clipboard.writeText(a.dataset.code).then(()=>{a.textContent="Copied!",setTimeout(()=>{a.textContent="Copy"},2e3)})})}),r.querySelectorAll(".lp-advanced-toggle").forEach(a=>{a.addEventListener("click",()=>{const d=a.nextElementSibling.classList.toggle("lp-advanced-open");a.textContent=d?"Advanced ▲":"Advanced ▼"})}),r.querySelectorAll(".lp-show-in-log").forEach(a=>{a.addEventListener("click",()=>{const c=a.dataset.filterId;N(),document.querySelectorAll(".analyzer-tab").forEach(u=>u.classList.remove("active"));const d=document.querySelector('.analyzer-tab[data-tab="events"]');d&&d.classList.add("active"),document.getElementById("incidents-section").hidden=!0,document.getElementById("events-panel").hidden=!1,l.query=c,l.page=0;const i=document.getElementById("tbl-query");i&&(i.value=c),y()})})}function N(){const e=document.getElementById("lookup-panel");e&&(e.hidden=!0)}function Qe(e,t,n){var o,a,c;let r;if(t){const d=((o=t.severity)==null?void 0:o.toLowerCase())??"info";r=`
      <div class="lp-section">
        <div class="lp-section-label">Knowledge Base</div>
        <div class="lp-doc-header">
          <span class="lp-id-badge">${e}</span>
          <div>
            <div class="lp-doc-title">${p(t.title)}</div>
            <div class="lp-doc-meta">
              <span class="sev-badge sev-badge-${d}">${p(t.severity)}</span>
              <span class="lp-channel">${p(t.channel||t.source||"")}</span>
            </div>
          </div>
        </div>
        <p class="lp-description">${p(t.description||t.short_desc||"")}</p>
        ${(a=t.causes)!=null&&a.length?`
          <div class="lp-subsection-label">Causes</div>
          <ul class="lp-causes">
            ${t.causes.map(i=>`<li>${p(i)}</li>`).join("")}
          </ul>`:""}
        ${(c=t.steps)!=null&&c.length?`
          <div class="lp-subsection-label">Investigation Steps</div>
          <ol class="lp-steps">
            ${t.steps.map(i=>`<li>${p(i)}</li>`).join("")}
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
      </div>`}else r=`
      <div class="lp-section">
        <div class="lp-section-label">Knowledge Base</div>
        <div class="lp-no-doc-state">
          <div class="lp-no-doc-title">No documentation for Event ${e}</div>
          <div class="lp-no-doc-sub">This event ID is not in the Eventful knowledge base.</div>
        </div>
      </div>`;let s;if(n.length===0)s=`
      <div class="lp-section">
        <div class="lp-section-label">From your log</div>
        <div class="lp-no-raw">No events with this ID in the uploaded log.</div>
      </div>`;else{const d=n.slice(0,3);s=`
      <div class="lp-section">
        <div class="lp-section-label">
          From your log
          ${n.length>1?`<span class="lp-raw-count">${n.length} occurrences</span>`:""}
        </div>
        ${d.map((i,u)=>{var M;const f=i.taskName||i.opcode||null,h=i.opcodeName||i.opcode||null,v=(M=i.keywordNames)!=null&&M.length?i.keywordNames.join(", "):i.keywords||null,g=i.dataAnon||[],m=[["Raw Level",String(i.levelNum)],["Raw Task",i.task],["Raw Opcode",i.opcode],["Raw Keywords",i.keywords],["Version",i.version],["Qualifiers",i.qualifiers],["Provider Desc.",i.providerDescription],["Related Act. ID",i.relatedActivityId]].filter(([,$])=>$);return`
          ${u>0?'<div class="lp-raw-divider"></div>':""}
          <div class="lp-raw-fields">
            ${S("Time",i.timestamp.toLocaleString())}
            ${S("Severity",`<span class="sev-badge sev-badge-${i.severity.toLowerCase()}">${i.severity}</span>`)}
            ${S("Provider",p(A(i.provider)))}
            ${S("Channel",p(i.channel))}
            ${S("Computer",p(i.computer||"—"))}
            ${S("Record ID",String(i.recordId||"—"))}
            ${i.processId?S("Process ID",String(i.processId)):""}
            ${i.threadId?S("Thread ID",String(i.threadId)):""}
            ${i.userSID?S("User SID",p(i.userSID)):""}
            ${i.activityId?S("Activity ID",p(i.activityId)):""}
            ${f?S("Task",p(f)):""}
            ${h?S("Opcode",p(h)):""}
            ${v?S("Keywords",p(v)):""}
          </div>
          ${i.message?`<div class="lp-raw-message-label">Message</div>
               <div class="lp-raw-message">${p(i.message)}</div>`:`<div class="lp-raw-message-label">Message</div>
               <div class="lp-raw-message lp-no-message">Message not rendered — Windows message templates are stored on the source machine. Export directly from the affected computer to see full event messages.</div>`}
          ${Object.keys(i.data||{}).length||g.length?`
            <div class="lp-raw-message-label">Event Data</div>
            <div class="lp-raw-data">
              ${Object.entries(i.data).map(([$,E])=>`
                <div class="lp-raw-data-row">
                  <span class="lp-raw-data-key">${p($)}</span>
                  <span class="lp-raw-data-val">${p(String(E))}</span>
                </div>`).join("")}
              ${g.map(($,E)=>`
                <div class="lp-raw-data-row">
                  <span class="lp-raw-data-key lp-raw-data-key--anon">[${E}]</span>
                  <span class="lp-raw-data-val">${p(String($))}</span>
                </div>`).join("")}
            </div>`:""}
          ${m.length?`
            <button class="lp-advanced-toggle">Advanced ▼</button>
            <div class="lp-advanced-section">
              <div class="lp-raw-message-label">Advanced / Raw</div>
              <div class="lp-raw-fields">
                ${m.map(([$,E])=>S($,p(E))).join("")}
              </div>
            </div>`:""}
          `}).join("")}
        ${n.length>3?`<div class="lp-raw-more">+ ${n.length-3} more occurrence${n.length-3!==1?"s":""} in log</div>`:""}
        <button class="lp-show-in-log" data-filter-id="${e}">Show all ${n.length} in All Events →</button>
      </div>`}return`<div class="lp-col lp-col-kb">${r}</div><div class="lp-col lp-col-raw">${s}</div>`}function S(e,t){return`
    <div class="lp-raw-field">
      <span class="lp-raw-key">${e}</span>
      <span class="lp-raw-val">${t}</span>
    </div>`}function Q(e){const t=w==null?void 0:w.querySelector(".upload-error");t&&t.remove();const n=document.createElement("div");n.className="upload-error",n.textContent=e,w==null||w.appendChild(n),x(L)}function p(e){return e?String(e).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"):""}function A(e){return e?e.replace(/^Microsoft-Windows-/i,"").replace(/^Microsoft-/i,""):"—"}function ce(e){return e.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}function Je(e){return e.toLocaleString([],{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})}function Ze(e){return`sev-header-${(e==null?void 0:e.toLowerCase())??"info"}`}function et(e){return{41:"Unexpected System Reboot",6008:"Unexpected Shutdown Detected",1001:"System Crash (BSOD)",1e3:"Application Crash",7024:"Critical Service Failure"}[e.id]??`Event ${e.id}`}
