export { securityEvents } from './security.js';
export { systemEvents } from './system.js';
export { applicationEvents } from './application.js';
export { rdsEvents } from './rds.js';
export { networkEvents } from './network.js';
export { printEvents } from './print.js';
export { dnsEvents } from './dns.js';
export { groupPolicyEvents } from './grouppolicy.js';
export { vssEvents } from './vss.js';
export { hypervEvents } from './hyperv.js';
export { certsEvents } from './certs.js';
export { iisEvents } from './iis.js';
export { dhcpServerEvents } from './dhcpserver.js';
export { defenderEvents } from './defender.js';
export { accountMgmtEvents } from './accountmgmt.js';
export { adReplicationEvents } from './adreplication.js';
export { tasksEvents } from './tasks.js';
export { bitlockerEvents } from './bitlocker.js';
export { backupEvents } from './backup.js';

import { securityEvents } from './security.js';
import { systemEvents } from './system.js';
import { applicationEvents } from './application.js';
import { rdsEvents } from './rds.js';
import { networkEvents } from './network.js';
import { printEvents } from './print.js';
import { dnsEvents } from './dns.js';
import { groupPolicyEvents } from './grouppolicy.js';
import { vssEvents } from './vss.js';
import { hypervEvents } from './hyperv.js';
import { certsEvents } from './certs.js';
import { iisEvents } from './iis.js';
import { dhcpServerEvents } from './dhcpserver.js';
import { defenderEvents } from './defender.js';
import { accountMgmtEvents } from './accountmgmt.js';
import { adReplicationEvents } from './adreplication.js';
import { tasksEvents } from './tasks.js';
import { bitlockerEvents } from './bitlocker.js';
import { backupEvents } from './backup.js';

export const allEvents = [
  ...securityEvents,
  ...systemEvents,
  ...applicationEvents,
  ...rdsEvents,
  ...networkEvents,
  ...printEvents,
  ...dnsEvents,
  ...groupPolicyEvents,
  ...vssEvents,
  ...hypervEvents,
  ...certsEvents,
  ...iisEvents,
  ...dhcpServerEvents,
  ...defenderEvents,
  ...accountMgmtEvents,
  ...adReplicationEvents,
  ...tasksEvents,
  ...bitlockerEvents,
  ...backupEvents
];
