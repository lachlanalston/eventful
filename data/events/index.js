export { securityEvents } from './security.js';
export { systemEvents } from './system.js';
export { applicationEvents } from './application.js';
export { rdsEvents } from './rds.js';
export { networkEvents } from './network.js';
export { printEvents } from './print.js';
export { dnsEvents } from './dns.js';
export { groupPolicyEvents } from './grouppolicy.js';
export { vssEvents } from './vss.js';

import { securityEvents } from './security.js';
import { systemEvents } from './system.js';
import { applicationEvents } from './application.js';
import { rdsEvents } from './rds.js';
import { networkEvents } from './network.js';
import { printEvents } from './print.js';
import { dnsEvents } from './dns.js';
import { groupPolicyEvents } from './grouppolicy.js';
import { vssEvents } from './vss.js';

export const allEvents = [
  ...securityEvents,
  ...systemEvents,
  ...applicationEvents,
  ...rdsEvents,
  ...networkEvents,
  ...printEvents,
  ...dnsEvents,
  ...groupPolicyEvents,
  ...vssEvents
];
