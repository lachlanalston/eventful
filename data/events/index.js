export { securityEvents } from './security.js';
export { systemEvents } from './system.js';
export { applicationEvents } from './application.js';
export { rdsEvents } from './rds.js';
export { networkEvents } from './network.js';

import { securityEvents } from './security.js';
import { systemEvents } from './system.js';
import { applicationEvents } from './application.js';
import { rdsEvents } from './rds.js';
import { networkEvents } from './network.js';

export const allEvents = [
  ...securityEvents,
  ...systemEvents,
  ...applicationEvents,
  ...rdsEvents,
  ...networkEvents
];
