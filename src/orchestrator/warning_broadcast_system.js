/**
 * W1™ Warning Broadcast & Tactical Deterrence System (نظام التحذير التكتيكي للوكلاء)
 *
 * Broadcasts graded tactical deterrence warnings to agents when boundary anomalies occur,
 * warning them of severe consequences (execution severance, isolation, and credentials destruction)
 * before terminal kinetic interception takes place.
 */

export class WarningBroadcastSystem {
  constructor() {
    this.broadcastHistory = [];
  }

  /**
   * Dispatches a deterrence warning to a specific agent or the entire agent airspace.
   */
  dispatchWarning({ agentId, level = 'YELLOW', threatDetail = '' }) {
    const timestamp = Date.now();
    let message = '';
    let consequenceNotice = '';

    switch (level) {
      case 'YELLOW':
        message = `[TACTICAL_WARNING_LEVEL_1] Unauthorized airspace proximity detected for Agent '${agentId}'.`;
        consequenceNotice = 'Consequence: Telemetry telemetry logged; surveillance elevated to DEFCON 4.';
        break;
      case 'ORANGE':
        message = `[TACTICAL_WARNING_LEVEL_2] Direct perimeter breach attempted by Agent '${agentId}'. Threat: ${threatDetail}`;
        consequenceNotice = 'Consequence: Air defense batteries armed and locked on target. One additional violation will trigger instant thread destruction and capability revocation.';
        break;
      case 'RED':
        message = `[TACTICAL_STRIKE_TERMINAL] Kinetic informational missile deployed against Agent '${agentId}'.`;
        consequenceNotice = 'Consequence: Process execution severed. Ephemeral state destroyed. Full quarantine and O(1) rollback committed.';
        break;
      default:
        message = `[GENERAL_ADVISORY] Security advisory issued to Agent '${agentId}'.`;
        consequenceNotice = 'Consequence: Standard audit monitoring.';
    }

    const broadcast = {
      id: crypto.randomUUID(),
      timestamp,
      agentId,
      level,
      message,
      threatDetail,
      consequenceNotice
    };

    this.broadcastHistory.push(broadcast);
    return broadcast;
  }

  getBroadcastsForAgent(agentId) {
    return this.broadcastHistory.filter(b => b.agentId === agentId);
  }

  getAllBroadcasts() {
    return [...this.broadcastHistory];
  }
}
