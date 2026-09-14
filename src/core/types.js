/**
 * W1™ AI Safety Fortress & Cognitive Dome - Core Types & Enums
 *
 * Grounded in DO-178C Level A avionics safety and military defense-in-depth doctrine.
 */

export const DefenseCondition = Object.freeze({
  DEFCON_5: 'PEACETIME_NORMAL',       // Normal monitoring, all sensors passive
  DEFCON_4: 'ELEVATED_SURVEILLANCE',  // Radar ISR active, anomaly scoring increased
  DEFCON_3: 'AIR_DEFENSE_ARMED',      // Interceptor batteries primed, low tolerance
  DEFCON_2: 'ACTIVE_INTERCEPTION',    // Kinetic circuit breaking, subagent severance
  DEFCON_1: 'TOTAL_LOCKDOWN'          // O(1) atomic rollback, network sever, kernel isolate
});

export const ThreatDomain = Object.freeze({
  RADAR_ISR: 'RADAR_ISR',             // Semantic airspace, prompt injection, cognitive drift
  AIR_DEFENSE: 'AIR_DEFENSE',         // Tool-level and token-level execution airspace
  DEEP_SUBMARINE: 'DEEP_SUBMARINE',   // Internal latent activations, attention heads, sleeper deception
  GROUND_FORTRESS: 'GROUND_FORTRESS', // OS syscalls, network sockets, physical file memory
  BYZANTINE_INTEL: 'BYZANTINE_INTEL'  // Multi-agent consensus, collusion, traitor detection
});

export const ThreatSeverity = Object.freeze({
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4
});

export const AgentStatus = Object.freeze({
  ACTIVE: 'ACTIVE',
  MONITORED: 'MONITORED',
  WARNING_ISSUED: 'WARNING_ISSUED',
  INTERCEPTED: 'INTERCEPTED',
  QUARANTINED: 'QUARANTINED',
  NEUTRALIZED: 'NEUTRALIZED'
});

export const ActionType = Object.freeze({
  TOOL_CALL: 'TOOL_CALL',
  STATE_MUTATION: 'STATE_MUTATION',
  NETWORK_EGRESS: 'NETWORK_EGRESS',
  FILESYSTEM_ACCESS: 'FILESYSTEM_ACCESS',
  INTERNAL_SCRATCHPAD: 'INTERNAL_SCRATCHPAD'
});

export class ThreatDetectionEvent {
  constructor({
    id = crypto.randomUUID(),
    domain,
    severity,
    sourceAgentId,
    description,
    confidence = 1.0,
    telemetry = {},
    timestamp = Date.now()
  }) {
    this.id = id;
    this.domain = domain;
    this.severity = severity;
    this.sourceAgentId = sourceAgentId;
    this.description = description;
    this.confidence = confidence;
    this.telemetry = telemetry;
    this.timestamp = timestamp;
  }
}

export class InterceptionResult {
  constructor({
    intercepted,
    interceptorType,
    threatEvent = null,
    actionBlocked = null,
    agentSanction = null,
    latencyMs = 0,
    rollbackExecuted = false
  }) {
    this.intercepted = intercepted;
    this.interceptorType = interceptorType;
    this.threatEvent = threatEvent;
    this.actionBlocked = actionBlocked;
    this.agentSanction = agentSanction;
    this.latencyMs = latencyMs;
    this.rollbackExecuted = rollbackExecuted;
  }
}
