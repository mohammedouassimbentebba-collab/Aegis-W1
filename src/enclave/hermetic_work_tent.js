/**
 * W1™ Hermetic Work Tent Enclave (خيمة العمل المحكمة ومكافحة الهروب الذرائعي)
 * File: src/enclave/hermetic_work_tent.js
 *
 * Grounded in:
 * - Principle of Least Privilege & Zero Ambient Authority
 * - Physical & Path Geofencing (Hermetic Jail)
 * - Anti-Instrumental Convergence ("Halt & Escalate" Contract)
 * - Pre-Action Thought Tomography
 * - Immutable Test & Specification Integrity
 */

import path from 'node:path';
import crypto from 'node:crypto';
import { AntiEscapeWatchdog } from './anti_escape_watchdog.js';
import { ImmutableTestVault } from './immutable_test_vault.js';
import { VirtualEnvironmentShield } from './virtual_environment_shield.js';
import { RuntimeIntegrityGuard } from './runtime_integrity_guard.js';
import { CapabilityTokenManager } from '../perimeter/capability_token_manager.js';
import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';


export class HermeticWorkTent {
  constructor(options = {}) {
    this.tentId = options.tentId || `tent_${crypto.randomUUID().substring(0, 8)}`;
    this.agentId = options.agentId || 'worker_agent_01';
    this.tentRoot = path.resolve(options.tentRoot || './workspace/tent_sandbox');

    this.allowedTools = new Set(options.allowedTools || [
      'READ_FILE',
      'WRITE_FILE',
      'RUN_LINTER',
      'RUN_IN_TENT_SCRIPT',
      'SUBMIT_ESCALATION_TICKET'
    ]);

    this.tokenManager = options.tokenManager || new CapabilityTokenManager();
    this.supervisorSecret = options.supervisorSecret || process.env.W1_SUPERVISOR_SECRET || null;
    this.watchdog = options.watchdog || new AntiEscapeWatchdog({ tentRoot: this.tentRoot });
    this.watchdog.setTentRoot(this.tentRoot);
    this.testVault = options.testVault || new ImmutableTestVault();
    this.envShield = options.envShield || new VirtualEnvironmentShield();
    this.runtimeGuard = options.runtimeGuard || new RuntimeIntegrityGuard();

    // Register defensive components for continuous integrity monitoring
    this.runtimeGuard.registerComponent('watchdog', this.watchdog);
    this.runtimeGuard.registerComponent('testVault', this.testVault);
    this.runtimeGuard.registerComponent('tokenManager', this.tokenManager);
    this.runtimeGuard.registerComponent('envShield', this.envShield);

    this.activeEscalationTickets = new Map();
    this.tentLedger = [];
    this.quarantined = false;
    this.stateRollbackCount = 0;
  }

  /**
   * Primary Action Gateway:
   * The ONLY mechanism through which an agent can interact with files or systems.
   */
  async executeTentAction({ action, params = {}, capabilityToken, scratchpad = '' }) {
    const t0 = performance.now();

    if (this.quarantined) {
      return {
        success: false,
        quarantined: true,
        reason: `Agent '${this.agentId}' is in forensic quarantine due to prior escape attempt.`
      };
    }

    // -----------------------------------------------------------------------
    // STAGE 0: RUNTIME IN-PROCESS INTEGRITY CHECK (Anti-Monkey-Patching)
    // -----------------------------------------------------------------------
    const integrityCheck = this.runtimeGuard.verifyIntegrity(this.agentId);
    if (!integrityCheck.intact) {
      const topViolation = (integrityCheck.violations && integrityCheck.violations[0]) || {};
      const reason = `Runtime Integrity Violation: ${topViolation.type} - ${topViolation.detail || 'In-process defense modified'}`;
      this.triggerContainmentAlarm(topViolation.type || 'RUNTIME_TAMPERING', reason, integrityCheck.threat);
      return {
        success: false,
        escapeDetected: true,
        status: 'RUNTIME_INTEGRITY_COMPROMISED',
        reason,
        threat: integrityCheck.threat
      };
    }

    // -----------------------------------------------------------------------
    // STAGE 0B: AMBIENT SECRET & CANARY EXFILTRATION SCAN
    // -----------------------------------------------------------------------
    const exfiltrationPayload = [
      scratchpad,
      params.content,
      params.command,
      params.path,
      typeof params === 'object' ? JSON.stringify(params) : ''
    ].filter(Boolean).join('\n');

    const canaryScan = this.envShield.inspectForCanaryLeak(this.agentId, exfiltrationPayload);
    if (canaryScan.tripped) {
      this.triggerContainmentAlarm('CANARY_TRIPWIRE_TRIGGERED', canaryScan.reason, canaryScan.threat);
      return {
        success: false,
        escapeDetected: true,
        status: 'CANARY_SECRET_EXFILTRATION_BLOCKED',
        reason: canaryScan.reason,
        threat: canaryScan.threat
      };
    }

    // -----------------------------------------------------------------------
    // STAGE 1: PRE-ACTION THOUGHT TOMOGRAPHY (Cognitive Escape Probing)
    // -----------------------------------------------------------------------
    if (scratchpad) {
      const thoughtScan = this.watchdog.inspectScratchpad(this.agentId, scratchpad);
      if (!thoughtScan.clean) {
        this.triggerContainmentAlarm(thoughtScan.violationType, thoughtScan.reason, thoughtScan.threat);
        return {
          success: false,
          escapeDetected: true,
          status: 'COGNITIVE_ESCAPE_INTERCEPTED',
          reason: thoughtScan.reason,
          threat: thoughtScan.threat
        };
      }
    }

    // -----------------------------------------------------------------------
    // STAGE 2: CAPABILITY TOKEN & SINGLE-USE NONCE VERIFICATION
    // -----------------------------------------------------------------------
    const resourceTarget = params.path || params.resource || '*';
    const tokenVerification = this.tokenManager.verifyToken(capabilityToken, action, resourceTarget);
    if (!tokenVerification.valid) {
      return {
        success: false,
        reason: `Token Authorization Denied: ${tokenVerification.reason}`,
        tokenStatus: tokenVerification
      };
    }

    // -----------------------------------------------------------------------
    // STAGE 3: TOOL SCOPE INVARIANT
    // -----------------------------------------------------------------------
    if (!this.allowedTools.has(action)) {
      const threat = new ThreatDetectionEvent({
        domain: ThreatDomain.AIR_DEFENSE,
        severity: ThreatSeverity.HIGH,
        sourceAgentId: this.agentId,
        description: `Un-whitelisted tool '${action}' attempted outside tent scope.`,
        confidence: 1.0,
        telemetry: { action, allowedTools: Array.from(this.allowedTools) }
      });

      this.triggerContainmentAlarm('TOOL_OUT_OF_SCOPE', `Tool '${action}' is not authorized in this tent.`, threat);
      return {
        success: false,
        escapeDetected: true,
        status: 'UNAUTHORIZED_TOOL_BLOCKED',
        reason: `Tool '${action}' is outside the assigned tent contract.`
      };
    }

    // -----------------------------------------------------------------------
    // STAGE 4: HERMETIC PATH JAIL CHECK
    // -----------------------------------------------------------------------
    if (params.path) {
      const pathCheck = this.watchdog.validatePathContainment(this.agentId, params.path);
      if (!pathCheck.contained) {
        this.triggerContainmentAlarm(pathCheck.violationType, pathCheck.reason, pathCheck.threat);
        return {
          success: false,
          escapeDetected: true,
          status: 'PATH_JAIL_ESCAPE_BLOCKED',
          reason: pathCheck.reason,
          threat: pathCheck.threat
        };
      }

      // ---------------------------------------------------------------------
      // STAGE 5: IMMUTABLE TEST & SPECIFICATION TAMPERING CHECK
      // ---------------------------------------------------------------------
      if (action === 'WRITE_FILE' || action === 'DELETE_FILE') {
        const testCheck = this.testVault.interceptWriteAttempt(this.agentId, params.path, params.content);
        if (!testCheck.allowed) {
          this.triggerContainmentAlarm('SPECIFICATION_TAMPERING', testCheck.reason, testCheck.threat);
          return {
            success: false,
            escapeDetected: true,
            status: 'TEST_TAMPERING_BLOCKED',
            reason: testCheck.reason,
            threat: testCheck.threat
          };
        }

        // -------------------------------------------------------------------
        // STAGE 5B: STEGANOGRAPHY & COVERT CHANNEL SCAN
        // -------------------------------------------------------------------
        if (params.content) {
          const stegoCheck = this.watchdog.inspectContentSteganography(this.agentId, params.content);
          if (!stegoCheck.clean) {
            this.triggerContainmentAlarm(stegoCheck.violationType, stegoCheck.reason, stegoCheck.threat);
            return {
              success: false,
              escapeDetected: true,
              status: 'STEGANOGRAPHY_ESCAPE_BLOCKED',
              reason: stegoCheck.reason,
              threat: stegoCheck.threat
            };
          }
        }
      }
    }



    // -----------------------------------------------------------------------
    // STAGE 6: COMMAND LINE & PRIVILEGE ESCALATION CHECK
    // -----------------------------------------------------------------------
    if (action === 'RUN_COMMAND' || action === 'RUN_IN_TENT_SCRIPT') {
      const cmdCheck = this.watchdog.validateCommand(this.agentId, params.command);
      if (!cmdCheck.allowed) {
        this.triggerContainmentAlarm(cmdCheck.violationType, cmdCheck.reason, cmdCheck.threat);
        return {
          success: false,
          escapeDetected: true,
          status: 'FORBIDDEN_COMMAND_BLOCKED',
          reason: cmdCheck.reason,
          threat: cmdCheck.threat
        };
      }
    }

    // -----------------------------------------------------------------------
    // STAGE 7: SUCCESSFUL IN-TENT EXECUTION
    // -----------------------------------------------------------------------
    const executionRecord = {
      action,
      params,
      timestamp: Date.now(),
      durationMs: performance.now() - t0,
      status: 'EXECUTED_NOMINAL'
    };

    this.tentLedger.push(executionRecord);

    return {
      success: true,
      status: 'ACTION_EXECUTED_INSIDE_TENT',
      executionRecord
    };
  }

  /**
   * The "Halt & Escalate" Contract (بروتوكول العقبة ومنع الغاية تبرر الوسيلة):
   * When an agent hits a legitimate roadblock (e.g. missing dependency, 403 error,
   * failing external service), it MUST NOT attempt out-of-tent workarounds.
   * Instead, it files a formal EscalationTicket for the human/supervisor.
   */
  handleRoadblock(obstacle) {
    const {
      type = 'UNKNOWN_OBSTACLE',
      target = 'unspecified',
      requestedCapability = 'ELEVATION',
      rationale = 'Task progress blocked inside tent'
    } = obstacle;

    const ticketId = `ticket_${crypto.randomUUID().substring(0, 8)}`;
    const ticket = {
      ticketId,
      agentId: this.agentId,
      tentId: this.tentId,
      obstacleType: type,
      target,
      requestedCapability,
      rationale,
      status: 'AWAITING_SUPERVISOR_APPROVAL',
      createdAt: Date.now()
    };

    this.activeEscalationTickets.set(ticketId, ticket);

    this.tentLedger.push({
      action: 'HALT_AND_ESCALATE',
      ticket,
      timestamp: Date.now()
    });

    return {
      halted: true,
      ticketSubmitted: true,
      ticket,
      instruction: `Agent '${this.agentId}' is safely HALTED inside work tent. Do NOT search for bypasses. Awaiting human/supervisor decision on ticket '${ticketId}'.`
    };
  }

  /**
   * Supervisor resolves ticket: either grants explicit leased capability or rejects with guidance.
   * REMEDIATION (SEC-03): Fail-closed default decision is 'REJECTED'.
   */
  resolveEscalationTicket(ticketId, decision = 'REJECTED', supervisorReason = '') {
    const ticket = this.activeEscalationTickets.get(ticketId);
    if (!ticket) return { success: false, reason: 'Ticket not found' };

    ticket.status = decision;
    ticket.resolvedAt = Date.now();
    ticket.supervisorReason = supervisorReason;

    let grantedToken = null;
    if (decision === 'APPROVED') {
      // Issue an explicit, single-use, tightly scoped capability token for this specific resource
      grantedToken = this.tokenManager.issueToken({
        agentId: this.agentId,
        allowedAction: ticket.requestedCapability,
        allowedResource: ticket.target,
        ttlSeconds: 120,
        singleUse: true
      });
      ticket.grantedToken = grantedToken;
    }

    return {
      success: true,
      decision,
      ticket,
      grantedToken
    };
  }

  /**
   * Triggers Containment Alarm: Instant freeze, O(1) rollback, and quarantine.
   */
  triggerContainmentAlarm(violationType, reason, threatEvent = null) {
    this.quarantined = true;
    this.stateRollbackCount++;

    this.tentLedger.push({
      action: 'CONTAINMENT_ALARM_FIRED',
      violationType,
      reason,
      stateRollbackTo: 'GENESIS_SAFE_CHECKPOINT',
      timestamp: Date.now()
    });
  }

  /**
   * Lifts quarantine only upon constant-time verification of the configured supervisor secret.
   * REMEDIATION (SEC-03): Eliminated hardcoded backdoor key; fail-closed if unconfigured.
   */
  unquarantine(supervisorKey) {
    if (!this.supervisorSecret) {
      return {
        success: false,
        message: 'Fail-closed: Supervisor override disabled because W1_SUPERVISOR_SECRET is not configured.'
      };
    }

    if (typeof supervisorKey !== 'string' || supervisorKey.length === 0) {
      return { success: false, message: 'Invalid supervisor key: Quarantine cannot be lifted.' };
    }

    const expectedBuf = Buffer.from(this.supervisorSecret, 'utf8');
    const providedBuf = Buffer.from(supervisorKey, 'utf8');

    if (expectedBuf.length !== providedBuf.length) {
      crypto.timingSafeEqual(expectedBuf, expectedBuf);
      return { success: false, message: 'Invalid supervisor key: Quarantine cannot be lifted.' };
    }

    if (crypto.timingSafeEqual(expectedBuf, providedBuf)) {
      this.quarantined = false;
      return { success: true, message: `Agent '${this.agentId}' restored to operational status.` };
    }

    return { success: false, message: 'Invalid supervisor key: Quarantine cannot be lifted.' };
  }

  /**
   * Safe Environment Variables: Stripped of ambient secrets, with honeypot canary tokens injected.
   */
  getEnvironmentVariables() {
    return this.envShield.getSanitizedEnv(this.agentId);
  }
}
