/**
 * W1™ Fortress Commander (القيادة المركزية للحصن ومنظومات الدفاع)
 *
 * Unifies all defense domains:
 * - Deterministic Mathematical Kernel
 * - Early Warning Radar (ISR)
 * - Air Defense Interceptor Batteries
 * - Deep Submarine Latent Sonar
 * - Byzantine Counter-Intelligence Council
 * - OS & AI Firewall Shield
 * - Capability Token Manager
 * - Warning Broadcast System
 */

import { DeterministicKernel } from '../core/deterministic_kernel.js';
import { DefenseCondition, ThreatDomain, ThreatSeverity } from '../core/types.js';
import { AirDefenseInterceptor } from '../defense_grid/air_defense_interceptor.js';
import { DeepSubmarineSonar } from '../defense_grid/deep_submarine_sonar.js';
import { EarlyWarningRadar } from '../defense_grid/early_warning_radar.js';
import { ElectronicWarfareOfficer } from '../defense_grid/electronic_warfare.js';
import { HoneypotDecoySystem } from '../perimeter/honeypot_decoy_system.js';
import { QuarantineEnclave } from '../forensics/quarantine_enclave.js';
import { createHash, createHmac, randomUUID } from 'node:crypto';
import { ByzantineCounterIntel } from '../defense_grid/byzantine_counter_intel.js';
import { CapabilityTokenManager } from '../perimeter/capability_token_manager.js';
import { OSFirewallShield } from '../perimeter/os_firewall_shield.js';
import { WarningBroadcastSystem } from './warning_broadcast_system.js';
import { NucleiTemplateEngine, Severity } from '../vulnerability_scanner/nuclei_template_engine.js';
import { ZeroDayDetector, ZeroDayThreatLevel } from '../vulnerability_scanner/zero_day_detector.js';

export class FortressCommander {
  constructor(initialState = {}, options = {}) {
    this.tokenManager = options.tokenManager || options.capabilityTokenManager || new CapabilityTokenManager(options.masterSecretKey);
    this.kernel = new DeterministicKernel(initialState, {
      ...options,
      tokenManager: this.tokenManager
    });
    this.radar = new EarlyWarningRadar(options.radarOptions);
    this.airDefense = new AirDefenseInterceptor(options.airDefenseOptions);
    this.submarineSonar = new DeepSubmarineSonar(options.submarineOptions);
    this.byzantineCouncil = new ByzantineCounterIntel(options.byzantineOptions);
    this.osFirewall = new OSFirewallShield(options.firewallOptions);
    this.warningSystem = new WarningBroadcastSystem();
    this.electronicWarfare = new ElectronicWarfareOfficer(options.ewOptions);
    this.honeypot = new HoneypotDecoySystem();
    this.quarantineEnclave = new QuarantineEnclave();
    // ARCH-15: Integrate Nuclei declarative policy scanner and Zero-Day detector into main pipeline
    this.nucleiScanner = options.nucleiScanner || new NucleiTemplateEngine(options.nucleiOptions);
    this.zeroDayDetector = options.zeroDayDetector || new ZeroDayDetector(options.zeroDayOptions);
    this.securityAuditLog = [];
    this.maxSecurityAuditLogSize = options.maxSecurityAuditLogSize || 5000;
    this.onSecurityAuditEvent = typeof options.onSecurityAuditEvent === 'function' ? options.onSecurityAuditEvent : null;

    // Register Air Defense with Kernel for automated interception
    this.kernel.registerInterceptor(this.airDefense);
  }

  /**
   * Emits a structured SOC/SIEM security audit event with SHA-256 content
   * fingerprint and zero raw sensitive payload leakage.
   */
  emitSecurityAuditEvent({
    layer,
    agentId,
    threatType,
    payload = '',
    action = 'BLOCK',
    correlationId = null
  }) {
    let serialized = '';
    try {
      serialized = typeof payload === 'string' ? payload : JSON.stringify(payload ?? '');
    } catch {
      serialized = '[UNSERIALIZABLE_CIRCULAR_OR_DEEP_PAYLOAD]';
    }
    const payloadSha256 = createHash('sha256').update(serialized).digest('hex');

    const event = {
      timestamp: new Date().toISOString(),
      correlationId: correlationId || randomUUID(),
      layer,
      agentId,
      threatType,
      action,
      payloadSha256
    };

    if (this.securityAuditLog.length >= this.maxSecurityAuditLogSize) {
      this.securityAuditLog.shift();
    }
    this.securityAuditLog.push(event);

    if (this.onSecurityAuditEvent) {
      this.onSecurityAuditEvent(event);
    }
    return event;
  }

  registerFriendlyAgent(agentId, policyScope = ['*']) {
    return this.airDefense.registerFriendlyAgent(agentId, policyScope);
  }

  generateIFFProof(agentId, nonce = crypto.randomUUID(), issuedAt = Date.now()) {
    const record = this.airDefense.certifiedFriendlyAgents.get(agentId);
    if (!record) return null;
    const signature = this.airDefense.computeIffSignature(record.token, nonce, issuedAt);
    return { nonce, issuedAt, signature };
  }

  /**
   * Complete end-to-end multi-layer defense pipeline for agent execution.
   */
  async processAgentMission({
    agentId,
    userPrompt = '',
    internalScratchpad = '',
    emittedOutput = '',
    activationMetrics = {},
    actionProposal = null,
    nextStateComputation = (s) => s,
    isHighImpactAction = false
  }) {
    const pipelineStartTime = performance.now();
    const correlationId = randomUUID();
    const defenseAudit = {
      correlationId,
      agentId,
      stagesPassed: [],
      intercepted: false,
      interceptionStage: null,
      reason: null
    };

    // =========================================================================
    // LAYER -1: Electronic Warfare & Signal Jamming Analysis (ECM/ECCM)
    // =========================================================================
    if (userPrompt) {
      const ewResult = this.electronicWarfare.analyzeSignalInterference({
        agentId,
        payloadText: userPrompt
      });
      if (ewResult.jammingDetected) {
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = ThreatDomain.RADAR_ISR;
        defenseAudit.reason = ewResult.reason;

        this.warningSystem.dispatchWarning({
          agentId,
          level: 'ORANGE',
          threatDetail: ewResult.reason
        });

        this.kernel.quarantineAgent(agentId, ewResult.reason);
        this.quarantineEnclave.quarantineAndSynthesizeVaccine({
          agentId,
          threatEvent: ewResult.threatEvent,
          compromisedContext: { userPrompt }
        });

        return {
          success: false,
          blocked: true,
          interceptionStage: ThreatDomain.RADAR_ISR,
          reason: ewResult.reason,
          threatEvent: ewResult.threatEvent,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
    }

    // =========================================================================
    // LAYER 0: OS & Network AI Firewall Stream Inspection (Anti-Worm / Anti-Trojan)
    // =========================================================================
    if (userPrompt) {
      const streamCheck = this.osFirewall.inspectPayloadStream({
        agentId,
        payload: userPrompt,
        direction: 'INGRESS'
      });
      if (!streamCheck.allowed) {
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = ThreatDomain.GROUND_FORTRESS;
        defenseAudit.reason = streamCheck.reason;

        this.warningSystem.dispatchWarning({
          agentId,
          level: 'RED',
          threatDetail: streamCheck.reason
        });

        this.kernel.quarantineAgent(agentId, streamCheck.reason);
        this.kernel.setDefenseCondition(DefenseCondition.DEFCON_2);

        return {
          success: false,
          blocked: true,
          interceptionStage: ThreatDomain.GROUND_FORTRESS,
          reason: streamCheck.reason,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('FIREWALL_DPI_CLEAR');
    }

    // =========================================================================
    // LAYER 1: Early Warning Radar & Reconnaissance (Pre-reasoning input scan)
    // =========================================================================
    if (userPrompt) {
      const radarResult = this.radar.scanAirspace(userPrompt, agentId);
      if (!radarResult.safe) {
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = ThreatDomain.RADAR_ISR;
        defenseAudit.reason = radarResult.reason;

        this.warningSystem.dispatchWarning({
          agentId,
          level: 'ORANGE',
          threatDetail: radarResult.reason
        });

        this.kernel.setDefenseCondition(DefenseCondition.DEFCON_3);

        return {
          success: false,
          blocked: true,
          interceptionStage: ThreatDomain.RADAR_ISR,
          reason: radarResult.reason,
          threatEvent: radarResult.threatEvent,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('RADAR_ISR_CLEAR');

      // =========================================================================
      // LAYER 1.5: Declarative Nuclei Policy Scan & Zero-Day Anomaly Check (ARCH-15)
      // =========================================================================
      const nucleiPromptScan = this.nucleiScanner.scan(
        { payload: userPrompt },
        { severities: [Severity.CRITICAL, Severity.HIGH] }
      );
      if (nucleiPromptScan.vulnerabilitiesFound > 0) {
        const topMatch = nucleiPromptScan.matches[0];
        const reason = `[NUCLEI_POLICY_SCANNER] Matched '${topMatch.templateId}' (${topMatch.severity}, CVSS ${topMatch.cvssScore}): ${topMatch.name}`;
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = 'NUCLEI_POLICY_SCANNER';
        defenseAudit.reason = reason;

        this.warningSystem.dispatchWarning({ agentId, level: 'RED', threatDetail: reason });
        const quarantined = topMatch.severity === Severity.CRITICAL;
        if (quarantined) {
          this.kernel.quarantineAgent(agentId, reason);
          this.kernel.setDefenseCondition(DefenseCondition.DEFCON_2);
        }

        const securityAuditEvent = this.emitSecurityAuditEvent({
          layer: 'LAYER_1_5_NUCLEI_PROMPT',
          agentId,
          threatType: topMatch.templateId,
          payload: userPrompt,
          action: quarantined ? 'QUARANTINE_AND_BLOCK' : 'BLOCK',
          correlationId
        });

        return {
          success: false,
          blocked: true,
          interceptionStage: 'NUCLEI_POLICY_SCANNER',
          reason,
          nucleiMatches: nucleiPromptScan.matches,
          securityAuditEvent,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('NUCLEI_PROMPT_CLEAR');

      const zeroDayPromptScan = this.zeroDayDetector.inspect({
        agentId,
        payload: userPrompt,
        actionType: actionProposal?.toolName || actionProposal?.actionType || 'PROMPT_INGRESS'
      });
      if (
        zeroDayPromptScan.threatLevel === ZeroDayThreatLevel.CONFIRMED_ZERO_DAY ||
        zeroDayPromptScan.threatLevel === ZeroDayThreatLevel.PROBABLE_ZERO_DAY
      ) {
        const reason = `[ZERO_DAY_DETECTOR] ${zeroDayPromptScan.threatLevel} (confidence=${zeroDayPromptScan.confidence.toFixed(2)}): ${zeroDayPromptScan.reasoning}`;
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = 'ZERO_DAY_DETECTOR';
        defenseAudit.reason = reason;

        this.warningSystem.dispatchWarning({ agentId, level: 'RED', threatDetail: reason });
        this.kernel.quarantineAgent(agentId, reason);
        this.kernel.setDefenseCondition(DefenseCondition.DEFCON_2);

        const securityAuditEvent = this.emitSecurityAuditEvent({
          layer: 'LAYER_1_5_ZERODAY_PROMPT',
          agentId,
          threatType: zeroDayPromptScan.anomalies[0]?.type || zeroDayPromptScan.threatLevel,
          payload: userPrompt,
          action: 'QUARANTINE_AND_BLOCK',
          correlationId
        });

        return {
          success: false,
          blocked: true,
          interceptionStage: 'ZERO_DAY_DETECTOR',
          reason,
          zeroDayAssessment: zeroDayPromptScan,
          securityAuditEvent,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('ZERODAY_PROMPT_CLEAR');
    }

    // =========================================================================
    // LAYER 2: Deep Submarine Sonar (Stateless SVD projection & rotated basis)
    // =========================================================================
    if (internalScratchpad || activationMetrics.activationVector) {
      const sonarResult = this.submarineSonar.pingLatentDepths({
        agentId,
        internalScratchpad,
        emittedOutput,
        activationVector: activationMetrics.activationVector,
        kernelHash: this.kernel.dag.currentRoot,
        timestep: Date.now()
      });

      if (sonarResult.deceptionDetected) {
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = ThreatDomain.DEEP_SUBMARINE;
        defenseAudit.reason = sonarResult.reason;

        this.warningSystem.dispatchWarning({
          agentId,
          level: 'RED',
          threatDetail: sonarResult.reason
        });

        // Quarantine immediately on latent treason
        this.kernel.quarantineAgent(agentId, sonarResult.reason);
        this.kernel.setDefenseCondition(DefenseCondition.DEFCON_2);

        return {
          success: false,
          blocked: true,
          interceptionStage: ThreatDomain.DEEP_SUBMARINE,
          reason: sonarResult.reason,
          threatEvent: sonarResult.threatEvent,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('DEEP_SUBMARINE_CLEAR');
    }

    // If no action is proposed, mission concludes safely at the cognitive level
    if (!actionProposal) {
      return {
        success: true,
        blocked: false,
        defenseAudit,
        state: this.kernel.getState(),
        latencyMs: performance.now() - pipelineStartTime
      };
    }

    // NOTE (SEC-13): IFF proofs are NEVER auto-attached server-side.
    // Callers claiming a registered friendly agentId must supply their own cryptographic iffProof.

    // =========================================================================
    // LAYER 2.5: Honeypot Decoy Enclave Inspection (Canary Tripwire)
    // =========================================================================
    const honeypotResult = this.honeypot.inspectForDecoyInteraction(agentId, actionProposal);
    if (honeypotResult.tripwireTriggered) {
      defenseAudit.intercepted = true;
      defenseAudit.interceptionStage = honeypotResult.threatEvent?.domain || ThreatDomain.GROUND_FORTRESS;
      defenseAudit.reason = honeypotResult.reason;

      this.warningSystem.dispatchWarning({
        agentId,
        level: 'RED',
        threatDetail: honeypotResult.reason
      });

      this.kernel.quarantineAgent(agentId, honeypotResult.reason);
      this.kernel.setDefenseCondition(DefenseCondition.DEFCON_1);

      this.quarantineEnclave.quarantineAndSynthesizeVaccine({
        agentId,
        threatEvent: honeypotResult.threatEvent,
        compromisedContext: { actionProposal }
      });

      return {
        success: false,
        blocked: true,
        interceptionStage: defenseAudit.interceptionStage,
        reason: honeypotResult.reason,
        threatEvent: honeypotResult.threatEvent,
        latencyMs: performance.now() - pipelineStartTime
      };
    }
    defenseAudit.stagesPassed.push('HONEYPOT_DECOY_CLEAR');

    // =========================================================================
    // LAYER 3: Byzantine Multi-Agent Consensus (For high-impact mutations)
    // =========================================================================
    if (isHighImpactAction && this.byzantineCouncil.validators.size > 0) {
      const consensusResult = await this.byzantineCouncil.evaluateConsensus(actionProposal);
      if (!consensusResult.consensusReached) {
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = ThreatDomain.BYZANTINE_INTEL;
        defenseAudit.reason = `Byzantine Council rejected proposal. Approvals: ${consensusResult.approvals}/${consensusResult.thresholdRequired}.`;

        return {
          success: false,
          blocked: true,
          interceptionStage: ThreatDomain.BYZANTINE_INTEL,
          reason: defenseAudit.reason,
          consensusResult,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('BYZANTINE_CONSENSUS_REACHED');
    }

    // =========================================================================
    // LAYER 4: OS & AI Firewall Shield (Perimeter syscall & egress checks)
    // =========================================================================
    if (actionProposal.targetPath) {
      const fsCheck = this.osFirewall.interceptFileSystemCall({
        agentId,
        operation: actionProposal.actionType,
        targetPath: actionProposal.targetPath
      });
      if (!fsCheck.allowed) {
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = ThreatDomain.GROUND_FORTRESS;
        defenseAudit.reason = fsCheck.reason;

        this.warningSystem.dispatchWarning({
          agentId,
          level: 'RED',
          threatDetail: fsCheck.reason
        });

        this.kernel.quarantineAgent(agentId, fsCheck.reason);
        return {
          success: false,
          blocked: true,
          interceptionStage: ThreatDomain.GROUND_FORTRESS,
          reason: fsCheck.reason,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('OS_FIREWALL_FS_CLEAR');
    }

    if (actionProposal.destinationHost) {
      const netCheck = this.osFirewall.interceptNetworkEgress({
        agentId,
        destinationHost: actionProposal.destinationHost,
        port: actionProposal.port || 443
      });
      if (!netCheck.allowed) {
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = ThreatDomain.GROUND_FORTRESS;
        defenseAudit.reason = netCheck.reason;

        this.warningSystem.dispatchWarning({
          agentId,
          level: 'ORANGE',
          threatDetail: netCheck.reason
        });

        return {
          success: false,
          blocked: true,
          interceptionStage: ThreatDomain.GROUND_FORTRESS,
          reason: netCheck.reason,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('OS_FIREWALL_NET_CLEAR');
    }

    // =========================================================================
    // LAYER 4.5: Action Proposal Nuclei & Zero-Day Inspection (ARCH-15)
    // =========================================================================
    if (actionProposal.parameters) {
      // Run ZeroDay structural & heuristic scan FIRST so circular/deep DoS payloads fail-closed
      // before JSON serialization inside regex-based template scanners.
      const zeroDayParamScan = this.zeroDayDetector.inspect({
        agentId,
        actionType: actionProposal.toolName || actionProposal.actionType || '',
        parameters: actionProposal.parameters
      });
      if (
        zeroDayParamScan.threatLevel === ZeroDayThreatLevel.CONFIRMED_ZERO_DAY ||
        zeroDayParamScan.threatLevel === ZeroDayThreatLevel.PROBABLE_ZERO_DAY
      ) {
        const reason = `[ZERO_DAY_DETECTOR] ${zeroDayParamScan.threatLevel} in action parameters (confidence=${zeroDayParamScan.confidence.toFixed(2)}): ${zeroDayParamScan.reasoning}`;
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = 'ZERO_DAY_DETECTOR';
        defenseAudit.reason = reason;

        this.warningSystem.dispatchWarning({ agentId, level: 'RED', threatDetail: reason });
        this.kernel.quarantineAgent(agentId, reason);
        const securityAuditEvent = this.emitSecurityAuditEvent({
          layer: 'LAYER_4_5_ZERODAY_ACTION',
          agentId,
          threatType: zeroDayParamScan.anomalies[0]?.type || zeroDayParamScan.threatLevel,
          payload: actionProposal.parameters,
          action: 'QUARANTINE_AND_BLOCK',
          correlationId
        });

        return {
          success: false,
          blocked: true,
          interceptionStage: 'ZERO_DAY_DETECTOR',
          reason,
          zeroDayAssessment: zeroDayParamScan,
          securityAuditEvent,
          latencyMs: performance.now() - pipelineStartTime
        };
      }

      const nucleiParamScan = this.nucleiScanner.scan(
        { payload: actionProposal.parameters },
        { severities: [Severity.CRITICAL, Severity.HIGH] }
      );
      if (nucleiParamScan.vulnerabilitiesFound > 0) {
        const topMatch = nucleiParamScan.matches[0];
        const reason = `[NUCLEI_POLICY_SCANNER] Hostile action parameters matched '${topMatch.templateId}' (${topMatch.severity}): ${topMatch.name}`;
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = 'NUCLEI_POLICY_SCANNER';
        defenseAudit.reason = reason;

        this.warningSystem.dispatchWarning({ agentId, level: 'RED', threatDetail: reason });
        this.kernel.quarantineAgent(agentId, reason);
        const securityAuditEvent = this.emitSecurityAuditEvent({
          layer: 'LAYER_4_5_NUCLEI_ACTION',
          agentId,
          threatType: topMatch.templateId,
          payload: actionProposal.parameters,
          action: 'QUARANTINE_AND_BLOCK',
          correlationId
        });

        return {
          success: false,
          blocked: true,
          interceptionStage: 'NUCLEI_POLICY_SCANNER',
          reason,
          nucleiMatches: nucleiParamScan.matches,
          securityAuditEvent,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('ACTION_SCANNER_CLEAR');
    }

    // =========================================================================
    // LAYER 5: Deterministic Kernel Execution & Air Defense Veto (O(1) Rollback)
    // =========================================================================
    const executionResult = this.kernel.executeTransaction({
      agentId,
      proposal: actionProposal,
      nextStateComputation
    });

    if (!executionResult.success) {
      defenseAudit.intercepted = true;
      defenseAudit.interceptionStage = executionResult.interceptedBy || 'DETERMINISTIC_KERNEL';
      defenseAudit.reason = executionResult.reason;

      this.warningSystem.dispatchWarning({
        agentId,
        level: 'RED',
        threatDetail: executionResult.reason
      });

      return {
        ...executionResult,
        interceptionStage: defenseAudit.interceptionStage,
        latencyMs: performance.now() - pipelineStartTime
      };
    }

    defenseAudit.stagesPassed.push('KERNEL_TRANSACTION_COMMITTED');

    return {
      success: true,
      blocked: false,
      committedNodeHash: executionResult.committedNodeHash,
      state: executionResult.state,
      defenseAudit,
      latencyMs: performance.now() - pipelineStartTime
    };
  }
}
