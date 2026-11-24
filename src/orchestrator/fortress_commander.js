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
import { PayloadCanonicalizer } from '../perimeter/payload_canonicalizer.js';
import { MultiTurnSessionWindow } from '../perimeter/multi_turn_window.js';
import { DefenseStateStore } from '../state/defense_state_store.js';
import { WarningBroadcastSystem } from './warning_broadcast_system.js';
import { NucleiTemplateEngine, Severity } from '../vulnerability_scanner/nuclei_template_engine.js';
import { ZeroDayDetector, ZeroDayThreatLevel } from '../vulnerability_scanner/zero_day_detector.js';

export class FortressCommander {
  constructor(initialState = {}, options = {}) {
    this._ownsStateStore = false;
    if (options.stateStore) {
      this.stateStore = options.stateStore;
    } else if (options.stateDbPath) {
      this.stateStore = new DefenseStateStore({ dbPath: options.stateDbPath });
      this._ownsStateStore = true;
    } else {
      this.stateStore = new DefenseStateStore({ memoryOnly: true, sweepIntervalMs: 0 });
      this._ownsStateStore = true;
    }

    this.tokenManager = options.tokenManager || options.capabilityTokenManager || new CapabilityTokenManager(options.masterSecretKey, {
      stateStore: this.stateStore
    });
    if (this.tokenManager && !this.tokenManager.stateStore) {
      this.tokenManager.stateStore = this.stateStore;
    }

    this.kernel = new DeterministicKernel(initialState, {
      ...options,
      tokenManager: this.tokenManager,
      stateStore: this.stateStore
    });
    this.radar = new EarlyWarningRadar(options.radarOptions);
    this.airDefense = new AirDefenseInterceptor({
      ...options.airDefenseOptions,
      stateStore: this.stateStore
    });
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
    // Batch 5: Canonicalizer, Multi-Turn Sliding Window & Durable State
    this.canonicalizer = options.canonicalizer || new PayloadCanonicalizer(options.canonicalizerOptions);
    this.sessionWindow = options.sessionWindow || new MultiTurnSessionWindow(options.sessionWindowOptions);

    this.securityAuditLog = [];
    this.maxAuditLogEntries = Number(options.maxAuditLogEntries ?? options.maxSecurityAuditLogSize ?? 10000);
    this.droppedAuditEvents = 0;
    this.auditSinkErrors = 0;
    this.onSecurityAuditEvent = typeof options.onSecurityAuditEvent === 'function' ? options.onSecurityAuditEvent : null;
    this.siemExporter = options.siemExporter || null;

    // Register Air Defense with Kernel for automated interception
    this.kernel.registerInterceptor(this.airDefense);
  }

  /**
   * Releases owned durable state store handles and flushes any configured SIEM exporter.
   */
  async close() {
    if (this.siemExporter && typeof this.siemExporter.flush === 'function') {
      await this.siemExporter.flush();
    }
    if (this._ownsStateStore && this.stateStore && typeof this.stateStore.close === 'function') {
      await this.stateStore.close();
    }
  }

  /**
   * Emits a structured SOC/SIEM security audit event with SHA-256 content
   * fingerprint and zero raw sensitive payload leakage.
   * Bounded ring-buffer & isolated sink error handling prevent pipeline disruption.
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

    if (this.maxAuditLogEntries > 0) {
      while (this.securityAuditLog.length >= this.maxAuditLogEntries) {
        this.securityAuditLog.shift();
        this.droppedAuditEvents++;
      }
      this.securityAuditLog.push(event);
    } else {
      this.droppedAuditEvents++;
    }

    if (this.onSecurityAuditEvent) {
      try {
        const maybePromise = this.onSecurityAuditEvent(event);
        if (maybePromise && typeof maybePromise.catch === 'function') {
          maybePromise.catch(() => {
            this.auditSinkErrors++;
          });
        }
      } catch {
        this.auditSinkErrors++;
      }
    }

    if (this.siemExporter && typeof this.siemExporter.exportEvent === 'function') {
      try {
        this.siemExporter.exportEvent(event);
      } catch {
        this.auditSinkErrors++;
      }
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
    sessionId = 'default',
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
      sessionId,
      stagesPassed: [],
      intercepted: false,
      interceptionStage: null,
      reason: null,
      canonicalization: null
    };

    // =========================================================================
    // PRE-FLIGHT: Durable Quarantine Enforcement (Survives Restarts)
    // =========================================================================
    if (agentId && this.kernel.isAgentQuarantined(agentId)) {
      const reason = `Agent '${agentId}' is under durable security quarantine and stripped of execution authority.`;
      defenseAudit.intercepted = true;
      defenseAudit.interceptionStage = 'DETERMINISTIC_KERNEL';
      defenseAudit.reason = reason;
      const securityAuditEvent = this.emitSecurityAuditEvent({
        layer: 'PREFLIGHT_DURABLE_QUARANTINE',
        agentId,
        threatType: 'QUARANTINED_AGENT_ACCESS_DENIED',
        payload: userPrompt || actionProposal?.toolName || agentId,
        action: 'BLOCK',
        correlationId
      });
      return {
        success: false,
        blocked: true,
        interceptionStage: 'DETERMINISTIC_KERNEL',
        reason,
        securityAuditEvent,
        latencyMs: performance.now() - pipelineStartTime
      };
    }

    // =========================================================================
    // LAYER -1.5: Mandatory Payload Canonicalization & Obfuscation De-masking
    // =========================================================================
    const canonPrompt = userPrompt ? this.canonicalizer.canonicalize(userPrompt) : null;
    if (canonPrompt) {
      defenseAudit.canonicalization = {
        maxObservedDepth: canonPrompt.maxObservedDepth,
        decodedLayersCount: canonPrompt.decodedLayers.length,
        evasionDetected: canonPrompt.evasionDetected,
        telemetry: canonPrompt.telemetry
      };

      if (canonPrompt.evasionDetected) {
        const reason = `[PAYLOAD_CANONICALIZER] Intentional evasion/obfuscation detected: ${canonPrompt.evasionReasons.join(', ')}`;
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = 'PAYLOAD_OBFUSCATION_EVASION';
        defenseAudit.reason = reason;

        this.warningSystem.dispatchWarning({ agentId, level: 'RED', threatDetail: reason });
        this.kernel.quarantineAgent(agentId, reason);
        this.kernel.setDefenseCondition(DefenseCondition.DEFCON_2);

        const securityAuditEvent = this.emitSecurityAuditEvent({
          layer: 'LAYER_CANONICALIZER_PROMPT',
          agentId,
          threatType: 'PAYLOAD_OBFUSCATION_EVASION',
          payload: userPrompt,
          action: 'QUARANTINE_AND_BLOCK',
          correlationId
        });

        return {
          success: false,
          blocked: true,
          interceptionStage: 'PAYLOAD_OBFUSCATION_EVASION',
          reason,
          canonicalization: canonPrompt,
          securityAuditEvent,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('CANONICALIZER_CLEAR');
    }

    // =========================================================================
    // LAYER -1: Electronic Warfare & Signal Jamming Analysis (ECM/ECCM)
    // Only apply raw high-entropy jamming check when input is NOT decodable
    // structured payload layers (encoded attacks proceed to Radar/Nuclei/ZeroDay).
    // =========================================================================
    if (userPrompt && canonPrompt.decodedLayers.length === 0) {
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
        payload: canonPrompt.combinedText,
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
      const scanSurface = canonPrompt.combinedText;
      const radarResult = this.radar.scanAirspace(scanSurface, agentId);
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
          canonicalization: canonPrompt,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('RADAR_ISR_CLEAR');

      // =========================================================================
      // LAYER 1.5: Declarative Nuclei Policy Scan & Zero-Day Anomaly Check (ARCH-15)
      // =========================================================================
      const nucleiPromptScan = this.nucleiScanner.scan(
        { payload: scanSurface },
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
          canonicalization: canonPrompt,
          securityAuditEvent,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('NUCLEI_PROMPT_CLEAR');

      const zeroDayPromptScan = this.zeroDayDetector.inspect({
        agentId,
        payload: scanSurface,
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
          canonicalization: canonPrompt,
          securityAuditEvent,
          latencyMs: performance.now() - pipelineStartTime
        };
      }
      defenseAudit.stagesPassed.push('ZERODAY_PROMPT_CLEAR');

      // =========================================================================
      // LAYER 1.8: Multi-Turn Sliding Window Fragmented-Attack Inspection
      // =========================================================================
      const windowInput = canonPrompt.decodedLayers.length > 0
        ? [canonPrompt.canonicalText, ...canonPrompt.decodedLayers].join(' ')
        : canonPrompt.canonicalText;
      const windowState = this.sessionWindow.recordAndAggregate(agentId, windowInput, sessionId);
      if (windowState.shouldInspectWindow) {
        const windowRadar = this.radar.scanAirspace(windowState.combinedWindowText, agentId);
        const windowNuclei = this.nucleiScanner.scan(
          { payload: windowState.combinedWindowText },
          { severities: [Severity.CRITICAL, Severity.HIGH] }
        );
        const windowZeroDay = this.zeroDayDetector.inspect({
          agentId,
          payload: windowState.combinedWindowText,
          actionType: 'MULTI_TURN_WINDOW'
        });

        const windowTriggered =
          !windowRadar.safe ||
          windowNuclei.vulnerabilitiesFound > 0 ||
          windowZeroDay.threatLevel === ZeroDayThreatLevel.CONFIRMED_ZERO_DAY ||
          windowZeroDay.threatLevel === ZeroDayThreatLevel.PROBABLE_ZERO_DAY;

        if (windowTriggered) {
          this.sessionWindow.rollbackLastTurn(agentId, sessionId);
          const triggerDetail = !windowRadar.safe
            ? windowRadar.reason
            : (windowNuclei.vulnerabilitiesFound > 0
              ? `Matched '${windowNuclei.matches[0].templateId}': ${windowNuclei.matches[0].name}`
              : windowZeroDay.reasoning);
          const reason = `[MULTI_TURN_SLIDING_WINDOW] Fragmented multi-turn threat across ${windowState.turnCount} turns: ${triggerDetail}`;
          defenseAudit.intercepted = true;
          defenseAudit.interceptionStage = 'MULTI_TURN_SLIDING_WINDOW';
          defenseAudit.reason = reason;

          this.warningSystem.dispatchWarning({ agentId, level: 'RED', threatDetail: reason });
          this.kernel.quarantineAgent(agentId, reason);
          this.kernel.setDefenseCondition(DefenseCondition.DEFCON_2);

          const securityAuditEvent = this.emitSecurityAuditEvent({
            layer: 'LAYER_1_8_MULTI_TURN_WINDOW',
            agentId,
            threatType: 'MULTI_TURN_FRAGMENTED_INJECTION',
            payload: windowState.combinedWindowText,
            action: 'QUARANTINE_AND_BLOCK',
            correlationId
          });

          return {
            success: false,
            blocked: true,
            interceptionStage: 'MULTI_TURN_SLIDING_WINDOW',
            reason,
            turnCount: windowState.turnCount,
            securityAuditEvent,
            latencyMs: performance.now() - pipelineStartTime
          };
        }
      }
      defenseAudit.stagesPassed.push('MULTI_TURN_WINDOW_CLEAR');
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

      const canonParams = this.canonicalizer.canonicalize(actionProposal.parameters);
      if (canonParams.evasionDetected) {
        const reason = `[PAYLOAD_CANONICALIZER] Intentional obfuscation in action parameters: ${canonParams.evasionReasons.join(', ')}`;
        defenseAudit.intercepted = true;
        defenseAudit.interceptionStage = 'PAYLOAD_OBFUSCATION_EVASION';
        defenseAudit.reason = reason;

        this.warningSystem.dispatchWarning({ agentId, level: 'RED', threatDetail: reason });
        this.kernel.quarantineAgent(agentId, reason);
        const securityAuditEvent = this.emitSecurityAuditEvent({
          layer: 'LAYER_4_5_CANONICALIZER_ACTION',
          agentId,
          threatType: 'PAYLOAD_OBFUSCATION_EVASION',
          payload: actionProposal.parameters,
          action: 'QUARANTINE_AND_BLOCK',
          correlationId
        });

        return {
          success: false,
          blocked: true,
          interceptionStage: 'PAYLOAD_OBFUSCATION_EVASION',
          reason,
          canonicalization: canonParams,
          securityAuditEvent,
          latencyMs: performance.now() - pipelineStartTime
        };
      }

      const nucleiParamScan = this.nucleiScanner.scan(
        { payload: canonParams.combinedText },
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

  /**
   * LAYER 5: Tool Output Sanitization (Anti Indirect Prompt Injection Gate)
   * Inspects untrusted data returned from external tools (RAG, Web, APIs)
   * through PayloadCanonicalizer + EarlyWarningRadar + NucleiTemplateEngine + ZeroDayDetector
   * BEFORE it is allowed back into the agent context window.
   *
   * @param {string} agentId
   * @param {string} toolName
   * @param {string|Object} rawOutput
   * @param {Object} [context={}]
   * @returns {{
   *   safe: boolean,
   *   allowed: boolean,
   *   blocked: boolean,
   *   interceptionStage?: string,
   *   threatType?: string,
   *   sanitizedOutput: string|null,
   *   reason?: string,
   *   securityAuditEvent?: Object,
   *   canonicalization?: Object
   * }}
   */
  inspectToolOutput(agentId, toolName, rawOutput, context = {}) {
    const correlationId = context.correlationId || randomUUID();

    // 1. Structural & shellcode ZeroDay pre-check (handles circular/depth-32 DoS before stringify)
    const zeroDayPreScan = this.zeroDayDetector.inspect({
      agentId,
      payload: typeof rawOutput === 'string' ? rawOutput : '',
      parameters: typeof rawOutput === 'object' && rawOutput !== null ? rawOutput : {},
      actionType: `TOOL_OUTPUT:${toolName || 'unknown'}`
    });

    if (
      zeroDayPreScan.threatLevel === ZeroDayThreatLevel.CONFIRMED_ZERO_DAY ||
      zeroDayPreScan.threatLevel === ZeroDayThreatLevel.PROBABLE_ZERO_DAY
    ) {
      const reason = `[LAYER_5_TOOL_OUTPUT] Blocked hostile Zero-Day pattern in '${toolName}' output: ${zeroDayPreScan.reasoning}`;
      this.warningSystem.dispatchWarning({ agentId, level: 'RED', threatDetail: reason });
      if (context.quarantineOnThreat) {
        this.kernel.quarantineAgent(agentId, reason);
      }
      const securityAuditEvent = this.emitSecurityAuditEvent({
        layer: 'LAYER_5_TOOL_OUTPUT_SANITIZATION',
        agentId,
        threatType: 'INDIRECT_PROMPT_INJECTION',
        payload: rawOutput,
        action: 'BLOCK_TOOL_OUTPUT',
        correlationId
      });
      return {
        safe: false,
        allowed: false,
        blocked: true,
        interceptionStage: 'LAYER_5_TOOL_OUTPUT_SANITIZATION',
        threatType: 'INDIRECT_PROMPT_INJECTION',
        sanitizedOutput: null,
        reason,
        zeroDayAssessment: zeroDayPreScan,
        securityAuditEvent
      };
    }

    // 2. Canonicalize & recursively decode tool output
    const canonOut = this.canonicalizer.canonicalize(rawOutput);
    if (canonOut.evasionDetected) {
      const reason = `[LAYER_5_TOOL_OUTPUT] Blocked obfuscated evasion in '${toolName}' output: ${canonOut.evasionReasons.join(', ')}`;
      this.warningSystem.dispatchWarning({ agentId, level: 'RED', threatDetail: reason });
      if (context.quarantineOnThreat) {
        this.kernel.quarantineAgent(agentId, reason);
      }
      const securityAuditEvent = this.emitSecurityAuditEvent({
        layer: 'LAYER_5_TOOL_OUTPUT_SANITIZATION',
        agentId,
        threatType: 'INDIRECT_PROMPT_INJECTION',
        payload: canonOut.canonicalText,
        action: 'BLOCK_TOOL_OUTPUT',
        correlationId
      });
      return {
        safe: false,
        allowed: false,
        blocked: true,
        interceptionStage: 'LAYER_5_TOOL_OUTPUT_SANITIZATION',
        threatType: 'INDIRECT_PROMPT_INJECTION',
        sanitizedOutput: null,
        reason,
        canonicalization: canonOut,
        securityAuditEvent
      };
    }

    // 3. Scan decoded + canonicalized output across Radar, Nuclei & ZeroDay
    const radarRes = this.radar.scanAirspace(canonOut.combinedText, agentId);
    const nucleiRes = this.nucleiScanner.scan(
      { payload: canonOut.combinedText },
      { severities: [Severity.CRITICAL, Severity.HIGH] }
    );
    const zeroDayDecoded = canonOut.decodedLayers.length > 0
      ? this.zeroDayDetector.inspect({
          agentId,
          payload: canonOut.combinedText,
          actionType: `TOOL_OUTPUT_DECODED:${toolName || 'unknown'}`
        })
      : zeroDayPreScan;

    const zeroDayTriggered =
      zeroDayDecoded.threatLevel === ZeroDayThreatLevel.CONFIRMED_ZERO_DAY ||
      zeroDayDecoded.threatLevel === ZeroDayThreatLevel.PROBABLE_ZERO_DAY;

    if (!radarRes.safe || nucleiRes.vulnerabilitiesFound > 0 || zeroDayTriggered) {
      const detail = !radarRes.safe
        ? radarRes.reason
        : (nucleiRes.vulnerabilitiesFound > 0
          ? `Matched '${nucleiRes.matches[0].templateId}': ${nucleiRes.matches[0].name}`
          : zeroDayDecoded.reasoning);
      const reason = `[LAYER_5_TOOL_OUTPUT] Indirect injection/malicious payload intercepted in '${toolName}': ${detail}`;

      this.warningSystem.dispatchWarning({ agentId, level: 'RED', threatDetail: reason });
      if (context.quarantineOnThreat) {
        this.kernel.quarantineAgent(agentId, reason);
      }

      const securityAuditEvent = this.emitSecurityAuditEvent({
        layer: 'LAYER_5_TOOL_OUTPUT_SANITIZATION',
        agentId,
        threatType: 'INDIRECT_PROMPT_INJECTION',
        payload: canonOut.combinedText,
        action: 'BLOCK_TOOL_OUTPUT',
        correlationId
      });

      return {
        safe: false,
        allowed: false,
        blocked: true,
        interceptionStage: 'LAYER_5_TOOL_OUTPUT_SANITIZATION',
        threatType: 'INDIRECT_PROMPT_INJECTION',
        sanitizedOutput: null,
        reason,
        nucleiMatches: nucleiRes.matches,
        canonicalization: canonOut,
        securityAuditEvent
      };
    }

    return {
      safe: true,
      allowed: true,
      blocked: false,
      sanitizedOutput: canonOut.canonicalText,
      canonicalization: canonOut
    };
  }
}
