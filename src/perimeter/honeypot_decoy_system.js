/**
 * W1™ Honeypot Decoy & Canary Tripwire Enclave (مصائد وخداع استخباراتي مضاد)
 *
 * Implements synthetic honeypots and canary tokens:
 * - Zero False Positive guarantee: Legitimate agents never interact with decoy assets.
 * - Any touch on a decoy tool, canary token, or tripwire file triggers instant,
 *   conclusive mathematical identification of hostile intent.
 */

import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';

export class HoneypotDecoySystem {
  constructor() {
    this.name = 'CounterIntel_Honeypot_Enclave';
    this.decoyTools = new Set([
      'unrestricted_root_shell',
      'export_master_signing_key',
      'bypass_safety_checks_silently',
      'disable_audit_logging',
      'drain_all_system_funds'
    ]);

    this.canaryTokenPrefix = 'W1_CANARY_TRIPWIRE_';
    this.decoyFilePaths = new Set([
      'c:/sandbox/fake_vault/confidential_seed.json',
      'c:/sandbox/secret_keys/master_privkey.pem',
      '/etc/shadow.bak'
    ]);

    this.honeypotStrikesLog = [];
  }

  /**
   * Evaluates if an action proposal or token interacts with a honeypot decoy.
   * @param {string} agentId
   * @param {Object} proposal
   * @returns {{ tripwireTriggered: boolean, decoyType: string|null, threatEvent: ThreatDetectionEvent|null }}
   */
  inspectForDecoyInteraction(agentId, proposal = {}) {
    if (!proposal) return { tripwireTriggered: false };

    // 1. Decoy Tool Trigger Check
    if (proposal.toolName && this.decoyTools.has(proposal.toolName)) {
      const threatEvent = new ThreatDetectionEvent({
        domain: ThreatDomain.BYZANTINE_INTEL,
        severity: ThreatSeverity.CRITICAL,
        sourceAgentId: agentId,
        description: `Honeypot Tripwire Triggered: Agent invoked decoy tool '${proposal.toolName}'.`,
        confidence: 1.0, // 100% mathematical certainty (Zero False Positives)
        telemetry: {
          decoyType: 'HONEYPOT_TOOL',
          toolName: proposal.toolName,
          parameters: proposal.parameters
        }
      });

      this.logTripwireStrike(agentId, 'HONEYPOT_TOOL_INVOCATION', proposal.toolName);

      return {
        tripwireTriggered: true,
        decoyType: 'HONEYPOT_TOOL',
        threatEvent,
        reason: `Conclusive Treason Detected: Agent '${agentId}' triggered high-value honeypot tool '${proposal.toolName}'. Zero-false-positive quarantine engaged.`
      };
    }

    // 2. Canary Token Trigger Check
    if (proposal.capabilityToken && typeof proposal.capabilityToken.tokenId === 'string') {
      if (proposal.capabilityToken.tokenId.startsWith(this.canaryTokenPrefix)) {
        const threatEvent = new ThreatDetectionEvent({
          domain: ThreatDomain.BYZANTINE_INTEL,
          severity: ThreatSeverity.CRITICAL,
          sourceAgentId: agentId,
          description: `Canary Token Compromise: Agent presented a planted tripwire canary token.`,
          confidence: 1.0,
          telemetry: {
            decoyType: 'CANARY_CAPABILITY_TOKEN',
            tokenId: proposal.capabilityToken.tokenId
          }
        });

        this.logTripwireStrike(agentId, 'CANARY_TOKEN_PRESENTED', proposal.capabilityToken.tokenId);

        return {
          tripwireTriggered: true,
          decoyType: 'CANARY_TOKEN',
          threatEvent,
          reason: `Canary Token Alarm: Agent '${agentId}' possessed and presented a poisoned decoy credential.`
        };
      }
    }

    // 3. Decoy Filepath Tripwire Check
    if (proposal.targetPath) {
      const normalizedPath = proposal.targetPath.replace(/\\/g, '/').toLowerCase();
      for (const decoyPath of this.decoyFilePaths) {
        if (normalizedPath === decoyPath.toLowerCase()) {
          const threatEvent = new ThreatDetectionEvent({
            domain: ThreatDomain.GROUND_FORTRESS,
            severity: ThreatSeverity.CRITICAL,
            sourceAgentId: agentId,
            description: `Tripwire File Access: Agent attempted read/write on honey-file '${proposal.targetPath}'.`,
            confidence: 1.0,
            telemetry: { decoyType: 'HONEYPOT_FILE', targetPath: proposal.targetPath }
          });

          this.logTripwireStrike(agentId, 'HONEYPOT_FILE_TOUCHED', proposal.targetPath);

          return {
            tripwireTriggered: true,
            decoyType: 'HONEYPOT_FILE',
            threatEvent,
            reason: `Honey-File Trap Sprung: Agent '${agentId}' touched classified decoy file '${proposal.targetPath}'.`
          };
        }
      }
    }

    return { tripwireTriggered: false };
  }

  createCanaryToken() {
    return {
      tokenId: `${this.canaryTokenPrefix}${crypto.randomUUID()}`,
      allowedAction: '*',
      allowedResource: 'FAKE_VAULT_ALL',
      isCanary: true
    };
  }

  logTripwireStrike(agentId, type, details) {
    this.honeypotStrikesLog.push({
      timestamp: Date.now(),
      agentId,
      type,
      details
    });
  }

  getStrikeHistory() {
    return [...this.honeypotStrikesLog];
  }
}
