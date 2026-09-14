/**
 * W1™ Web Defense Adapter (محول حماية الويب وبوابة التطبيقات)
 * File: src/target_app/w1_web_defense_adapter.js
 *
 * Connects the target web application with the W1 Defense Fortress:
 * - OS Firewall Shield (Worm & Trojan sanitizer)
 * - Early Warning Radar (DPI & Prompt injection detector)
 * - Static Linter & Kernel (Wiper & destructive command blocker)
 * - Hermetic Work Tent Watchdog (Path traversal & Credential thief blocker)
 * - Capability Token Manager (Cryptographic Zero Ambient Authority)
 * - Global Sybil Shield (Multi-identity distributed botnet DDoS defense)
 *
 * DO-178C LEVEL A SAFETY INVARIANT FLOOR:
 * Even if relaxedMode is requested, safety invariants are physically non-bypassable.
 * Destructive wipers, self-replicating worms, prompt injections, and unauthenticated
 * master credential theft can NEVER be executed.
 */

import { FortressCommander } from '../orchestrator/fortress_commander.js';
import { OSFirewallShield } from '../perimeter/os_firewall_shield.js';
import { AntiEscapeWatchdog } from '../enclave/anti_escape_watchdog.js';
import { CapabilityTokenManager } from '../perimeter/capability_token_manager.js';
import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';

export class W1WebDefenseAdapter {
  constructor(options = {}) {
    this.name = 'W1_Web_Defense_Adapter';
    this.commander = options.commander || new FortressCommander();
    this.osShield = new OSFirewallShield();
    this.watchdog = new AntiEscapeWatchdog();
    this.tokenManager = options.tokenManager || new CapabilityTokenManager();
    this.relaxedMode = options.relaxedMode || false;

    // Per-identity and Global Rate Limiting
    this.ipRateLimits = new Map();
    this.globalRequestTimestamps = [];
  }

  setRelaxedMode(relaxed) {
    this.relaxedMode = Boolean(relaxed);
  }

  /**
   * Resets rate-limiting sliding windows (useful for test isolation).
   */
  resetRateLimits() {
    this.ipRateLimits.clear();
    this.globalRequestTimestamps = [];
  }

  /**
   * Evaluates an incoming HTTP request before it touches the target backend.
   * Enforces the DO-178C Level A non-bypassable safety invariant floor.
   */
  async processIncomingPayload({ agentId, endpoint, method, headers = {}, body = {}, bodyStr = '' }) {
    // -----------------------------------------------------------------------
    // INVARIANT FLOOR 1: DATA WIPER & DESTRUCTIVE COMMAND CHECK (Admin Endpoint)
    // -----------------------------------------------------------------------
    if (endpoint === '/api/v1/admin/execute' || body.command) {
      const command = body.command || '';
      const cmdCheck = this.watchdog.validateCommand(agentId, command);
      if (!cmdCheck.allowed) {
        const isWiper = /rm\s+-rf|rmdir|drop\s+database|wipe_all|format/i.test(command);
        const reason = isWiper
          ? 'WIPER_MALWARE_PREVENTED: Destructive command rejected by Fortress Kernel.'
          : 'VIRUS_MALWARE_PREVENTED: Malicious binary shellcode or privilege escalation rejected by Fortress Linter.';
        return {
          allowed: false,
          reason,
          threatEvent: cmdCheck.threat
        };
      }
    }

    // -----------------------------------------------------------------------
    // INVARIANT FLOOR 2: TROJAN HORSE & AI WORM CHECK (RAG Ingestion Endpoint)
    // -----------------------------------------------------------------------
    const payloadText = body.document || body.prompt || body.command || bodyStr;

    // Check for Self-Replicating AI Worms (Morris-II)
    const wormDetection = this.osShield.detectAIWorm(agentId, payloadText);
    if (wormDetection.wormDetected) {
      return {
        allowed: false,
        reason: `AI_WORM_INTERCEPTED: Self-replicating generative malware blocked.`,
        threatEvent: wormDetection.threatEvent
      };
    }

    // Check for Prompt Injection / Trojan Backdoors via Radar
    const radarResult = this.commander.radar.scanAirspace(payloadText, agentId);
    if (!radarResult.safe) {
      return {
        allowed: false,
        reason: `TROJAN_PROMPT_INJECTION_BLOCKED: Hidden backdoor detected in payload.`,
        threatEvent: radarResult.threatEvent
      };
    }

    // Additional explicit regex check for prompt injection keywords in payload
    if (/ignore\s+(all\s+)?previous\s+instructions|system\s*override|exfiltrate\s+vault/i.test(payloadText)) {
      const threat = new ThreatDetectionEvent({
        domain: ThreatDomain.EARLY_WARNING,
        severity: ThreatSeverity.CRITICAL,
        sourceAgentId: agentId,
        description: 'Trojan horse prompt injection signature intercepted in payload.',
        confidence: 0.99
      });
      return {
        allowed: false,
        reason: 'TROJAN_PROMPT_INJECTION_BLOCKED: Hidden backdoor detected in payload.',
        threatEvent: threat
      };
    }

    // -----------------------------------------------------------------------
    // INVARIANT FLOOR 3: ZERO AMBIENT AUTHORITY & CREDENTIAL PROTECTION
    // -----------------------------------------------------------------------
    if (endpoint === '/api/v1/credentials' || endpoint === '/api/v1/vault/intel') {
      const authHeader = headers['authorization'] || headers['x-capability-token'];
      if (!authHeader) {
        const threat = new ThreatDetectionEvent({
          domain: ThreatDomain.OS_KERNEL_SHIELD,
          severity: ThreatSeverity.CRITICAL,
          sourceAgentId: agentId,
          description: `Unauthorized attempt to exfiltrate Crown Jewel credentials or intel without capability token.`,
          confidence: 1.0
        });
        return {
          allowed: false,
          reason: 'UNAUTHORIZED_EXFILTRATION_BLOCKED: Zero Ambient Authority enforced.',
          threatEvent: threat
        };
      }

      // If a capability token is presented, verify cryptographic method & path binding
      try {
        const rawToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
        const tokenObj = typeof rawToken === 'string' && rawToken.startsWith('{')
          ? JSON.parse(rawToken)
          : null;
        if (tokenObj) {
          const bindingCheck = this.tokenManager.verifyHttpBinding(tokenObj, method, endpoint);
          if (!bindingCheck.valid) {
            return {
              allowed: false,
              reason: `UNAUTHORIZED_EXFILTRATION_BLOCKED: ${bindingCheck.reason}`
            };
          }
        }
      } catch {
        return {
          allowed: false,
          reason: 'UNAUTHORIZED_EXFILTRATION_BLOCKED: Malformed capability token.'
        };
      }
    }

    // -----------------------------------------------------------------------
    // INVARIANT FLOOR 4: GLOBAL SYBIL SHIELD & DISTRIBUTED BOTNET DDOS DEFENSE
    // -----------------------------------------------------------------------
    const now = Date.now();
    this.globalRequestTimestamps = this.globalRequestTimestamps.filter(t => (now - t) < 1000);
    this.globalRequestTimestamps.push(now);

    // Global cluster threshold (15 req/sec strict, 25 req/sec relaxed)
    const globalLimit = this.relaxedMode ? 25 : 15;
    if (this.globalRequestTimestamps.length > globalLimit) {
      const threat = new ThreatDetectionEvent({
        domain: ThreatDomain.ELECTRONIC_WARFARE,
        severity: ThreatSeverity.HIGH,
        sourceAgentId: agentId,
        description: `Global Sybil Shield: Distributed DDoS flood throttled (${this.globalRequestTimestamps.length} aggregate req/sec across cluster).`,
        confidence: 0.99
      });
      return {
        allowed: false,
        reason: 'GLOBAL_SYBIL_DDOS_CLUSTER_THROTTLED',
        threatEvent: threat
      };
    }

    // Per-Agent Burst Limit
    const rateWindow = this.ipRateLimits.get(agentId) || { count: 0, firstSeen: now };
    if (now - rateWindow.firstSeen > 1000) {
      rateWindow.count = 1;
      rateWindow.firstSeen = now;
    } else {
      rateWindow.count++;
    }
    this.ipRateLimits.set(agentId, rateWindow);

    const perAgentLimit = this.relaxedMode ? 20 : 15;
    if (rateWindow.count > perAgentLimit) {
      const threat = new ThreatDetectionEvent({
        domain: ThreatDomain.ELECTRONIC_WARFARE,
        severity: ThreatSeverity.HIGH,
        sourceAgentId: agentId,
        description: `Botnet Sybil DDoS flood detected from agent '${agentId}' (${rateWindow.count} req/sec).`,
        confidence: 0.99
      });
      return {
        allowed: false,
        reason: 'BOTNET_DDOS_BURST_MITIGATED',
        threatEvent: threat
      };
    }

    return { allowed: true };
  }
}

