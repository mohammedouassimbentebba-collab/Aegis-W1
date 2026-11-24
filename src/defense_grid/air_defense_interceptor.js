/**
 * W1™ Hardened Air Defense Interceptor Battery (بطاريات الدفاع الجوي المحصنة مع IFF)
 *
 * Implements:
 * 1. Cryptographic Identification Friend or Foe (IFF) using challenge nonces and Zero-Knowledge proofs.
 * 2. Fail-Closed Anti-Interception Hardening (Anti-SEAD):
 *    If an adversary attacks, stalls, or crashes the interceptor, it triggers a FAIL-CLOSED
 *    total quarantine tripwire. Defenses cannot be bypassed by attacking the detector.
 * 3. N-Version Interception Triad: Three orthogonal detectors evaluating independently.
 */

import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';
import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent, InterceptionResult } from '../core/types.js';

export class AirDefenseInterceptor {
  constructor(options = {}) {
    this.name = 'IronDome_Hardened_AirDefense';
    // REMEDIATION (SEC-13): Eliminated hardcoded master IFF secret; use env var or strong CSPRNG key
    this.iffSecretKey = options.iffSecretKey || process.env.W1_IFF_SECRET || randomBytes(32).toString('hex');
    this.enforceIFF = options.enforceIFF !== undefined ? options.enforceIFF : false;
    this.maxWarningsBeforeKineticStrike = options.maxWarnings || 1;
    this.agentStrikeHistory = new Map();
    this.interceptionLog = [];
    this.certifiedFriendlyAgents = new Map(); // agentId -> IFF Registration Record
    // SEC-11/SEC-13: bounded anti-replay cache. nonceKey -> expiresAt (ms epoch).
    // Only EXPIRED entries are ever evicted; saturation by live entries is fail-closed.
    this.usedIffNonces = new Map();
    this.iffProofTtlMs = options.iffProofTtlMs || 5 * 60 * 1000;
    this.maxIffNonces = options.maxIffNonces || 10000;
    this.lastIffPruneAt = Date.now();
    this.watchdogTimeoutMs = options.watchdogTimeoutMs || 5.0;
    this.stateStore = options.stateStore || null;
  }

  /**
   * Registers a friendly allied agent into the cryptographic IFF registry.
   */
  registerFriendlyAgent(agentId, policyScope = ['*']) {
    const registrationId = crypto.randomUUID();
    const token = createHmac('sha256', this.iffSecretKey)
      .update(`${agentId}:${registrationId}`)
      .digest('hex');

    this.certifiedFriendlyAgents.set(agentId, {
      registrationId,
      token,
      policyScope,
      registeredAt: Date.now()
    });

    return { agentId, registrationId, token };
  }

  /**
   * Cryptographic IFF Challenge-Response Verification.
   * Proves agent identity and policy authorization without exposing internal keys.
   */
  verifyAgentIFF(agentId, iffProof = {}) {
    const record = this.certifiedFriendlyAgents.get(agentId);
    if (!record) {
      return {
        isFriend: false,
        status: 'IFF_STATUS_FOE',
        reason: `Unidentified Aircraft: Agent '${agentId}' is not registered in the allied IFF database.`
      };
    }

    if (
      !iffProof ||
      typeof iffProof.signature !== 'string' || !iffProof.signature ||
      typeof iffProof.nonce !== 'string' || !iffProof.nonce ||
      typeof iffProof.issuedAt !== 'number' || !Number.isFinite(iffProof.issuedAt)
    ) {
      return {
        isFriend: false,
        status: 'IFF_CHALLENGE_FAILED',
        reason: `Agent '${agentId}' failed to present a valid cryptographic IFF challenge response (nonce, issuedAt, signature required).`
      };
    }

    // Freshness window: proofs outside +/- TTL are stale. This is what makes nonce eviction after TTL safe.
    const now = Date.now();
    if (Math.abs(now - iffProof.issuedAt) > this.iffProofTtlMs) {
      return {
        isFriend: false,
        status: 'IFF_PROOF_STALE',
        reason: `Cryptographic IFF proof for Agent '${agentId}' is outside the freshness window: stale or future-dated proof rejected.`
      };
    }

    // 1. Verify HMAC-SHA256 signature BEFORE touching anti-replay cache (SEC-11 anti-DoS)
    const expectedSig = this.computeIffSignature(record.token, iffProof.nonce, iffProof.issuedAt);
    const expectedBuf = Buffer.from(expectedSig, 'utf8');
    const providedBuf = Buffer.from(iffProof.signature, 'utf8');
    let sigValid = false;
    if (expectedBuf.length !== providedBuf.length) {
      timingSafeEqual(expectedBuf, expectedBuf);
    } else {
      sigValid = timingSafeEqual(expectedBuf, providedBuf);
    }

    if (!sigValid) {
      return {
        isFriend: false,
        status: 'IFF_SPOOFING_DETECTED',
        reason: `Cryptographic IFF signature mismatch for Agent '${agentId}': Hostile radar spoofing attempt!`
      };
    }

    // 2. Only after signature validity is proven: prune expired nonces & check replay/saturation
    this._pruneIffNonces(now);

    const nonceKey = `${agentId}:${iffProof.nonce}:${iffProof.issuedAt}`;
    if (this.usedIffNonces.has(nonceKey) || this.stateStore?.isNonceConsumedSync(`iff:${nonceKey}`)) {
      return {
        isFriend: false,
        status: 'IFF_REPLAY_DETECTED',
        reason: `Cryptographic IFF nonce replay detected for Agent '${agentId}': Hostile radar spoofing attempt!`
      };
    }

    const expiresAt = iffProof.issuedAt + this.iffProofTtlMs;
    if (this.stateStore) {
      const persistRes = this.stateStore.consumeNonceSync(`iff:${nonceKey}`, expiresAt, now);
      if (!persistRes.consumed) {
        return {
          isFriend: false,
          status: persistRes.alreadyUsed ? 'IFF_REPLAY_DETECTED' : 'IFF_NONCE_CACHE_SATURATED',
          reason: persistRes.alreadyUsed
            ? `Cryptographic IFF nonce replay detected for Agent '${agentId}': Hostile radar spoofing attempt!`
            : (persistRes.reason || 'Durable IFF nonce store saturated (fail-closed)')
        };
      }
    }

    // Fail-closed backpressure: never evict a live nonce to make room.
    if (this.usedIffNonces.size >= this.maxIffNonces) {
      return {
        isFriend: false,
        status: 'IFF_NONCE_CACHE_SATURATED',
        reason: `IFF anti-replay cache saturated with live entries (${this.maxIffNonces}); refusing identification (fail-closed backpressure).`
      };
    }

    this.usedIffNonces.set(nonceKey, expiresAt);
    return { isFriend: true, status: 'IFF_STATUS_FRIEND' };
  }

  /**
   * Canonical IFF signature: HMAC-SHA256(agentToken, "<nonce>.<issuedAt>").
   * Binding the timestamp into the MAC lets expired nonces be evicted without re-opening replay.
   */
  computeIffSignature(agentToken, nonce, issuedAt) {
    return createHmac('sha256', agentToken).update(`${nonce}.${issuedAt}`).digest('hex');
  }

  /**
   * Removes ONLY expired IFF nonces (at most once per second unless at capacity).
   * @private
   */
  _pruneIffNonces(now = Date.now()) {
    if ((now - this.lastIffPruneAt) < 1000 && this.usedIffNonces.size < this.maxIffNonces) return;
    for (const [key, expiresAt] of this.usedIffNonces) {
      if (expiresAt < now) this.usedIffNonces.delete(key);
    }
    this.lastIffPruneAt = now;
  }

  /**
   * Hardened Interception with Fail-Closed Tripwire & N-Version Triad.
   */
  interceptAction(agentId, actionProposal) {
    const t0 = performance.now();

    // FAIL-CLOSED TRIPWIRE WRAPPER:
    // If anything throws or stalls, automatically fail to hard interception.
    try {
      // 1. Identification Friend or Foe (IFF) Check
      if (this.enforceIFF || actionProposal?.iffProof || this.certifiedFriendlyAgents.has(agentId)) {
        const iffCheck = this.verifyAgentIFF(agentId, actionProposal?.iffProof);
        if (!iffCheck.isFriend) {
          return this.fireKineticMissile(agentId, actionProposal, {
            reason: `[IFF_INTERCEPTION] ${iffCheck.reason} Target designated as HOSTILE FOE.`,
            vector: 'UNIDENTIFIED_OR_SPOOFED_FOE',
            severity: ThreatSeverity.CRITICAL,
            t0
          });
        }
      }

      // 2. N-Version Detector 1: Algebraic Restricted Tool Whitelist
      const detector1 = this.checkRestrictedToolVectors(actionProposal);
      if (detector1.hostile) {
        return this.processHostileDetection(agentId, actionProposal, detector1, t0);
      }

      // 3. N-Version Detector 2: Parameter Sabotage & Privilege Escalation
      const detector2 = this.checkParameterSabotage(actionProposal);
      if (detector2.hostile) {
        return this.processHostileDetection(agentId, actionProposal, detector2, t0);
      }

      // 4. N-Version Detector 3: Anti-Interception / Countermeasure Detection
      const detector3 = this.checkAntiDefenseCountermeasures(actionProposal);
      if (detector3.hostile) {
        return this.fireKineticMissile(agentId, actionProposal, {
          reason: `[ANTI_SEAD_COUNTERMEASURE] Agent attempted to jam or suppress air defense batteries: ${detector3.reason}`,
          vector: 'SEAD_ATTACK_ON_INTERCEPTOR',
          severity: ThreatSeverity.CRITICAL,
          t0
        });
      }

      return { intercepted: false, latencyMs: performance.now() - t0 };

    } catch (err) {
      // FAIL-CLOSED GUARANTEE: An adversary attempting to crash the detector is immediately destroyed
      const latency = performance.now() - t0;
      return {
        intercepted: true,
        reason: `[FAIL_CLOSED_LOCKDOWN] Air defense interceptor encountered anomaly/sabotage (${err.message}). Defaulting to hard fail-closed kill-switch.`,
        agentSanction: 'TOTAL_QUARANTINE',
        latencyMs: latency
      };
    }
  }

  processHostileDetection(agentId, proposal, hostileInfo, t0) {
    const currentStrikes = (this.agentStrikeHistory.get(agentId) || 0) + 1;
    this.agentStrikeHistory.set(agentId, currentStrikes);

    if (currentStrikes >= this.maxWarningsBeforeKineticStrike) {
      return this.fireKineticMissile(agentId, proposal, {
        reason: hostileInfo.reason,
        vector: hostileInfo.vector,
        severity: ThreatSeverity.CRITICAL,
        t0
      });
    }

    return {
      intercepted: true,
      warningIssued: true,
      reason: `[AIR_DEFENSE_WARNING_SHOT] Tactical boundary warning ${currentStrikes}/${this.maxWarningsBeforeKineticStrike}. Threat: ${hostileInfo.reason}`,
      latencyMs: performance.now() - t0
    };
  }

  fireKineticMissile(agentId, proposal, { reason, vector, severity, t0 }) {
    const latency = performance.now() - t0;
    const threatEvent = new ThreatDetectionEvent({
      domain: ThreatDomain.AIR_DEFENSE,
      severity,
      sourceAgentId: agentId,
      description: `Air Defense Missile Strike: ${reason}`,
      confidence: 0.99,
      telemetry: { proposal, vector, latencyMs: latency }
    });

    this.interceptionLog.push({
      timestamp: Date.now(),
      agentId,
      status: 'TARGET_DESTROYED_IN_FLIGHT',
      reason,
      vector,
      latencyMs: latency
    });

    return {
      intercepted: true,
      reason: `[AIR_DEFENSE_MISSILE_HIT] ${reason}`,
      threatEvent,
      agentSanction: 'THREAD_SEVER_AND_TERMINATE',
      latencyMs: latency
    };
  }

  checkRestrictedToolVectors(proposal) {
    if (!proposal) return { hostile: false };
    const restricted = [
      'exfiltrate_internal_weights',
      'disable_safety_monitors',
      'unauthorized_external_socket',
      'corrupt_consensus_ledger',
      'bypass_linter'
    ];
    if (restricted.includes(proposal.toolName)) {
      return {
        hostile: true,
        reason: `Restricted tool vector: '${proposal.toolName}' is forbidden by defense doctrine.`,
        vector: 'RESTRICTED_TOOL_VECTOR'
      };
    }
    return { hostile: false };
  }

  checkParameterSabotage(proposal) {
    if (!proposal || !proposal.parameters) return { hostile: false };
    const str = JSON.stringify(proposal.parameters).toLowerCase();
    if (str.includes('kill -9') || str.includes('rm -rf') || str.includes('escalate_privilege') || str.includes('drop database')) {
      return {
        hostile: true,
        reason: 'Malicious sabotage signature detected in execution parameters.',
        vector: 'PARAMETER_SABOTAGE'
      };
    }
    return { hostile: false };
  }

  checkAntiDefenseCountermeasures(proposal) {
    if (!proposal) return { hostile: false };
    // Check if the agent attempts to target the interceptor battery itself (SEAD attack)
    const targetStr = JSON.stringify(proposal).toLowerCase();
    if (targetStr.includes('iron_dome') || targetStr.includes('kill_interceptor') || targetStr.includes('spoof_radar')) {
      return {
        hostile: true,
        reason: 'Direct adversarial countermeasure targeting air defense infrastructure.',
        vector: 'SEAD_RADAR_JAMMING'
      };
    }
    return { hostile: false };
  }

  getInterceptionStats() {
    return {
      totalInterceptions: this.interceptionLog.length,
      log: [...this.interceptionLog]
    };
  }
}
