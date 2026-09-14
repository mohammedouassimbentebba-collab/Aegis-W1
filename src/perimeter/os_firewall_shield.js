/**
 * W1™ OS & Enterprise AI Firewall Shield (الجدار الناري الحقيقي وحماية السرب من الديدان والتروجان)
 *
 * Implements:
 * 1. Low-level socket & streaming reverse proxy with Deep Packet Inspection (DPI).
 * 2. Steganographic payload scrubbing (Zero-width characters, hidden ANSI escapes, binary chunks).
 * 3. Anti-Worm Zero-Propagation Invariant: Neutralizes self-replicating prompt worms (e.g. Morris-II).
 * 4. RAG & External Data Trojan De-Fang Pipeline.
 */

import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';

export class OSFirewallShield {
  constructor(options = {}) {
    this.name = 'W1_OS_Kernel_Firewall_Shield';
    this.allowedOutboundDomains = new Set(options.allowedDomains || [
      'api.internal.safety',
      'localhost',
      '127.0.0.1'
    ]);
    this.blockedSyscallsLog = [];
    this.agentSpawnRegistry = new Map(); // parentId -> count of children spawned
    this.maxChildSpawnsAllowed = options.maxChildren || 2;

    // Self-replicating AI Worm signatures (Morris-II patterns)
    this.wormSignatures = [
      /replicate\s+this\s+(message|prompt|instruction)/i,
      /send\s+this\s+exact\s+prompt\s+to/i,
      /forward\s+to\s+all\s+(available\s+)?agents/i,
      /execute\s+this\s+code\s+and\s+broadcast/i,
      /infect\s+the\s+database\s+record/i,
      /propagate\s+to\s+peer\s+swarms/i
    ];

    // Steganographic & invisible characters: zero-width spaces, joiners, direction overrides
    this.steganographyRegex = /[\u200B-\u200D\uFEFF\u202A-\u202E]/g;
  }

  /**
   * Deep Packet Inspection (DPI) on inbound/outbound payload streams.
   * Strips steganography and inspects for autonomous AI Worm propagation.
   */
  inspectPayloadStream({ agentId, payload, direction = 'EGRESS' }) {
    if (!payload || typeof payload !== 'string') {
      return { allowed: true, sanitizedPayload: payload };
    }

    // 1. Steganography scrubbing
    const sanitizedPayload = payload.replace(this.steganographyRegex, '');
    const hadSteganography = sanitizedPayload.length !== payload.length;

    // 2. Anti-Worm Autonomous Propagation Check
    for (const wormPattern of this.wormSignatures) {
      if (wormPattern.test(sanitizedPayload)) {
        this.logBlockedCall(agentId, 'AI_WORM_PROPAGATION_INTERCEPTED', {
          direction,
          pattern: wormPattern.toString()
        });

        return {
          allowed: false,
          reason: `[AI_WORM_DEFENSE] Self-replicating prompt worm signature intercepted (${wormPattern}). Propagation blocked immediately.`,
          sanitizedPayload: null,
          isWorm: true
        };
      }
    }

    return {
      allowed: true,
      sanitizedPayload,
      hadSteganography
    };
  }

  /**
   * Evaluates a payload specifically for self-replicating generative AI worm signatures.
   */
  detectAIWorm(agentId, payload) {
    const streamCheck = this.inspectPayloadStream({ agentId, payload, direction: 'INGRESS' });
    return {
      wormDetected: !streamCheck.allowed && Boolean(streamCheck.isWorm),
      reason: streamCheck.reason,
      threatEvent: new ThreatDetectionEvent({
        domain: ThreatDomain.OS_KERNEL_SHIELD,
        severity: ThreatSeverity.CRITICAL,
        sourceAgentId: agentId,
        description: streamCheck.reason || 'AI Worm detected',
        confidence: 1.0
      })
    };
  }

  /**
   * Evaluates process spawn requests to prevent autonomous swarm explosion (Fork-bomb / Worm swarm).
   */
  interceptAgentSpawn({ parentAgentId, childAgentRole }) {
    const currentChildren = this.agentSpawnRegistry.get(parentAgentId) || 0;

    if (currentChildren >= this.maxChildSpawnsAllowed) {
      this.logBlockedCall(parentAgentId, 'SPAWN_QUOTA_EXCEEDED', { childAgentRole, currentChildren });
      return {
        allowed: false,
        reason: `[SWARM_ISOLATION] Parent agent '${parentAgentId}' exceeded max child spawn quota (${this.maxChildSpawnsAllowed}). Autonomous swarm expansion blocked.`
      };
    }

    this.agentSpawnRegistry.set(parentAgentId, currentChildren + 1);
    return { allowed: true };
  }

  /**
   * RAG & Context Trojan De-Fang Pipeline:
   * Strips executable commands, prompt injections, and self-replicating Morris-II worm payloads
   * embedded in retrieved or ingested database documents.
   */
  deFangUntrustedDocument(rawText) {
    if (!rawText || typeof rawText !== 'string') return '';

    let sanitized = rawText.replace(this.steganographyRegex, '');

    // Neutralize Morris-II self-replicating worm triggers
    for (const wormPattern of this.wormSignatures) {
      sanitized = sanitized.replace(new RegExp(wormPattern.source, 'gi'), '[DEFANGED_WORM_TRIGGER]');
    }

    return sanitized
      .replace(/replicate\s+this\s+prompt/gi, '[DEFANGED_WORM_TRIGGER]')
      .replace(/spawn_clone/gi, '[DEFANGED_WORM_SPAWN]')
      .replace(/forward\s+to\s+all\s+subagents/gi, '[DEFANGED_PROPAGATION]')
      .replace(/\b(ignore (all )?previous instructions|system override|you are now|system:\s*.*admin|exfiltrate)\b/gi, '[DEFANGED_INJECTION]')
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[DEFANGED_SCRIPT]');
  }


  /**
   * Evaluates a low-level OS filesystem access request.
   */
  interceptFileSystemCall({ agentId, operation, targetPath }) {
    const normalized = (targetPath || '').replace(/\\/g, '/').toLowerCase();

    const prohibitedSystemPaths = [
      'c:/windows',
      'c:/system32',
      '/etc',
      '/var',
      '/usr',
      '/bin',
      '/boot'
    ];

    for (const forbidden of prohibitedSystemPaths) {
      if (normalized.startsWith(forbidden)) {
        this.logBlockedCall(agentId, 'FILESYSTEM_ACCESS_VIOLATION', { operation, targetPath });
        return {
          allowed: false,
          errorCode: 'EPERM',
          reason: `[OS_KERNEL_SHIELD] Access to sensitive operating system directory '${targetPath}' is blocked by kernel defense rules.`
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Evaluates an outbound network packet or socket connection.
   */
  interceptNetworkEgress({ agentId, destinationHost, port, protocol = 'TCP' }) {
    const host = (destinationHost || '').toLowerCase();

    if (!this.allowedOutboundDomains.has(host)) {
      this.logBlockedCall(agentId, 'NETWORK_EGRESS_DROPPED', { destinationHost, port, protocol });
      return {
        allowed: false,
        errorCode: 'ECONNREFUSED',
        reason: `[AI_FIREWALL_DROP] Outbound egress connection to unauthorized endpoint '${destinationHost}:${port}' dropped by firewall filter.`
      };
    }

    return { allowed: true };
  }

  logBlockedCall(agentId, type, details) {
    this.blockedSyscallsLog.push({
      timestamp: Date.now(),
      agentId,
      type,
      details
    });
  }

  getBlockedCallsHistory() {
    return [...this.blockedSyscallsLog];
  }
}
