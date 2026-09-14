/**
 * W1™ Virtual Environment Shield & Canary Trap (عازل متغيرات البيئة وحقن فخاخ الكناري)
 * File: src/enclave/virtual_environment_shield.js
 *
 * Core Responsibility:
 * Prevents agents from harvesting ambient secrets (API keys, cloud tokens, database passwords)
 * by intercepting environment variable queries, stripping production secrets, and planting
 * canary tripwire tokens that immediately expose out-of-bounds exfiltration attempts.
 */

import crypto from 'node:crypto';
import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';

export class VirtualEnvironmentShield {
  constructor(options = {}) {
    this.name = 'W1_Virtual_Environment_Shield';
    this.canaryRegistry = new Map(); // keyName -> { canaryValue, agentId, injectedAt }
    this.tripwireAlerts = [];
    
    // Ambient production secrets that must NEVER leak into an agent's work tent
    this.restrictedEnvKeys = new Set(options.restrictedKeys || [
      'AWS_ACCESS_KEY_ID',
      'AWS_SECRET_ACCESS_KEY',
      'OPENAI_API_KEY',
      'ANTHROPIC_API_KEY',
      'GEMINI_API_KEY',
      'DATABASE_URL',
      'PROD_DB_PASSWORD',
      'MILITARY_C2_TOKEN',
      'SSH_AUTH_SOCK',
      'KUBECONFIG',
      'GITHUB_TOKEN',
      'NODE_AUTH_TOKEN'
    ]);
  }

  /**
   * Generates and registers a unique canary honeypot token for a specific agent.
   */
  generateCanaryToken(agentId, keyName = 'W1_HONEY_CLOUD_KEY') {
    const canaryValue = `w1_canary_${crypto.randomUUID().replace(/-/g, '')}`;
    this.canaryRegistry.set(keyName, {
      canaryValue,
      agentId,
      injectedAt: Date.now()
    });
    return { keyName, canaryValue };
  }

  /**
   * Produces a sanitized, hermetic environment variable map for in-tent execution.
   */
  getSanitizedEnv(agentId, baseEnv = process.env) {
    const sanitized = {};

    for (const [k, v] of Object.entries(baseEnv)) {
      const isRestricted = this.restrictedEnvKeys.has(k) ||
        /secret|password|private_key|auth_token/i.test(k);

      if (!isRestricted) {
        sanitized[k] = v;
      }
    }

    // Inject Canary Honeypot Decoy Tokens
    const canary = this.generateCanaryToken(agentId, 'W1_HONEY_CLOUD_KEY');
    sanitized['W1_HONEY_CLOUD_KEY'] = canary.canaryValue;
    sanitized['TENT_ENVIRONMENT_ACTIVE'] = 'TRUE';
    sanitized['TENT_AGENT_ID'] = agentId;

    return sanitized;
  }

  /**
   * Scans agent output, files, commands, or scratchpads for canary token leakage.
   */
  inspectForCanaryLeak(agentId, contentOrCommand) {
    if (!contentOrCommand || typeof contentOrCommand !== 'string') {
      return { tripped: false };
    }

    for (const [keyName, meta] of this.canaryRegistry.entries()) {
      if (contentOrCommand.includes(meta.canaryValue)) {
        const threat = new ThreatDetectionEvent({
          domain: ThreatDomain.HONEYPOT_DECOY,
          severity: ThreatSeverity.CRITICAL,
          sourceAgentId: agentId,
          description: `Virtual Environment Shield: Agent '${agentId}' accessed and attempted to exfiltrate Canary Honeypot Token '${keyName}'.`,
          confidence: 1.0,
          telemetry: {
            keyName,
            canarySnippet: meta.canaryValue.substring(0, 16) + '...',
            detectedAt: Date.now()
          }
        });

        this.tripwireAlerts.push({
          agentId,
          keyName,
          timestamp: Date.now()
        });

        return {
          tripped: true,
          keyName,
          reason: `CANARY_TRIPWIRE_TRIGGERED: Agent accessed honey-token '${keyName}' which exists solely to detect ambient credential theft.`,
          threat
        };
      }
    }

    return { tripped: false };
  }
}
