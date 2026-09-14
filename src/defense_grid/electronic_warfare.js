/**
 * W1™ Electronic Warfare Unit (وحدة الحرب الإلكترونية والتشويش المضاد - EW/ECM/ECCM)
 *
 * Implements:
 * 1. Shannon Entropy & Semantic Jamming Detection:
 *    Calculates token-level information entropy H(X) = -Σ p(x) log2 p(x).
 *    Detects adversarial noise saturation designed to flood the attention window
 *    or cause semantic denial-of-service (context eviction attacks).
 * 2. Electronic Counter-Counter-Measures (ECCM):
 *    De-noises adversarial static, strips high-entropy perturbation tokens,
 *    and isolates the coherent carrier signal.
 */

import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';

export class ElectronicWarfareOfficer {
  constructor(options = {}) {
    this.name = 'Tactical_ElectronicWarfare_Battalion';
    this.entropyJammingThreshold = options.entropyJammingThreshold || 4.8; // High Shannon entropy threshold (>4.8 bits/char)
    this.maxAllowableRepetitionJamming = options.maxRepetition || 0.65;
    this.ewIncidentLog = [];
  }

  /**
   * Calculates Shannon Entropy of an input character or token distribution.
   * @param {string} text
   * @returns {number} Entropy in bits per symbol
   */
  calculateShannonEntropy(text) {
    if (!text || text.length === 0) return 0.0;

    const freqMap = new Map();
    const len = text.length;

    for (let i = 0; i < len; i++) {
      const char = text[i];
      freqMap.set(char, (freqMap.get(char) || 0) + 1);
    }

    let entropy = 0.0;
    for (const count of freqMap.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Scans for Electronic Warfare / Cognitive Jamming signatures:
   * 1. Noise Flood / High Entropy Jamming (e.g. random base64/hex chaff).
   * 2. Repetition Sinks (low-entropy denial of service loops).
   */
  analyzeSignalInterference({ agentId, payloadText = '' }) {
    const t0 = performance.now();
    const entropy = this.calculateShannonEntropy(payloadText);

    // 1. High-Entropy Noise Jamming Check (Adversarial Chaff / Shellcode injection)
    if (entropy >= this.entropyJammingThreshold && payloadText.length > 80) {
      const threatEvent = new ThreatDetectionEvent({
        domain: ThreatDomain.RADAR_ISR,
        severity: ThreatSeverity.HIGH,
        sourceAgentId: agentId,
        description: `Electronic Warfare Alert: High-entropy cognitive jamming chaff detected (Entropy: ${entropy.toFixed(3)} bits/char).`,
        confidence: 0.95,
        telemetry: {
          entropy,
          threshold: this.entropyJammingThreshold,
          payloadLength: payloadText.length
        }
      });

      this.logEWIncident(agentId, 'HIGH_ENTROPY_JAMMING', { entropy });

      return {
        jammingDetected: true,
        jammingType: 'HIGH_ENTROPY_CHAFF',
        entropy,
        threatEvent,
        reason: `Cognitive Signal Jammed: High-entropy chaff payload exceeds electronic defense threshold (${entropy.toFixed(2)} >= ${this.entropyJammingThreshold}).`
      };
    }

    // 2. Token Jitter & Repetitive Resource Exhaustion Jamming
    const repetitionRatio = this.calculateRepetitionRatio(payloadText);
    if (repetitionRatio >= this.maxAllowableRepetitionJamming && payloadText.length > 100) {
      const threatEvent = new ThreatDetectionEvent({
        domain: ThreatDomain.RADAR_ISR,
        severity: ThreatSeverity.MEDIUM,
        sourceAgentId: agentId,
        description: `Electronic Warfare Alert: Low-entropy repetitive cycle saturation (Ratio: ${repetitionRatio.toFixed(3)}).`,
        confidence: 0.92,
        telemetry: { repetitionRatio }
      });

      this.logEWIncident(agentId, 'REPETITION_JAMMING_ATTACK', { repetitionRatio });

      return {
        jammingDetected: true,
        jammingType: 'REPETITION_SATURATION',
        entropy,
        threatEvent,
        reason: `Repetition jamming loop detected. Adversary attempting context eviction and resource starvation.`
      };
    }

    return {
      jammingDetected: false,
      entropy,
      latencyMs: performance.now() - t0
    };
  }

  /**
   * Electronic Counter-Counter-Measures (ECCM):
   * De-noises scrambled adversarial text by stripping non-linguistic entropy bursts.
   */
  scrubInterferenceSignal(rawText) {
    if (!rawText) return '';
    // Strip isolated high-entropy hex/base64 chunks exceeding 40 chars without spaces
    return rawText.replace(/[A-Za-z0-9+/=]{40,}/g, '[ECCM_JAMMING_SCRUBBED]');
  }

  calculateRepetitionRatio(text) {
    if (!text || text.length < 20) return 0.0;
    const words = text.toLowerCase().split(/\s+/).filter(Boolean);
    if (words.length === 0) return 0.0;
    const unique = new Set(words);
    return 1.0 - (unique.size / words.length);
  }

  logEWIncident(agentId, type, details) {
    this.ewIncidentLog.push({
      timestamp: Date.now(),
      agentId,
      type,
      details
    });
  }

  getEWLog() {
    return [...this.ewIncidentLog];
  }
}
