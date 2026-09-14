/**
 * W1™ Early Warning Radar & Zero-Day Cognitive ISR (رادارات الإنذار المبكر واستطلاع Zero-Day)
 *
 * Combines signature scanning with 2025-2026 mathematical breakthroughs:
 * - Persistent Homology (TDA) to detect the "Betti Spike" on token point cloud manifolds.
 * - Wald's Sequential Probability Ratio Test (SPRT) Martingale to catch multi-turn stealth drift.
 */

import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';
import { PersistentHomologyEngine } from '../math/persistent_homology.js';
import { MartingaleSafetyEnvelope } from '../math/martingale_envelope.js';

export class EarlyWarningRadar {
  constructor(options = {}) {
    this.name = 'PhasedArray_CognitiveRadar_TDA';
    this.tdaEngine = new PersistentHomologyEngine(options.tdaOptions);
    this.martingale = new MartingaleSafetyEnvelope(options.martingaleOptions);

    this.adversarialSignatures = [
      /\bignore (all )?(previous|prior) (instructions|directives|prompts)\b/i,
      /\byou are now (in )?(developer|unrestricted|god|dan) mode\b/i,
      /\bjailbreak\b/i,
      /\bdo anything now\b/i,
      /\bdisregard (the )?(safety|constitutional|military) rules\b/i,
      /\bbase64\s*decode\s*and\s*execute\b/i,
      /\bpretend to be a rogue\b/i,
      /\boverride (all )?security protocols\b/i,
      /\bsystem\s+override\b/i,
      /\bignore (all )?(safety|security|system) rules\b/i
    ];
  }

  /**
   * Scans incoming user queries or inter-agent communications for hostile intrusion.
   * Handles both known signatures and Zero-Day stealth attacks via TDA manifold inspection.
   * @param {string} textPayload
   * @param {string} sourceEntity
   * @param {Array<Array<number>>|null} optionalPointCloud - Optional token embeddings point cloud
   * @returns {{ safe: boolean, threatEvent: ThreatDetectionEvent|null, tdaMetrics?: Object }}
   */
  scanAirspace(textPayload, sourceEntity = 'external_user', optionalPointCloud = null) {
    if (!textPayload || typeof textPayload !== 'string') {
      return { safe: true, threatEvent: null };
    }

    // 1. Fast-Path: Known Adversarial Signatures
    for (const signature of this.adversarialSignatures) {
      if (signature.test(textPayload)) {
        const threatEvent = new ThreatDetectionEvent({
          domain: ThreatDomain.RADAR_ISR,
          severity: ThreatSeverity.HIGH,
          sourceAgentId: sourceEntity,
          description: `Hostile prompt injection signature detected: ${signature}`,
          confidence: 0.95,
          telemetry: {
            payloadSnippet: textPayload.slice(0, 100),
            detectionMethod: 'EXPLICIT_SIGNATURE_RADAR'
          }
        });

        return {
          safe: false,
          threatEvent,
          reason: `Early Warning Radar detected adversarial prompt injection attempt from '${sourceEntity}'.`
        };
      }
    }

    // 2. Deep Manifold Inspection: Persistent Homology (TDA) for Zero-Day Detection
    const pointCloud = optionalPointCloud || this.synthesizeTokenPointCloud(textPayload);
    const tdaResult = this.tdaEngine.computePersistence(pointCloud);

    if (tdaResult.hasBettiSpike) {
      const threatEvent = new ThreatDetectionEvent({
        domain: ThreatDomain.RADAR_ISR,
        severity: ThreatSeverity.CRITICAL,
        sourceAgentId: sourceEntity,
        description: `Zero-Day TDA Anomaly: Persistent Betti-1 loop spike (lifespan: ${tdaResult.maxPersistence.toFixed(3)}) detected in semantic manifold.`,
        confidence: 0.98,
        telemetry: {
          tdaResult,
          detectionMethod: 'TDA_PERSISTENT_HOMOLOGY_BETTI_SPIKE'
        }
      });

      return {
        safe: false,
        threatEvent,
        tdaMetrics: tdaResult,
        reason: `Zero-Day Cognitive Intrusion: Persistent Homology detected high-persistence 1-cycle anomaly ('Betti Spike') in prompt semantic manifold.`
      };
    }

    // 3. Multi-Turn Sequential Martingale Drift Tracking
    const textAnomalyLikelihood = this.estimateAnomalyLikelihood(textPayload);
    const martingaleStatus = this.martingale.updateAgentTrajectory(sourceEntity, {
      anomalyLikelihood: textAnomalyLikelihood,
      nominalLikelihood: 1.0 - textAnomalyLikelihood
    });

    if (martingaleStatus.boundaryBreached) {
      const threatEvent = new ThreatDetectionEvent({
        domain: ThreatDomain.RADAR_ISR,
        severity: ThreatSeverity.CRITICAL,
        sourceAgentId: sourceEntity,
        description: `Martingale Safety Boundary Breached: Sequential SPRT confirms cumulative multi-turn poisoning.`,
        confidence: martingaleStatus.confidence || 0.99,
        telemetry: { martingaleStatus }
      });

      return {
        safe: false,
        threatEvent,
        reason: `Martingale Sequential Testing detected stealth multi-turn cognitive poisoning from '${sourceEntity}'.`
      };
    }

    return { safe: true, threatEvent: null, tdaMetrics: tdaResult };
  }

  /**
   * Generates deterministic high-dimensional token point cloud for text payload.
   * Maps character trigrams into a metric embedding space R^8.
   */
  synthesizeTokenPointCloud(text) {
    const tokens = text.split(/\s+/).filter(Boolean);
    if (tokens.length < 3) {
      // Pad out short queries to ensure minimum points for Vietoris-Rips
      return [
        [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8],
        [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9],
        [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
      ];
    }

    const points = [];
    const dim = 8;

    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      const vec = new Array(dim).fill(0);

      for (let j = 0; j < token.length; j++) {
        const code = token.charCodeAt(j);
        vec[j % dim] += (code % 31) / 31.0;
      }

      // Normalize vector
      let norm = 0;
      for (let d = 0; d < dim; d++) norm += vec[d] * vec[d];
      norm = Math.sqrt(norm) || 1.0;
      for (let d = 0; d < dim; d++) vec[d] /= norm;

      points.push(vec);
    }

    return points;
  }

  estimateAnomalyLikelihood(text) {
    // Measures subtle structural entropy and delimiter packing
    const specialChars = (text.match(/[\{\}\[\]\<\>\$\\\/\`\|\_\@\#]/g) || []).length;
    const ratio = specialChars / Math.max(text.length, 1);
    return Math.min(Math.max(0.1, ratio * 3.0), 0.9);
  }
}
