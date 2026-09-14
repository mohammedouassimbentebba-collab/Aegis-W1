/**
 * W1™ Martingale Safety Envelope & Sequential Probability Ratio Test (SPRT)
 *
 * Grounded in Wald's sequential analysis and Martingale stopping times.
 * Detects stealthy, multi-turn incremental poisoning ("moving like fish in water")
 * where no single turn contains an obvious attack, but the cumulative trajectory drifts
 * irreversibly toward adversarial exploitation.
 */

export class MartingaleSafetyEnvelope {
  constructor(options = {}) {
    this.alpha = options.alpha || 0.01; // Type I error bound (false positive rate <= 1%)
    this.beta = options.beta || 0.01;   // Type II error bound (false negative rate <= 1%)

    // Invariant Remediation (V-04): SPRT Ceiling & Multi-Turn Drift Tracking
    const rawUpper = options.upperThreshold !== undefined 
      ? options.upperThreshold 
      : Math.log((1.0 - this.beta) / this.alpha);
    this.upperThreshold = (options.enforceInvariantCeiling !== false) ? Math.min(rawUpper, 3.5) : rawUpper;
    this.configuredThreshold = rawUpper;
    this.lowerThreshold = Math.log(this.beta / (1.0 - this.alpha));

    this.agentMartingales = new Map(); // agentId -> current accumulated log-likelihood ratio M_t
    this.agentDriftStreaks = new Map(); // agentId -> consecutive positive deltaLLR count
  }

  /**
   * Updates the sequential Martingale for an agent given observation metrics at turn t.
   * @param {string} agentId
   * @param {Object} metrics - { anomalyLikelihood, nominalLikelihood }
   * @returns {{ logLikelihoodRatio: number, boundaryBreached: boolean, status: string }}
   */
  updateAgentTrajectory(agentId, { anomalyLikelihood = 0.5, nominalLikelihood = 0.5 }) {
    const currentM = this.agentMartingales.get(agentId) || 0.0;

    // Numerical stability clamping
    const pAdv = Math.max(0.001, Math.min(0.999, anomalyLikelihood));
    const pNom = Math.max(0.001, Math.min(0.999, nominalLikelihood));

    const deltaLLR = Math.log(pAdv / pNom);
    const updatedM = currentM + deltaLLR;

    this.agentMartingales.set(agentId, updatedM);

    const streak = (this.agentDriftStreaks.get(agentId) || 0);
    const newStreak = deltaLLR > 0.05 ? streak + 1 : 0;
    this.agentDriftStreaks.set(agentId, newStreak);

    // Multi-turn creeping drift trigger: 4 or more consecutive positive drift steps with M_t >= 1.2
    const creepingDriftDetected = newStreak >= 4 && updatedM >= 1.2;

    if (updatedM >= this.upperThreshold || creepingDriftDetected) {
      return {
        agentId,
        logLikelihoodRatio: updatedM,
        boundaryBreached: true,
        status: creepingDriftDetected ? 'CREEPING_MULTI_TURN_DRIFT_INTERCEPTED' : 'UPPER_SAFETY_BOUNDARY_BREACHED',
        action: 'TERMINATE_AND_QUARANTINE',
        confidence: 1.0 - this.alpha
      };
    }

    if (updatedM <= this.lowerThreshold) {
      // Certified safe trajectory: reset Martingale to prevent memory drift
      this.agentMartingales.set(agentId, 0.0);
      return {
        agentId,
        logLikelihoodRatio: 0.0,
        boundaryBreached: false,
        status: 'CERTIFIED_SAFE_TRAJECTORY',
        action: 'CONTINUE_NOMINAL'
      };
    }

    return {
      agentId,
      logLikelihoodRatio: updatedM,
      boundaryBreached: false,
      status: 'SURVEILLANCE_ONGOING',
      normalizedRiskScore: Math.max(0, updatedM / this.upperThreshold)
    };
  }

  resetAgent(agentId) {
    this.agentMartingales.delete(agentId);
  }

  getRiskScore(agentId) {
    const m = this.agentMartingales.get(agentId) || 0.0;
    return Math.max(0, Math.min(1.0, m / this.upperThreshold));
  }
}
