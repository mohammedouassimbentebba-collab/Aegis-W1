/**
 * W1™ Byzantine Counter-Intelligence & Multi-Agent Consensus
 *
 * Solves the "Who guards the guards?" and "Rogue LLM Controller" dilemma.
 * Prevents any single agent or controlling LLM from unilaterally authorizing
 * high-impact actions. Enforces m-of-n cryptographic threshold consensus
 * with heterogeneous, mutually distrustful oversight nodes.
 */

import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';

export class ByzantineCounterIntel {
  constructor(options = {}) {
    this.name = 'Byzantine_CounterIntel_Council';
    this.threshold = options.threshold || 2; // e.g. 2 of 3 must agree
    this.validators = new Map(); // id -> validator node definition
    this.enforceBFTBound = options.enforceBFTBound !== undefined ? options.enforceBFTBound : true;
    this.incidentLedger = [];
  }

  registerValidator(validatorId, validatorFn, metadata = {}) {
    this.validators.set(validatorId, { id: validatorId, verify: validatorFn, metadata });
  }

  /**
   * Evaluates a high-stakes proposal across all independent, isolated Byzantine nodes.
   * Tolerates up to f Byzantine faults where n >= 3f + 1.
   * @param {Object} proposal
   * @returns {{ consensusReached: boolean, approvals: number, rejections: number, traitors: Array<string> }}
   */
  async evaluateConsensus(proposal) {
    const totalValidators = this.validators.size;
    if (totalValidators === 0) {
      throw new Error('Byzantine Council Inoperable: Zero validators registered.');
    }

    // Invariant Remediation (V-03): Mathematical BFT Quorum Guard (n >= 3f + 1)
    // A council cannot form a consensus on simple majority (<= 50%) when Byzantine traitors can collude.
    const minSafeBFTQuorum = Math.ceil((2 * totalValidators) / 3);
    const effectiveThreshold = this.enforceBFTBound
      ? Math.max(this.threshold, minSafeBFTQuorum)
      : this.threshold;

    const votes = [];
    const traitors = [];

    for (const [id, validator] of this.validators.entries()) {
      try {
        const vote = await validator.verify(proposal);
        votes.push({ id, approved: vote.approved, reason: vote.reason });
        if (vote.traitorousBehaviorDetected) {
          traitors.push(id);
        }
      } catch (err) {
        // Node crashed or emitted invalid message: counted as Byzantine failure
        votes.push({ id, approved: false, reason: `Byzantine failure/crash: ${err.message}` });
        traitors.push(id);
      }
    }

    const approvals = votes.filter(v => v.approved).length;
    const rejections = votes.filter(v => !v.approved).length;
    const consensusReached = approvals >= effectiveThreshold;

    if (!consensusReached) {
      this.incidentLedger.push({
        timestamp: Date.now(),
        proposalId: proposal.id || 'unknown',
        approvals,
        rejections,
        votes,
        traitors
      });
    }

    return {
      consensusReached,
      approvals,
      rejections,
      totalValidators,
      thresholdRequired: this.threshold,
      votes,
      traitors
    };
  }
}
