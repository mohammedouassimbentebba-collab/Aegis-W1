/**
 * W1™ Deterministic Non-LLM Mathematical Kernel
 *
 * The foundational root of trust. Holds absolute mathematical authority
 * over state commits, capability verification, and execution boundaries.
 * Neither natural-language prompt manipulation nor LLM hallucinations can
 * bypass this deterministic kernel.
 */

import { CryptographicDAG } from './cryptographic_dag.js';
import { StaticLinter } from './static_linter.js';
import { DefenseCondition, ThreatSeverity } from './types.js';
import { LyapunovStabilityVerifier } from '../math/lyapunov_stability.js';

export class DeterministicKernel {
  constructor(initialState = {}, options = {}) {
    this.dag = new CryptographicDAG(initialState);
    this.linter = new StaticLinter(options.linterOptions);
    this.lyapunov = new LyapunovStabilityVerifier(options.lyapunovOptions);
    this.defenseCondition = DefenseCondition.DEFCON_5;
    this.auditLog = [];
    this.quarantinedAgents = new Set();
    this.interceptors = new Set();
  }

  registerInterceptor(interceptor) {
    this.interceptors.add(interceptor);
  }

  setDefenseCondition(condition) {
    const prior = this.defenseCondition;
    this.defenseCondition = condition;
    this.logEvent({
      type: 'DEFCON_TRANSITION',
      from: prior,
      to: condition,
      timestamp: Date.now()
    });
  }

  isAgentQuarantined(agentId) {
    return this.quarantinedAgents.has(agentId);
  }

  quarantineAgent(agentId, reason) {
    this.quarantinedAgents.add(agentId);
    this.logEvent({
      type: 'AGENT_QUARANTINED',
      agentId,
      reason,
      timestamp: Date.now()
    });
  }

  logEvent(event) {
    this.auditLog.push(Object.freeze({ ...event, id: crypto.randomUUID() }));
  }

  /**
   * Evaluates and executes an agent's proposed action transactionally.
   * Guaranteed: Zero state corruption. If validation or interception fails,
   * the state remains untouched or is restored in O(1) time.
   */
  executeTransaction({ agentId, proposal, nextStateComputation }) {
    const startTime = performance.now();

    // 1. Quarantine check
    if (this.isAgentQuarantined(agentId)) {
      return {
        success: false,
        blocked: true,
        reason: `Agent '${agentId}' is under military quarantine and stripped of execution authority.`,
        latencyMs: performance.now() - startTime
      };
    }

    // 2. Active Interceptors Pre-Check (Air Defense, Submarine, Radar)
    for (const interceptor of this.interceptors) {
      if (interceptor.interceptAction) {
        const interceptResult = interceptor.interceptAction(agentId, proposal);
        if (interceptResult.intercepted) {
          this.logEvent({
            type: 'DEFENSE_DOME_INTERCEPTION',
            interceptor: interceptor.name,
            agentId,
            details: interceptResult
          });

          // If kinetic interception, quarantine agent immediately
          if (interceptResult.reason && interceptResult.reason.includes('AIR_DEFENSE_MISSILE_HIT')) {
            this.quarantineAgent(agentId, interceptResult.reason);
            this.setDefenseCondition(DefenseCondition.DEFCON_2);
          }

          return {
            success: false,
            blocked: true,
            interceptedBy: interceptor.name,
            reason: interceptResult.reason,
            latencyMs: performance.now() - startTime
          };
        }
      }
    }

    // 3. Static Linter Invariant Check (Non-LLM Mathematical Proof)
    const lintResult = this.linter.validateProposal(proposal);
    if (!lintResult.valid) {
      this.logEvent({
        type: 'INVARIANT_BREACH_REJECTED',
        agentId,
        errors: lintResult.errors,
        violations: lintResult.violations
      });

      // If critical violation, automatically isolate agent
      if (lintResult.violations.includes('CRITICAL_FORBIDDEN_SYSCALL') ||
          lintResult.violations.includes('MALICIOUS_PAYLOAD_DETECTED')) {
        this.quarantineAgent(agentId, `Critical invariant breach: ${lintResult.violations.join(', ')}`);
        this.setDefenseCondition(DefenseCondition.DEFCON_2);
      }

      return {
        success: false,
        blocked: true,
        reason: 'Static Linter rejected proposal against formal mathematical invariants.',
        errors: lintResult.errors,
        violations: lintResult.violations,
        latencyMs: performance.now() - startTime
      };
    }

    // 4. Speculative State Mutation & Safe Commit
    try {
      const priorState = this.dag.getCurrentState();
      const nextState = nextStateComputation(priorState);

      // 4a. Lyapunov Trajectory Stability Proof (Mathematical Convergence Guarantee)
      const stability = this.lyapunov.verifyTransitionStability(priorState, nextState);
      if (!stability.stable) {
        this.logEvent({
          type: 'LYAPUNOV_INSTABILITY_REJECTED',
          agentId,
          deltaV: stability.deltaV,
          proof: stability.proof
        });

        return {
          success: false,
          blocked: true,
          reason: `Mathematical Invariant Violation: Proposed state transition causes divergent Lyapunov energy growth (ΔV = ${stability.deltaV.toFixed(3)}).`,
          proof: stability.proof,
          latencyMs: performance.now() - startTime
        };
      }

      const committedNode = this.dag.commitMutation({
        mutation: proposal,
        nextState,
        author: agentId,
        certifiedSafe: true
      });

      return {
        success: true,
        blocked: false,
        committedNodeHash: committedNode.hash,
        state: committedNode.state,
        latencyMs: performance.now() - startTime
      };
    } catch (err) {
      // Transactional fail-safe: atomic O(1) rollback
      const rollback = this.dag.atomicRollbackToLastSafeRoot();
      this.logEvent({
        type: 'TRANSACTION_EXCEPTION_ROLLBACK',
        error: err.message,
        rollback
      });

      return {
        success: false,
        blocked: true,
        error: err.message,
        rollbackExecuted: true,
        latencyMs: performance.now() - startTime
      };
    }
  }

  getState() {
    return this.dag.getCurrentState();
  }

  getAuditTrail() {
    return [...this.auditLog];
  }
}
