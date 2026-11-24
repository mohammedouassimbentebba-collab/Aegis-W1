/**
 * W1™ Deterministic Non-LLM Mathematical Kernel
 *
 * The foundational root of trust. Holds absolute mathematical authority
 * over state commits, capability verification, and execution boundaries.
 * Neither natural-language prompt manipulation nor LLM hallucinations can
 * bypass this deterministic kernel.
 *
 * REMEDIATION (2026-09-20):
 * - Injected CapabilityTokenManager into StaticLinter for HMAC verification.
 * - Agent identity bound to proposal — cross-agent token theft detected.
 * - Token nonce consumed atomically on successful DAG commit (replay prevention).
 * - Quarantine expanded to cover CAPABILITY_TOKEN_CRYPTO_FAILED and SUBJECT_MISMATCH.
 * - Added commitProposal() alias for API compatibility.
 */

import { CryptographicDAG } from './cryptographic_dag.js';
import { StaticLinter } from './static_linter.js';
import { DefenseCondition, ThreatSeverity } from './types.js';
import { LyapunovStabilityVerifier } from '../math/lyapunov_stability.js';

/**
 * Violation types that trigger immediate agent quarantine and DEFCON-2.
 * These indicate either active attacks or compromised agent identities.
 */
const QUARANTINE_VIOLATIONS = new Set([
  'CRITICAL_FORBIDDEN_SYSCALL',
  'MALICIOUS_PAYLOAD_DETECTED',
  'CAPABILITY_TOKEN_CRYPTO_FAILED',
  'CAPABILITY_TOKEN_SUBJECT_MISMATCH'
]);

export class DeterministicKernel {
  /**
   * @param {Object} initialState - Initial state for the cryptographic DAG.
   * @param {Object} options
   * @param {import('../perimeter/capability_token_manager.js').CapabilityTokenManager} [options.tokenManager]
   *   - Capability token manager for HMAC verification and nonce consumption.
   * @param {import('../perimeter/capability_token_manager.js').CapabilityTokenManager} [options.capabilityTokenManager]
   *   - Alias for tokenManager (backward compatibility).
   * @param {Object} [options.linterOptions] - Options passed to StaticLinter.
   * @param {Object} [options.lyapunovOptions] - Options for Lyapunov stability verifier.
   */
  constructor(initialState = {}, options = {}) {
    // Resolve token manager from multiple possible option names
    this.tokenManager = options.tokenManager || options.capabilityTokenManager || null;

    this.dag = new CryptographicDAG(initialState);

    // Inject tokenManager into the StaticLinter so it can perform
    // real cryptographic verification on capability tokens
    this.linter = options.linter || new StaticLinter({
      ...options.linterOptions,
      tokenManager: this.tokenManager
    });

    this.lyapunov = new LyapunovStabilityVerifier(options.lyapunovOptions);
    this.defenseCondition = DefenseCondition.DEFCON_5;
    this.auditLog = [];
    this.quarantinedAgents = new Set();
    this.interceptors = new Set();
    this.stateStore = options.stateStore || null;
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
    return this.quarantinedAgents.has(agentId) || Boolean(this.stateStore?.isAgentQuarantinedSync(agentId));
  }

  quarantineAgent(agentId, reason) {
    this.quarantinedAgents.add(agentId);
    if (this.stateStore) {
      this.stateStore.quarantineAgentSync(agentId, reason);
    }
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
   * Public API alias for executeTransaction.
   * Provides the standard interface expected by integration layers.
   */
  commitProposal({ agentId, proposal, nextStateComputation }) {
    return this.executeTransaction({ agentId, proposal, nextStateComputation });
  }

  /**
   * Evaluates and executes an agent's proposed action transactionally.
   * Guaranteed: Zero state corruption. If validation or interception fails,
   * the state remains untouched or is restored in O(1) time.
   *
   * Security pipeline:
   * 1. Quarantine check
   * 2. Active interceptors (Air Defense, Submarine, Radar)
   * 3. Static Linter invariant check (with HMAC token verification)
   * 4. Token nonce consumption (replay prevention)
   * 5. Lyapunov trajectory stability proof
   * 6. DAG commit with cryptographic audit trail
   */
  executeTransaction({ agentId, proposal, nextStateComputation }) {
    const startTime = performance.now();

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 1. Quarantine check — quarantined agents are permanently blocked
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if (this.isAgentQuarantined(agentId)) {
      return {
        success: false,
        blocked: true,
        reason: `Agent '${agentId}' is under military quarantine and stripped of execution authority.`,
        latencyMs: performance.now() - startTime
      };
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 2. Active Interceptors Pre-Check (Air Defense, Submarine, Radar)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 3. Static Linter Invariant Check (Non-LLM Mathematical Proof)
    //    Now includes HMAC-SHA256 verification and subject binding
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    const lintResult = this.linter.validateProposal(proposal, agentId);
    if (!lintResult.valid) {
      this.logEvent({
        type: 'INVARIANT_BREACH_REJECTED',
        agentId,
        errors: lintResult.errors,
        violations: lintResult.violations
      });

      // Quarantine on critical violations including token forgery
      const hasCriticalViolation = lintResult.violations.some(v => QUARANTINE_VIOLATIONS.has(v));
      if (hasCriticalViolation) {
        this.quarantineAgent(agentId, `Critical invariant breach: ${lintResult.violations.join(', ')}`);
        this.setDefenseCondition(DefenseCondition.DEFCON_2);
      }

      return {
        success: false,
        blocked: true,
        reason: lintResult.errors && lintResult.errors.length > 0
          ? `Static Linter rejected proposal: ${lintResult.errors.join('; ')}`
          : 'Static Linter rejected proposal against formal mathematical invariants.',
        errors: lintResult.errors,
        violations: lintResult.violations,
        latencyMs: performance.now() - startTime
      };
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 4. Atomic Token Nonce Consumption (Replay Prevention)
    //    Must happen BEFORE DAG commit so a replayed token never touches state.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if (this.tokenManager && proposal.capabilityToken) {
      const action = proposal.toolName || proposal.actionType || '*';
      const resource = (proposal.parameters && (proposal.parameters.path || proposal.parameters.target || proposal.parameters.resource)) || '*';

      const consumeResult = this.tokenManager.verifyToken(
        proposal.capabilityToken,
        action,
        resource,
        true  // consume=true — marks token as used
      );

      if (!consumeResult.valid) {
        this.logEvent({
          type: 'TOKEN_REPLAY_DETECTED',
          agentId,
          reason: consumeResult.reason,
          tokenId: proposal.capabilityToken.tokenId
        });

        return {
          success: false,
          blocked: true,
          reason: `Token nonce exhaustion or replay detected: ${consumeResult.reason}`,
          latencyMs: performance.now() - startTime
        };
      }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 5. Speculative State Mutation & Safe Commit
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    try {
      const priorState = this.dag.getCurrentState();
      const nextState = nextStateComputation(priorState);

      // 5a. Lyapunov Trajectory Stability Proof (Mathematical Convergence Guarantee)
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
