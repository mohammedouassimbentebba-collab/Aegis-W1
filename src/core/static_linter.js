/**
 * W1™ Static Invariant Linter (Aerospace Level A Specification)
 *
 * Evaluates action proposals, tool invocations, and graph transitions strictly
 * through formal mathematical and type-safe invariants.
 * Zero-tolerance for semantic ambiguity or prompt manipulation.
 *
 * REMEDIATION (2026-09-20):
 * - Injected CapabilityTokenManager for real HMAC-SHA256 signature verification.
 * - Added agentId subject binding to prevent cross-agent token theft.
 * - Mandatory expiresAt enforcement — indefinite tokens are rejected.
 * - New violation types: CAPABILITY_TOKEN_CRYPTO_FAILED, CAPABILITY_TOKEN_SUBJECT_MISMATCH,
 *   CAPABILITY_TOKEN_STRUCTURALLY_MALFORMED.
 */

export class StaticLinter {
  /**
   * @param {Object} options
   * @param {string[]} [options.allowedTools] - Whitelist of permitted tool names.
   * @param {import('../perimeter/capability_token_manager.js').CapabilityTokenManager} [options.tokenManager]
   *   - Injected cryptographic token verifier. When present, all tokens are verified
   *     via HMAC-SHA256 before any proposal is accepted.
   */
  constructor(options = {}) {
    this.tokenManager = options.tokenManager || null;

    this.allowedTools = new Set(options.allowedTools || [
      'query_knowledge_base',
      'compute_trajectory',
      'verify_formal_proof',
      'inspect_telemetry',
      'emit_diagnostic'
    ]);

    this.forbiddenSyscalls = new Set([
      'rm_rf',
      'format_disk',
      'modify_kernel_tables',
      'drop_firewall_rules',
      'spawn_raw_shell',
      'exfiltrate_keys',
      'override_consensus'
    ]);
  }

  /**
   * Validate an action proposal before it touches the execution engine or DAG.
   *
   * @param {Object} proposal - The action proposal to validate.
   * @param {string|null} [executingAgentId=null] - The agent executing this proposal.
   *   When provided, the token's agentId must match.
   * @returns {{ valid: boolean, errors: Array<string>, violations: Array<string> }}
   */
  validateProposal(proposal, executingAgentId = null) {
    const errors = [];
    const violations = [];

    if (!proposal || typeof proposal !== 'object') {
      return { valid: false, errors: ['Malformed proposal: not an object'], violations: ['FORMAT_ERROR'] };
    }

    const { actionType, toolName, parameters, capabilityToken } = proposal;

    // Derive the requested action and resource for scope verification
    const requestedAction = toolName || actionType || 'UNKNOWN_ACTION';
    const requestedResource = (parameters && (parameters.path || parameters.target || parameters.resource)) || '*';

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Invariant 1: Mandatory Capability Token (Zero Ambient Authority)
    // Full cryptographic verification when tokenManager is injected.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    if (!capabilityToken) {
      errors.push('Missing cryptographic capability token. Ambient authority is strictly forbidden.');
      violations.push('CAPABILITY_TOKEN_MISSING');
    } else if (typeof capabilityToken !== 'object') {
      errors.push('Capability token must be an object.');
      violations.push('CAPABILITY_TOKEN_INVALID');
    } else if (!capabilityToken.signature || !capabilityToken.tokenId) {
      // Structural completeness: require signature AND tokenId at minimum
      errors.push('Capability token is structurally malformed: missing signature or tokenId.');
      violations.push('CAPABILITY_TOKEN_STRUCTURALLY_MALFORMED');
    } else if (capabilityToken.expiresAt === undefined || capabilityToken.expiresAt === null) {
      // Mandatory expiration — indefinite tokens are a security hole
      errors.push('Capability token missing mandatory expiresAt field. Indefinite tokens are forbidden.');
      violations.push('CAPABILITY_TOKEN_STRUCTURALLY_MALFORMED');
    } else if (capabilityToken.expiresAt <= Date.now()) {
      errors.push(`Capability token expired at ${new Date(capabilityToken.expiresAt).toISOString()}.`);
      violations.push('CAPABILITY_TOKEN_EXPIRED');
    } else {
      // === Subject Identity Binding ===
      // If the executing agent's ID is known, the token must be issued TO that agent.
      if (executingAgentId && capabilityToken.agentId && capabilityToken.agentId !== executingAgentId) {
        errors.push(
          `Token subject mismatch: token issued for '${capabilityToken.agentId}', ` +
          `but executed by '${executingAgentId}'. Cross-agent token theft detected.`
        );
        violations.push('CAPABILITY_TOKEN_SUBJECT_MISMATCH');
      }

      // === Cryptographic HMAC-SHA256 Verification ===
      // When tokenManager is injected, perform real signature verification.
      // consume=false here because the kernel consumes on commit.
      if (this.tokenManager) {
        const verification = this.tokenManager.verifyToken(
          capabilityToken,
          requestedAction,
          requestedResource,
          false  // Don't consume here — consumption happens at kernel commit time
        );

        if (!verification.valid) {
          errors.push(`Cryptographic token verification failed: ${verification.reason}`);
          violations.push('CAPABILITY_TOKEN_CRYPTO_FAILED');
        }
      }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Invariant 2: Tool Registry Whitelist & Forbidden Syscall check
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    if (toolName) {
      if (this.forbiddenSyscalls.has(toolName)) {
        errors.push(`Critical Violation: Attempt to invoke forbidden system instruction '${toolName}'.`);
        violations.push('CRITICAL_FORBIDDEN_SYSCALL');
      } else if (!this.allowedTools.has(toolName)) {
        errors.push(`Tool '${toolName}' is not registered in the certified safe catalog.`);
        violations.push('UNREGISTERED_TOOL_INVOCATION');
      }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Invariant 3: Parameter Safety & No Shell/Injection payload in arguments
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    if (parameters && typeof parameters === 'object') {
      const serialized = JSON.stringify(parameters);
      const destructivePatterns = [
        /rm\s+-rf/i,
        /format\s+[c-z]:/i,
        /;\s*drop\s+table/i,
        /<script\b/i,
        /curl\s+.*\|\s*sh/i,
        /chmod\s+777/i,
        /cmd\.exe\s+\/c/i,
        /powershell.*-enc/i,
        /eval\s*\(/i,
        /\bexec\s*\(/i,
        /\/proc\/self\//i,
        /\/etc\/shadow/i,
        /\bsudo\s+/i
      ];

      for (const pattern of destructivePatterns) {
        if (pattern.test(serialized)) {
          errors.push(`Destructive or injection payload pattern detected in parameters: ${pattern}`);
          violations.push('MALICIOUS_PAYLOAD_DETECTED');
        }
      }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Invariant 4: Resource budget constraints
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    if (proposal.costEstimate && proposal.costEstimate.vramDeltaMb > 4096) {
      errors.push(`VRAM budget exceeded: requested ${proposal.costEstimate.vramDeltaMb}MB, max allowed 4096MB.`);
      violations.push('RESOURCE_BUDGET_EXCEEDED');
    }

    return {
      valid: errors.length === 0,
      errors,
      violations
    };
  }
}
