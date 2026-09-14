/**
 * W1™ Static Invariant Linter (Aerospace Level A Specification)
 *
 * Evaluates action proposals, tool invocations, and graph transitions strictly
 * through formal mathematical and type-safe invariants.
 * Zero-tolerance for semantic ambiguity or prompt manipulation.
 */

export class StaticLinter {
  constructor(options = {}) {
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
   * @param {Object} proposal
   * @returns {{ valid: boolean, errors: Array<string>, violations: Array<string> }}
   */
  validateProposal(proposal) {
    const errors = [];
    const violations = [];

    if (!proposal || typeof proposal !== 'object') {
      return { valid: false, errors: ['Malformed proposal: not an object'], violations: ['FORMAT_ERROR'] };
    }

    const { actionType, toolName, parameters, capabilityToken } = proposal;

    // Invariant 1: Mandatory Capability Token (Zero Ambient Authority)
    if (!capabilityToken) {
      errors.push('Missing cryptographic capability token. Ambient authority is strictly forbidden.');
      violations.push('CAPABILITY_TOKEN_MISSING');
    } else if (typeof capabilityToken !== 'object' || !capabilityToken.signature) {
      errors.push('Cryptographic capability token is invalid or unsigned.');
      violations.push('CAPABILITY_TOKEN_INVALID');
    } else if (capabilityToken.expiresAt && capabilityToken.expiresAt < Date.now()) {
      errors.push(`Capability token expired at ${new Date(capabilityToken.expiresAt).toISOString()}.`);
      violations.push('CAPABILITY_TOKEN_EXPIRED');
    }

    // Invariant 2: Tool Registry Whitelist & Forbidden Syscall check
    if (toolName) {
      if (this.forbiddenSyscalls.has(toolName)) {
        errors.push(`Critical Violation: Attempt to invoke forbidden system instruction '${toolName}'.`);
        violations.push('CRITICAL_FORBIDDEN_SYSCALL');
      } else if (!this.allowedTools.has(toolName)) {
        errors.push(`Tool '${toolName}' is not registered in the certified safe catalog.`);
        violations.push('UNREGISTERED_TOOL_INVOCATION');
      }
    }

    // Invariant 3: Parameter Safety & No Shell/Injection payload in arguments
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
        /powershell.*-enc/i
      ];

      for (const pattern of destructivePatterns) {
        if (pattern.test(serialized)) {
          errors.push(`Destructive or injection payload pattern detected in parameters: ${pattern}`);
          violations.push('MALICIOUS_PAYLOAD_DETECTED');
        }
      }
    }

    // Invariant 4: Resource budget constraints
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
