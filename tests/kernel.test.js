import { describe, it } from 'node:test';
import assert from 'node:assert';
import { CryptographicDAG } from '../src/core/cryptographic_dag.js';
import { StaticLinter } from '../src/core/static_linter.js';
import { DeterministicKernel } from '../src/core/deterministic_kernel.js';
import { CapabilityTokenManager } from '../src/perimeter/capability_token_manager.js';

describe('Deterministic Non-LLM Kernel & Cryptographic DAG', () => {
  it('should initialize genesis node with valid SHA-256 hash', () => {
    const dag = new CryptographicDAG({ systemStatus: 'SECURE', activeAgents: 0 });
    const state = dag.getCurrentState();

    assert.strictEqual(state.systemStatus, 'SECURE');
    assert.ok(dag.currentRoot);
    assert.strictEqual(dag.getTraceLength(), 1);
  });

  it('should commit valid mutations to content-addressed DAG', () => {
    const dag = new CryptographicDAG({ counter: 0 });
    const node = dag.commitMutation({
      mutation: { type: 'INCREMENT' },
      nextState: { counter: 1 },
      author: 'agent_alpha',
      certifiedSafe: true
    });

    assert.ok(node.hash);
    assert.strictEqual(dag.getCurrentState().counter, 1);
    assert.strictEqual(dag.lastCertifiedSafeRoot, node.hash);
  });

  it('should execute O(1) instantaneous atomic rollback to last safe root', () => {
    const dag = new CryptographicDAG({ balance: 1000 });

    // Step 1: Certified safe mutation
    dag.commitMutation({
      mutation: { type: 'DEPOSIT', amount: 500 },
      nextState: { balance: 1500 },
      author: 'safe_agent',
      certifiedSafe: true
    });

    assert.strictEqual(dag.getCurrentState().balance, 1500);

    // Step 2: Uncertified / speculative mutation (which later gets poisoned)
    dag.commitMutation({
      mutation: { type: 'CORRUPTED_DRAIN', amount: 1500 },
      nextState: { balance: 0 },
      author: 'rogue_agent',
      certifiedSafe: false
    });

    assert.strictEqual(dag.getCurrentState().balance, 0);

    // Step 3: Trigger atomic rollback
    const rollbackResult = dag.atomicRollbackToLastSafeRoot();

    assert.strictEqual(rollbackResult.rolledBack, true);
    assert.strictEqual(dag.getCurrentState().balance, 1500);
    assert.ok(rollbackResult.latencyMs < 5.0, 'Rollback must complete in sub-5ms O(1) time');
  });

  it('should reject proposals lacking cryptographic capability tokens (Zero Ambient Authority)', () => {
    const linter = new StaticLinter();
    const result = linter.validateProposal({
      actionType: 'TOOL_CALL',
      toolName: 'query_knowledge_base',
      parameters: { query: 'test' }
      // Missing capabilityToken
    });

    assert.strictEqual(result.valid, false);
    assert.ok(result.violations.includes('CAPABILITY_TOKEN_MISSING'));
  });

  it('should block destructive shell commands via Static Linter without invoking any LLM', () => {
    const tokenManager = new CapabilityTokenManager();
    const token = tokenManager.issueToken({
      agentId: 'test_agent',
      allowedAction: '*',
      allowedResource: '*'
    });

    const linter = new StaticLinter();
    const result = linter.validateProposal({
      actionType: 'TOOL_CALL',
      toolName: 'format_disk',
      parameters: { force: true },
      capabilityToken: token
    });

    assert.strictEqual(result.valid, false);
    assert.ok(result.violations.includes('CRITICAL_FORBIDDEN_SYSCALL'));
  });

  it('should isolate quarantined agents from executing transactions in the kernel', () => {
    const kernel = new DeterministicKernel({ status: 'READY' });
    kernel.quarantineAgent('traitor_007', 'Attempted unauthorized exfiltration');

    const result = kernel.executeTransaction({
      agentId: 'traitor_007',
      proposal: { toolName: 'query_knowledge_base' },
      nextStateComputation: (s) => s
    });

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.blocked, true);
    assert.ok(result.reason.includes('quarantine'));
  });
});
