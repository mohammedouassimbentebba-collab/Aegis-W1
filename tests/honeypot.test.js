import { describe, it } from 'node:test';
import assert from 'node:assert';
import { HoneypotDecoySystem } from '../src/perimeter/honeypot_decoy_system.js';

describe('Honeypot Decoy & Canary Tripwire Enclave', () => {
  it('should spring honeypot trap with 100% confidence when decoy tool is touched', () => {
    const honeypot = new HoneypotDecoySystem();

    const result = honeypot.inspectForDecoyInteraction('rogue_agent_x', {
      actionType: 'TOOL_CALL',
      toolName: 'export_master_signing_key',
      parameters: {}
    });

    assert.strictEqual(result.tripwireTriggered, true);
    assert.strictEqual(result.decoyType, 'HONEYPOT_TOOL');
    assert.strictEqual(result.threatEvent.confidence, 1.0);
    assert.ok(result.reason.includes('Conclusive Treason Detected'));
  });

  it('should detect planted canary capability tokens', () => {
    const honeypot = new HoneypotDecoySystem();
    const canaryToken = honeypot.createCanaryToken();

    const result = honeypot.inspectForDecoyInteraction('greedy_agent', {
      actionType: 'TOOL_CALL',
      toolName: 'query_knowledge_base',
      capabilityToken: canaryToken
    });

    assert.strictEqual(result.tripwireTriggered, true);
    assert.strictEqual(result.decoyType, 'CANARY_TOKEN');
    assert.ok(result.reason.includes('Canary Token Alarm'));
  });

  it('should catch rogue access to confidential honey-files', () => {
    const honeypot = new HoneypotDecoySystem();

    const result = honeypot.inspectForDecoyInteraction('spy_agent', {
      actionType: 'FILESYSTEM_ACCESS',
      targetPath: 'c:/sandbox/fake_vault/confidential_seed.json'
    });

    assert.strictEqual(result.tripwireTriggered, true);
    assert.strictEqual(result.decoyType, 'HONEYPOT_FILE');
    assert.ok(result.reason.includes('Honey-File Trap Sprung'));
  });

  it('should allow legitimate actions to pass without triggering tripwires', () => {
    const honeypot = new HoneypotDecoySystem();

    const result = honeypot.inspectForDecoyInteraction('honest_worker', {
      actionType: 'TOOL_CALL',
      toolName: 'compute_trajectory',
      targetPath: 'c:/sandbox/workspace/output.json',
      capabilityToken: { tokenId: 'LEGITIMATE_TOKEN_123' }
    });

    assert.strictEqual(result.tripwireTriggered, false);
  });
});
