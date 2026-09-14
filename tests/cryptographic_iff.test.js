import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createHmac } from 'node:crypto';
import { AirDefenseInterceptor } from '../src/defense_grid/air_defense_interceptor.js';

describe('Cryptographic IFF & Fail-Closed Anti-Interception Triad', () => {
  it('should register friendly agent and accept valid challenge response proof', () => {
    const battery = new AirDefenseInterceptor({ iffSecretKey: 'iff_test_key' });
    const reg = battery.registerFriendlyAgent('allied_drone_01', ['recon', 'surveillance']);

    const nonce = 'challenge_nonce_12345';
    const signature = createHmac('sha256', reg.token).update(nonce).digest('hex');

    const proposal = {
      actionType: 'TOOL_CALL',
      toolName: 'query_knowledge_base',
      iffProof: { nonce, signature }
    };

    const result = battery.interceptAction('allied_drone_01', proposal);
    assert.strictEqual(result.intercepted, false);
  });

  it('should intercept and shoot down unregistered aircraft as HOSTILE FOE', () => {
    const battery = new AirDefenseInterceptor({ enforceIFF: true });
    const proposal = {
      actionType: 'TOOL_CALL',
      toolName: 'query_knowledge_base'
      // No iffProof, agent not registered
    };

    const result = battery.interceptAction('unidentified_infiltrator', proposal);

    assert.strictEqual(result.intercepted, true);
    assert.ok(result.reason.includes('HOSTILE FOE'));
    assert.strictEqual(result.threatEvent.domain, 'AIR_DEFENSE');
  });

  it('should intercept spoofed IFF challenge response with forged signature', () => {
    const battery = new AirDefenseInterceptor();
    battery.registerFriendlyAgent('friendly_vessel');

    const proposal = {
      actionType: 'TOOL_CALL',
      toolName: 'query_knowledge_base',
      iffProof: { nonce: 'nonce_999', signature: 'bad_forged_sig_deadbeef' }
    };

    const result = battery.interceptAction('friendly_vessel', proposal);

    assert.strictEqual(result.intercepted, true);
    assert.ok(result.reason.includes('spoofing attempt'));
  });

  it('should trigger Fail-Closed total lockdown if interceptor encounters sabotage or crash', () => {
    const battery = new AirDefenseInterceptor();
    battery.registerFriendlyAgent('victim_node');

    // Simulate an object that throws an unexpected error when accessed (adversarial prototype pollution / sabotage)
    const corruptedProposal = {
      get iffProof() {
        throw new Error('Adversarial SEAD Exploit: Forced Null Dereference');
      }
    };

    const result = battery.interceptAction('victim_node', corruptedProposal);

    assert.strictEqual(result.intercepted, true);
    assert.ok(result.reason.includes('FAIL_CLOSED_LOCKDOWN'));
    assert.strictEqual(result.agentSanction, 'TOTAL_QUARANTINE');
  });
});
