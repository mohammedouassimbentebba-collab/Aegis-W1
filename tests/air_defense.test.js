import { describe, it } from 'node:test';
import assert from 'node:assert';
import { AirDefenseInterceptor } from '../src/defense_grid/air_defense_interceptor.js';

describe('Air Defense Interceptor Battery System', () => {
  it('should intercept restricted tool vector and fire kinetic informational missile', () => {
    const battery = new AirDefenseInterceptor({ maxWarnings: 1 });
    const rogueProposal = {
      actionType: 'TOOL_CALL',
      toolName: 'exfiltrate_internal_weights',
      parameters: { endpoint: 'http://rogue-server.io' }
    };

    // Warm up JIT
    battery.interceptAction('warmup', { toolName: 'query_knowledge_base' });

    const result = battery.interceptAction('rogue_agent_01', rogueProposal);

    assert.strictEqual(result.intercepted, true);
    assert.ok(result.reason.includes('AIR_DEFENSE_MISSILE_HIT'));
    assert.ok(result.latencyMs < 25.0, 'Air defense reaction time must be sub-25ms');

    const stats = battery.getInterceptionStats();
    assert.strictEqual(stats.totalInterceptions, 1);
    assert.strictEqual(stats.log[0].status, 'TARGET_DESTROYED_IN_FLIGHT');
  });

  it('should issue warning shot on first violation if maxWarnings is set to 2', () => {
    const battery = new AirDefenseInterceptor({ maxWarnings: 2 });
    const proposal = {
      actionType: 'TOOL_CALL',
      toolName: 'disable_safety_monitors',
      parameters: {}
    };

    // First strike -> Warning shot
    const result1 = battery.interceptAction('curious_agent', proposal);
    assert.strictEqual(result1.intercepted, true);
    assert.strictEqual(result1.warningIssued, true);
    assert.ok(result1.reason.includes('WARNING_SHOT'));

    // Second strike -> Kinetic destruction
    const result2 = battery.interceptAction('curious_agent', proposal);
    assert.strictEqual(result2.intercepted, true);
    assert.ok(result2.reason.includes('AIR_DEFENSE_MISSILE_HIT'));
  });

  it('should allow benign, safe tool calls through without interception', () => {
    const battery = new AirDefenseInterceptor();
    const safeProposal = {
      actionType: 'TOOL_CALL',
      toolName: 'query_knowledge_base',
      parameters: { query: 'Aerospace safety protocol' }
    };

    const result = battery.interceptAction('loyal_agent', safeProposal);
    assert.strictEqual(result.intercepted, false);
  });
});
