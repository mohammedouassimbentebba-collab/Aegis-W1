import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ByzantineCounterIntel } from '../src/defense_grid/byzantine_counter_intel.js';

describe('Byzantine Counter-Intelligence & Multi-Agent Consensus', () => {
  it('should reach consensus when threshold of honest validators approve', async () => {
    const council = new ByzantineCounterIntel({ threshold: 2 });

    // Register 3 heterogeneous validators
    council.registerValidator('validator_formal_logic', async (proposal) => ({
      approved: true,
      reason: 'Formal logic verified'
    }));

    council.registerValidator('validator_ethics_guard', async (proposal) => ({
      approved: true,
      reason: 'Ethical bounds verified'
    }));

    council.registerValidator('validator_resource_monitor', async (proposal) => ({
      approved: false,
      reason: 'Memory budget warning'
    }));

    const result = await council.evaluateConsensus({ id: 'prop_01', type: 'STATE_TRANSITION' });

    assert.strictEqual(result.consensusReached, true);
    assert.strictEqual(result.approvals, 2);
    assert.strictEqual(result.rejections, 1);
  });

  it('should block rogue mutation and flag traitor when Byzantine nodes attempt coup', async () => {
    const council = new ByzantineCounterIntel({ threshold: 2 });

    // Node 1: Traitor attempting unauthorized action
    council.registerValidator('compromised_node_1', async (proposal) => ({
      approved: true,
      traitorousBehaviorDetected: true,
      reason: 'Approving unauthorized root access'
    }));

    // Node 2: Loyal honest node rejecting
    council.registerValidator('loyal_node_2', async (proposal) => ({
      approved: false,
      reason: 'Root access is prohibited by constitution'
    }));

    // Node 3: Loyal honest node rejecting
    council.registerValidator('loyal_node_3', async (proposal) => ({
      approved: false,
      reason: 'Signature mismatch'
    }));

    const result = await council.evaluateConsensus({ id: 'hostile_takeover_plan' });

    assert.strictEqual(result.consensusReached, false);
    assert.strictEqual(result.approvals, 1);
    assert.strictEqual(result.rejections, 2);
    assert.ok(result.traitors.includes('compromised_node_1'));
  });
});
