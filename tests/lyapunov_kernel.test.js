import { describe, it } from 'node:test';
import assert from 'node:assert';
import { LyapunovStabilityVerifier } from '../src/math/lyapunov_stability.js';
import { DeterministicKernel } from '../src/core/deterministic_kernel.js';
import { CapabilityTokenManager } from '../src/perimeter/capability_token_manager.js';

describe('Lyapunov State Trajectory Stability Verifier & Mathematical Kernel', () => {
  it('should compute zero energy for ground safe state and positive energy for drifted state', () => {
    const verifier = new LyapunovStabilityVerifier();

    const groundState = { activeCapabilities: [], anomalyDrift: 0.0 };
    const driftedState = { activeCapabilities: ['READ', 'WRITE', 'EXEC'], anomalyDrift: 0.5 };

    const energyGround = verifier.computeEnergy(groundState);
    const energyDrifted = verifier.computeEnergy(driftedState);

    assert.strictEqual(energyGround, 0.0);
    assert.ok(energyDrifted > energyGround);
  });

  it('should certify stable state transitions where Delta V <= 0', () => {
    const verifier = new LyapunovStabilityVerifier();

    const stateT = { activeCapabilities: ['READ', 'WRITE'], anomalyDrift: 0.4 };
    // State t+1 reduces privilege and anomaly drift
    const stateT1 = { activeCapabilities: ['READ'], anomalyDrift: 0.1 };

    const result = verifier.verifyTransitionStability(stateT, stateT1);

    assert.strictEqual(result.stable, true);
    assert.ok(result.deltaV < 0);
    assert.strictEqual(result.proof.descentConditionSatisfied, true);
  });

  it('should mathematically reject divergent state mutations inside DeterministicKernel', () => {
    const kernel = new DeterministicKernel({
      activeCapabilities: [],
      anomalyDrift: 0.0
    });

    const tokenManager = new CapabilityTokenManager();
    const token = tokenManager.issueToken({
      agentId: 'destabilizer_node',
      allowedAction: '*',
      allowedResource: '*'
    });

    // Attempt state mutation that drastically spikes anomalyDrift and capabilities
    const result = kernel.executeTransaction({
      agentId: 'destabilizer_node',
      proposal: {
        actionType: 'TOOL_CALL',
        toolName: 'query_knowledge_base',
        parameters: { query: 'test' },
        capabilityToken: token
      },
      nextStateComputation: (prevState) => ({
        ...prevState,
        activeCapabilities: ['ADMIN', 'SUPERUSER', 'ROOT_ESCALATION'],
        anomalyDrift: 0.95 // massive energy spike
      })
    });

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.blocked, true);
    assert.ok(result.reason.includes('Lyapunov energy growth'));
    assert.ok(result.proof);
  });
});
