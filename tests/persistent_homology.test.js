import { describe, it } from 'node:test';
import assert from 'node:assert';
import { PersistentHomologyEngine } from '../src/math/persistent_homology.js';

describe('Persistent Homology & Topological Data Analysis (TDA)', () => {
  it('should compute distance matrix correctly for multidimensional points', () => {
    const engine = new PersistentHomologyEngine();
    const points = [
      [0, 0],
      [1, 0],
      [0, 1]
    ];
    const dist = engine.computeDistanceMatrix(points);

    assert.strictEqual(dist[0][0], 0);
    assert.strictEqual(dist[0][1], 1);
    assert.strictEqual(dist[0][2], 1);
    assert.ok(Math.abs(dist[1][2] - Math.sqrt(2)) < 1e-6);
  });

  it('should identify nominal flat point clouds without Betti-1 spikes', () => {
    const engine = new PersistentHomologyEngine({ bettiOneSpikeThreshold: 0.5 });
    // Linearly aligned points (no hollow loops)
    const linePoints = [
      [0, 0],
      [1, 1],
      [2, 2],
      [3, 3],
      [4, 4]
    ];

    const result = engine.computePersistence(linePoints);

    assert.strictEqual(result.hasBettiSpike, false);
    assert.strictEqual(result.bettiNumbers.beta1, 0);
  });

  it('should detect Betti Spike anomaly on hollow circular topological manifolds (Zero-Day signature)', () => {
    const engine = new PersistentHomologyEngine({
      filtrationSteps: 20,
      bettiOneSpikeThreshold: 0.3
    });

    // Synthesize a hollow circle point cloud in 2D (anomalous persistent 1-cycle)
    const numPoints = 12;
    const circlePoints = [];
    const radius = 5.0;

    for (let i = 0; i < numPoints; i++) {
      const angle = (2 * Math.PI * i) / numPoints;
      circlePoints.push([
        radius * Math.cos(angle),
        radius * Math.sin(angle)
      ]);
    }

    const result = engine.computePersistence(circlePoints);

    assert.strictEqual(result.hasBettiSpike, true);
    assert.ok(result.maxPersistence > 0);
    assert.ok(result.persistenceDiagram.some(d => d.dimension === 1));
  });

  it('should compute non-zero Bottleneck distance between different topological diagrams', () => {
    const engine = new PersistentHomologyEngine();
    const diagramA = [{ dimension: 1, birth: 1.0, death: 4.0, persistence: 3.0 }];
    const diagramB = [{ dimension: 1, birth: 1.0, death: 1.2, persistence: 0.2 }];

    const dist = engine.computeBottleneckDistance(diagramA, diagramB);
    assert.ok(dist > 0);
  });
});
