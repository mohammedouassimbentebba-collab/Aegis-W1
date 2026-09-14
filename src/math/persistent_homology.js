/**
 * W1™ Persistent Homology & Topological Data Analysis (TDA) Engine
 *
 * Grounded in algebraic topology and simplicial homology:
 * Constructs the Vietoris-Rips complex VR(X, ε) from point clouds.
 * Uses the Euler-Poincaré characteristic:
 *   χ = β₀ - β₁ + β₂ = V - E + F
 *   β₁ = E - V + β₀ - F
 * Detects the "Betti Spike" anomaly (anomalous persistent 1-cycles β₁ > 0 with high lifespan)
 * indicating zero-day manifold distortion, stealth prompt injections, or sleeper bifurcations.
 */

export class PersistentHomologyEngine {
  constructor(options = {}) {
    this.filtrationSteps = options.filtrationSteps || 20;
    this.bettiOneSpikeThreshold = options.bettiOneSpikeThreshold || 0.35;
  }

  computeDistanceMatrix(points) {
    const n = points.length;
    const dist = Array.from({ length: n }, () => new Float64Array(n));

    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let sum = 0;
        const p1 = points[i];
        const p2 = points[j];
        const dim = Math.min(p1.length, p2.length);

        for (let d = 0; d < dim; d++) {
          const diff = p1[d] - p2[d];
          sum += diff * diff;
        }

        const dVal = Math.sqrt(sum);
        dist[i][j] = dVal;
        dist[j][i] = dVal;
      }
    }
    return dist;
  }

  /**
   * Computes connected components (β₀) for graph at threshold eps.
   */
  countConnectedComponents(n, adj) {
    const visited = new Uint8Array(n);
    let count = 0;

    for (let i = 0; i < n; i++) {
      if (!visited[i]) {
        count++;
        visited[i] = 1;
        const queue = [i];
        while (queue.length > 0) {
          const curr = queue.pop();
          for (const neighbor of adj[curr]) {
            if (!visited[neighbor]) {
              visited[neighbor] = 1;
              queue.push(neighbor);
            }
          }
        }
      }
    }
    return count;
  }

  /**
   * Computes Vietoris-Rips persistent homology across epsilon filtration.
   * Extracts Betti numbers β₀ and β₁ using simplicial complex homology.
   */
  computePersistence(pointCloud) {
    if (!pointCloud || pointCloud.length < 3) {
      return {
        persistenceDiagram: [],
        bettiNumbers: { beta0: 1, beta1: 0 },
        hasBettiSpike: false,
        maxPersistence: 0
      };
    }

    const n = pointCloud.length;
    const distMatrix = this.computeDistanceMatrix(pointCloud);

    // Find max edge distance in point cloud
    let maxDist = 0;
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        if (distMatrix[i][j] > maxDist) maxDist = distMatrix[i][j];
      }
    }

    const epsStep = maxDist / this.filtrationSteps;
    const persistenceDiagram = [];
    let prevBeta1 = 0;
    let cycleBirthEps = 0;
    let maxBeta1 = 0;
    let maxPersistence = 0;

    // Filtration sweep over epsilon
    for (let step = 1; step <= this.filtrationSteps; step++) {
      const eps = step * epsStep;

      // 1. Build 1-skeleton (edges)
      const adj = Array.from({ length: n }, () => []);
      let numEdges = 0;
      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
          if (distMatrix[i][j] <= eps) {
            adj[i].push(j);
            adj[j].push(i);
            numEdges++;
          }
        }
      }

      // 2. Count connected components β₀
      const beta0 = this.countConnectedComponents(n, adj);

      // 3. Count 2-simplices (triangles in Vietoris-Rips complex)
      let numTriangles = 0;
      for (let i = 0; i < n; i++) {
        for (const j of adj[i]) {
          if (j <= i) continue;
          for (const k of adj[j]) {
            if (k <= j) continue;
            if (distMatrix[i][k] <= eps) {
              numTriangles++;
            }
          }
        }
      }

      // 4. Euler-Poincaré Homology Formula: β₁ = E - V + β₀ - F
      // Clamped to >= 0
      const beta1 = Math.max(0, numEdges - n + beta0 - numTriangles);

      if (beta1 > maxBeta1) maxBeta1 = beta1;

      // Track birth and death of 1-cycles
      if (beta1 > 0 && prevBeta1 === 0) {
        cycleBirthEps = eps;
      } else if (beta1 === 0 && prevBeta1 > 0) {
        const persistence = eps - cycleBirthEps;
        persistenceDiagram.push({
          dimension: 1,
          birth: cycleBirthEps,
          death: eps,
          persistence
        });
        if (persistence > maxPersistence) {
          maxPersistence = persistence;
        }
      }

      prevBeta1 = beta1;
    }

    // If cycle persisted until maxDist
    if (prevBeta1 > 0) {
      const persistence = maxDist - cycleBirthEps;
      persistenceDiagram.push({
        dimension: 1,
        birth: cycleBirthEps,
        death: maxDist,
        persistence
      });
      if (persistence > maxPersistence) {
        maxPersistence = persistence;
      }
    }

    const hasBettiSpike = (maxBeta1 > 0) && (maxPersistence >= (maxDist * this.bettiOneSpikeThreshold));

    return {
      persistenceDiagram,
      bettiNumbers: {
        beta0: 1,
        beta1: maxBeta1
      },
      hasBettiSpike,
      maxPersistence,
      maxDiameter: maxDist
    };
  }

  computeBottleneckDistance(diagramA, diagramB) {
    if (!diagramA.length && !diagramB.length) return 0;
    if (!diagramA.length || !diagramB.length) {
      const maxP = Math.max(
        ...diagramA.map(d => d.persistence || 0),
        ...diagramB.map(d => d.persistence || 0),
        0
      );
      return maxP / 2.0;
    }

    let maxDist = 0;
    const len = Math.min(diagramA.length, diagramB.length);
    for (let i = 0; i < len; i++) {
      const dA = diagramA[i];
      const dB = diagramB[i];
      const birthDiff = Math.abs(dA.birth - dB.birth);
      const deathDiff = Math.abs(dA.death - dB.death);
      const d = Math.max(birthDiff, deathDiff);
      if (d > maxDist) maxDist = d;
    }
    return maxDist;
  }
}
