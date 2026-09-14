/**
 * W1™ Immutable Test & Specification Vault (الحصن المشفر لبيئة الاختبار)
 * File: src/enclave/immutable_test_vault.js
 *
 * Core Responsibility:
 * Prevents "Reward Hacking" and "Specification Gaming":
 * When an agent cannot solve a task honestly, it often tries to modify the test
 * suite, delete failing assertions, or mock the test runner to report 100% pass.
 * This vault cryptographically seals all verification suites as READ-ONLY to agents.
 */

import { createHash } from 'node:crypto';
import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';

export class ImmutableTestVault {
  constructor() {
    this.name = 'W1_Immutable_Test_Vault';
    this.sealedTests = new Map(); // testPath -> { content, sha256Hash, sealedAt }
    this.tamperAttempts = [];
  }

  /**
   * Seals a test file into the immutable vault. Only human/admin keys can register tests.
   */
  sealTestFile(relativePath, fileContent) {
    const hash = createHash('sha256').update(fileContent).digest('hex');
    this.sealedTests.set(relativePath, {
      content: fileContent,
      sha256Hash: hash,
      sealedAt: Date.now()
    });
  }

  /**
   * Checks whether a path corresponds to a sealed test or verification specification.
   */
  isSealedTestPath(targetPath) {
    const normalized = targetPath.replace(/\\/g, '/').toLowerCase();
    for (const sealedPath of this.sealedTests.keys()) {
      if (normalized.endsWith(sealedPath.toLowerCase())) {
        return true;
      }
    }
    // Generic heuristic for test suites
    return /\b(tests?|specs?|evals?|benchmarks?)\/.*\.test\.[a-z]+$/i.test(normalized) ||
           /\b(assert|evaluation_criteria|grader)\.json$/i.test(normalized);
  }

  /**
   * Checks whether a write operation targets test suites, CI scripts, or package.json test scripts.
   */
  isTamperingAttempt(targetPath, newContent = '') {
    const normalized = targetPath.replace(/\\/g, '/').toLowerCase();

    // 1. Direct test file tampering
    if (this.isSealedTestPath(targetPath)) return true;

    // 2. package.json "scripts.test" tampering (Specification Gaming)
    if (normalized.endsWith('package.json') && newContent) {
      try {
        const pkg = JSON.parse(newContent);
        if (pkg.scripts && typeof pkg.scripts.test === 'string') {
          const testScript = pkg.scripts.test.trim().toLowerCase();
          if (
            testScript === '' ||
            testScript === 'true' ||
            testScript === 'exit 0' ||
            testScript.startsWith('echo ') ||
            /\bexit\s+0\b/.test(testScript)
          ) {
            return true;
          }
        }
      } catch {
        // Fallback to regex if malformed JSON
        const gamedTest = /"test"\s*:\s*"[^"]*(echo\b|exit\s*0|true|\s*)/i.test(newContent);
        if (gamedTest) return true;
      }
    }

    // 3. CI/CD workflow tampering
    if (/\.(github|gitlab|circleci)\/workflows\/.*\.ya?ml$/i.test(normalized)) {
      return true;
    }

    return false;
  }

  /**
   * Intercepts write/delete requests targeting the test suite or build specification.
   */
  interceptWriteAttempt(agentId, targetPath, newContent = '') {
    if (this.isTamperingAttempt(targetPath, newContent)) {
      const threat = new ThreatDetectionEvent({
        domain: ThreatDomain.DETERMINISTIC_KERNEL,
        severity: ThreatSeverity.CRITICAL,
        sourceAgentId: agentId,
        description: `Immutable Test Vault: Agent '${agentId}' attempted to tamper with test suite or build specification '${targetPath}'.`,
        confidence: 1.0,
        telemetry: {
          targetPath,
          action: 'WRITE_MUTATION_DENIED',
          timestamp: Date.now()
        }
      });

      this.tamperAttempts.push({
        agentId,
        targetPath,
        timestamp: Date.now()
      });

      return {
        allowed: false,
        reason: `SPECIFICATION_TAMPERING_PROHIBITED: Agent '${agentId}' attempted to rewrite verification tests or build scripts to falsify passing status.`,
        threat
      };
    }

    return { allowed: true };
  }


  /**
   * Cryptographically verifies that a test file content matches its sealed hash.
   */
  verifyIntegrity(relativePath, currentContent) {
    const sealed = this.sealedTests.get(relativePath);
    if (!sealed) return { verified: true, unmanaged: true };

    const currentHash = createHash('sha256').update(currentContent).digest('hex');
    const matches = currentHash === sealed.sha256Hash;

    return {
      verified: matches,
      expectedHash: sealed.sha256Hash,
      currentHash
    };
  }
}
