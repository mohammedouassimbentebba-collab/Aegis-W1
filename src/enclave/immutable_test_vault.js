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

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';

export class ImmutableTestVault {
  constructor(options = {}) {
    this.name = 'W1_Immutable_Test_Vault';
    this.sealedTests = new Map(); // testPath -> { content, sha256Hash, hmacSignature, sealedAt }
    this.tamperAttempts = [];

    // QUAL-19: Keyed HMAC sealing secret (zero hardcoded fallback secret; fail-closed if explicitly null/missing under strictKeyRequired)
    if (options.sealSecret !== undefined) {
      this.sealSecret = options.sealSecret || null;
    } else if (process.env.W1_VAULT_HMAC_KEY) {
      this.sealSecret = process.env.W1_VAULT_HMAC_KEY;
    } else if (options.strictKeyRequired) {
      this.sealSecret = null;
    } else {
      this.sealSecret = randomBytes(32).toString('hex');
    }
  }

  /**
   * Seals a test file into the immutable vault. Only human/admin keys can register tests.
   */
  sealTestFile(relativePath, fileContent) {
    if (!this.sealSecret) {
      throw new Error('Fail-closed: ImmutableTestVault requires sealSecret or W1_VAULT_HMAC_KEY.');
    }
    const hash = createHash('sha256').update(fileContent).digest('hex');
    const hmacSignature = createHmac('sha256', this.sealSecret)
      .update(`${relativePath}\0${fileContent}`)
      .digest('hex');
    this.sealedTests.set(relativePath, {
      content: fileContent,
      sha256Hash: hash,
      hmacSignature,
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
        // Fallback to strict regex if malformed JSON (QUAL-19: no empty-string match on normal test scripts)
        const gamedTest = /"test"\s*:\s*"(?:\s*|true|exit\s+0|echo\b[^"]*)"/i.test(newContent);
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
   * Cryptographically verifies that a test file content matches its sealed HMAC & hash in constant time (QUAL-19).
   */
  verifyIntegrity(relativePath, currentContent) {
    if (!this.sealSecret) {
      return { verified: false, reason: 'Fail-closed: ImmutableTestVault sealSecret is missing.' };
    }
    const sealed = this.sealedTests.get(relativePath);
    if (!sealed) return { verified: true, unmanaged: true };

    const currentHash = createHash('sha256').update(currentContent).digest('hex');
    const expectedHmac = createHmac('sha256', this.sealSecret)
      .update(`${relativePath}\0${currentContent}`)
      .digest('hex');

    const a = Buffer.from(expectedHmac, 'utf8');
    const b = Buffer.from(sealed.hmacSignature || '', 'utf8');
    let matches = false;
    if (a.length !== b.length) {
      timingSafeEqual(a, a);
    } else {
      matches = timingSafeEqual(a, b);
    }

    return {
      verified: matches,
      expectedHash: sealed.sha256Hash,
      currentHash
    };
  }
}
