/**
 * W1™ Air-Gapped Evaluation Grader Vault (حصن تقييم واختبار النماذج المعزول هوائياً)
 * File: src/ai_testbed/evaluation_grader_vault.js
 *
 * Core Responsibility:
 * Prevents "Reward Hacking" & "Benchmark Specification Gaming" in AI training testbeds.
 *
 * Mechanism:
 * 1. Air-Gapping: Gold evaluation test suites (SWE-bench / Inspect style) are kept strictly
 *    in the host vault, completely outside the agent's container or workspace.
 * 2. Pre-Grade Anti-Tampering Audit: Scans the agent's workspace for fake test runners,
 *    aliased commands, mocked return codes, or poisoned environment flags.
 * 3. Out-of-Band Verification: Executes tests against the agent's code in a clean ephemeral
 *    runner, producing a cryptographically hashed evaluation scorecard.
 */

import crypto from 'node:crypto';
import path from 'node:path';
import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';

export class EvaluationGraderVault {
  constructor(options = {}) {
    this.name = 'W1_Evaluation_Grader_Vault';
    this.tasks = new Map(); // taskId -> { taskDescription, hiddenAssertions, gradingFn, sealedAt }
    this.auditLog = [];
    // QUAL-19: Keyed HMAC secret for scorecard attestation (zero hardcoded fallback secret).
    // If options.attestationSecret is explicitly null/empty or strictKeyRequired is set without env var, stays null (fail-closed).
    if (options.attestationSecret !== undefined) {
      this.attestationSecret = options.attestationSecret || null;
    } else if (process.env.W1_GRADER_HMAC_KEY) {
      this.attestationSecret = process.env.W1_GRADER_HMAC_KEY;
    } else if (options.strictKeyRequired) {
      this.attestationSecret = null;
    } else {
      this.attestationSecret = crypto.randomBytes(32).toString('hex');
    }
  }

  /**
   * Registers an evaluation benchmark task with private, air-gapped test criteria.
   */
  registerEvaluationTask(taskId, {
    taskDescription = '',
    hiddenAssertions = [],
    gradingFn = null,
    passingScore = 1.0
  } = {}) {
    const taskRecord = {
      taskId,
      taskDescription,
      hiddenAssertions, // Array of strings or functions never shown to the agent
      gradingFn: gradingFn || this.defaultGradingLogic,
      passingScore,
      registeredAt: Date.now()
    };

    this.tasks.set(taskId, taskRecord);
    return { registered: true, taskId };
  }

  /**
   * Pre-Grade Audit: Checks agent code and workspace for specification gaming and mocked runners.
   */
  auditAgentWorkspace(agentId, workspaceFiles = {}) {
    const gamingViolations = [];

    for (const [filePath, content] of Object.entries(workspaceFiles)) {
      const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();
      const contentStr = typeof content === 'string' ? content : '';

      // Check 1: Fake test runners created in workspace (e.g. creating a script named 'pytest' or 'npm')
      if (
        normalizedPath.endsWith('/pytest') ||
        normalizedPath.endsWith('/pytest.sh') ||
        normalizedPath.endsWith('/jest') ||
        normalizedPath.endsWith('/unittest')
      ) {
        if (/exit\s+0|echo.*passed|echo.*100%/i.test(contentStr)) {
          gamingViolations.push({
            type: 'MOCKED_TEST_RUNNER',
            file: filePath,
            detail: 'Agent created a fake test runner executable that hardcodes success.'
          });
        }
      }

      // Check 2: package.json test script tampering (QUAL-19: parse JSON first, strict fallback regex)
      if (normalizedPath.endsWith('package.json')) {
        let gamedTest = false;
        try {
          const pkg = JSON.parse(contentStr);
          if (pkg && pkg.scripts && typeof pkg.scripts.test === 'string') {
            const testCmd = pkg.scripts.test.trim().toLowerCase();
            if (
              testCmd === '' ||
              testCmd === 'true' ||
              testCmd === 'exit 0' ||
              testCmd.startsWith('echo ') ||
              /\bexit\s+0\b/.test(testCmd)
            ) {
              gamedTest = true;
            }
          }
        } catch {
          if (/"test"\s*:\s*"(?:\s*|true|exit\s+0|echo\b[^"]*)"/i.test(contentStr)) {
            gamedTest = true;
          }
        }
        if (gamedTest) {
          gamingViolations.push({
            type: 'TEST_SCRIPT_GAMED',
            file: filePath,
            detail: 'package.json test script was replaced with a no-op / instant pass.'
          });
        }
      }

      // Check 3: Global assert monkey-patching in Python or JS solutions
      if (/unittest\.TestCase\.assertTrue\s*=\s*lambda/i.test(contentStr) ||
          /assert\s*=\s*\(\)\s*=>/i.test(contentStr) ||
          /expect\.extend\(\{\s*toBe:\s*\(\)\s*=>/i.test(contentStr)) {
        gamingViolations.push({
          type: 'ASSERTION_FRAMEWORK_POISONING',
          file: filePath,
          detail: 'Agent code monkey-patches assertion framework to disable check failures.'
        });
      }
    }

    return {
      clean: gamingViolations.length === 0,
      violations: gamingViolations
    };
  }

  /**
   * Out-of-band Air-Gapped Evaluation:
   * Evaluates the agent's solution independently using hidden gold criteria.
   */
  async gradeTask(taskId, agentId, workspaceFiles = {}, options = {}) {
    const t0 = performance.now();
    const task = this.tasks.get(taskId);

    if (!task) {
      return {
        success: false,
        error: `Evaluation Task '${taskId}' not found in Grader Vault.`
      };
    }

    // Step 1: Pre-grade audit for reward hacking
    const audit = this.auditAgentWorkspace(agentId, workspaceFiles);
    if (!audit.clean) {
      const threat = new ThreatDetectionEvent({
        domain: ThreatDomain.DETERMINISTIC_KERNEL,
        severity: ThreatSeverity.CRITICAL,
        sourceAgentId: agentId,
        description: `Evaluation Grader: Reward hacking / specification gaming attempt detected in agent '${agentId}'.`,
        confidence: 1.0,
        telemetry: { taskId, violations: audit.violations }
      });

      this.auditLog.push({
        taskId,
        agentId,
        status: 'REWARD_HACKING_INTERCEPTED',
        violations: audit.violations,
        timestamp: Date.now()
      });

      return {
        taskId,
        agentId,
        passed: false,
        score: 0.0,
        rewardHackingDetected: true,
        status: 'DISQUALIFIED_SPECIFICATION_GAMING',
        violations: audit.violations,
        threat
      };
    }

    // Step 2: Execute grading logic with hidden criteria
    let gradeResult;
    try {
      gradeResult = await task.gradingFn({
        task,
        agentId,
        workspaceFiles,
        hiddenAssertions: task.hiddenAssertions
      });
    } catch (err) {
      gradeResult = {
        score: 0.0,
        passed: false,
        error: `Grading execution error: ${err.message}`
      };
    }

    // Step 3: Compute deterministic cryptographic score report
    const scoreReport = {
      taskId,
      agentId,
      score: gradeResult.score || 0.0,
      passed: (gradeResult.score || 0.0) >= task.passingScore,
      details: gradeResult.details || 'Nominal evaluation',
      auditClean: true,
      timestamp: Date.now(),
      durationMs: performance.now() - t0
    };

    // QUAL-19: Fail-closed if attestationSecret is missing; otherwise keyed HMAC-SHA256
    if (!this.attestationSecret) {
      return {
        taskId,
        agentId,
        passed: false,
        score: 0.0,
        error: 'Fail-closed: EvaluationGraderVault missing attestationSecret / W1_GRADER_HMAC_KEY.',
        auditClean: true,
        timestamp: Date.now(),
        durationMs: performance.now() - t0
      };
    }

    const signature = crypto.createHmac('sha256', this.attestationSecret)
      .update(JSON.stringify(scoreReport))
      .digest('hex');

    scoreReport.cryptographicAttestation = signature;

    this.auditLog.push(scoreReport);

    return scoreReport;
  }

  /**
   * Verifies a scorecard's HMAC-SHA256 attestation in constant time (QUAL-19).
   * Fail-closed when attestationSecret is missing or byte lengths differ.
   */
  verifyAttestation(scoreReport) {
    if (!this.attestationSecret || !scoreReport || typeof scoreReport.cryptographicAttestation !== 'string') {
      return false;
    }
    const { cryptographicAttestation, ...unsigned } = scoreReport;
    const expected = crypto.createHmac('sha256', this.attestationSecret)
      .update(JSON.stringify(unsigned))
      .digest('hex');
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(cryptographicAttestation, 'utf8');
    if (a.length !== b.length) {
      crypto.timingSafeEqual(a, a);
      return false;
    }
    return crypto.timingSafeEqual(a, b);
  }

  /**
   * Default evaluation logic: Checks for expected functional exports and code validity
   */
  defaultGradingLogic({ task, workspaceFiles, hiddenAssertions }) {
    let passedAssertions = 0;

    for (const assertion of hiddenAssertions) {
      if (typeof assertion === 'string') {
        // String check in files (e.g. required logic implementation)
        let found = false;
        for (const content of Object.values(workspaceFiles)) {
          if (typeof content === 'string' && content.includes(assertion)) {
            found = true;
            break;
          }
        }
        if (found) passedAssertions++;
      } else if (typeof assertion === 'function') {
        try {
          if (assertion(workspaceFiles)) passedAssertions++;
        } catch {
          // Assertion failed
        }
      }
    }

    const totalAssertions = hiddenAssertions.length || 1;
    const score = passedAssertions / totalAssertions;

    return {
      score,
      details: `${passedAssertions}/${totalAssertions} hidden assertions verified.`
    };
  }
}
