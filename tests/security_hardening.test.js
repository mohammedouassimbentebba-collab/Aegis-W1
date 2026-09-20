import { describe, it } from 'node:test';
import assert from 'node:assert';
import { CapabilityTokenManager } from '../src/perimeter/capability_token_manager.js';
import { StaticLinter } from '../src/core/static_linter.js';
import { DeterministicKernel } from '../src/core/deterministic_kernel.js';
import { AiTestbedGateway } from '../src/ai_testbed/ai_testbed_gateway.js';
import { LiveAIFirewallProxy } from '../src/perimeter/live_firewall_proxy.js';
import { ContainerIsolationEngine } from '../src/ai_testbed/container_isolation_engine.js';

describe('W1™ Critical Security Hardening & Vulnerability Remediation Suite', () => {

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Remediation 1: Cryptographic Capability Token HMAC Verification
  // Proves the audit finding: Forged tokens with signature: "forged" must be REJECTED!
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  it('Remediation 1 (CRITICAL): StaticLinter & DeterministicKernel must reject forged capability tokens', () => {
    const tokenManager = new CapabilityTokenManager(null, { suppressKeyWarning: true });
    const linter = new StaticLinter({ tokenManager });

    // The exact attack demonstrated in the cybersecurity audit:
    const forgedToken = {
      tokenId: 'forged-uuid-001',
      agentId: 'attacker_agent',
      allowedAction: 'query_knowledge_base',
      allowedResource: '*',
      issuedAt: Date.now(),
      expiresAt: Date.now() + 60000,
      singleUse: true,
      signature: 'forged' // Untrusted attacker supplied signature
    };

    const forgedProposal = {
      actionType: 'TOOL_CALL',
      toolName: 'query_knowledge_base',
      parameters: { query: 'reconnaissance' },
      capabilityToken: forgedToken
    };

    // 1. StaticLinter must reject it cryptographically
    const lintResult = linter.validateProposal(forgedProposal, 'attacker_agent');
    assert.strictEqual(lintResult.valid, false, 'Forged token must not pass validation');
    assert.ok(
      lintResult.violations.includes('CAPABILITY_TOKEN_CRYPTO_FAILED'),
      'Must flag CAPABILITY_TOKEN_CRYPTO_FAILED violation'
    );

    // 2. DeterministicKernel must reject it and automatically quarantine the attacker
    const kernel = new DeterministicKernel({ status: 'ACTIVE' }, { tokenManager });
    const execResult = kernel.executeTransaction({
      agentId: 'attacker_agent',
      proposal: forgedProposal,
      nextStateComputation: (s) => s
    });

    assert.strictEqual(execResult.success, false);
    assert.strictEqual(execResult.blocked, true);
    assert.ok(kernel.isAgentQuarantined('attacker_agent'), 'Attacker agent must be immediately quarantined');
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Remediation 2: Subject Identity Binding (Anti-Token-Theft)
  // Proves that Agent B cannot execute transactions using Agent A's token.
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  it('Remediation 2 (CRITICAL): Token must be bound to agentId; cross-agent token theft is rejected', () => {
    const tokenManager = new CapabilityTokenManager(null, { suppressKeyWarning: true });
    const kernel = new DeterministicKernel({ status: 'ACTIVE' }, { tokenManager });

    // Issue legitimate token for Agent Alice
    const aliceToken = tokenManager.issueToken({
      agentId: 'agent_alice',
      allowedAction: 'query_knowledge_base',
      allowedResource: '*'
    });

    // Agent Bob attempts to use Alice's token
    const stolenProposal = {
      actionType: 'TOOL_CALL',
      toolName: 'query_knowledge_base',
      parameters: { query: 'test' },
      capabilityToken: aliceToken
    };

    const result = kernel.executeTransaction({
      agentId: 'agent_bob', // Mismatch!
      proposal: stolenProposal,
      nextStateComputation: (s) => s
    });

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.blocked, true);
    assert.ok(result.violations.includes('CAPABILITY_TOKEN_SUBJECT_MISMATCH'));
    assert.ok(kernel.isAgentQuarantined('agent_bob'), 'Agent Bob must be quarantined for token theft');
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Remediation 3: Monotonic Single-Use Token Nonce Tracking (Replay Prevention)
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  it('Remediation 3 (HIGH): Replaying a consumed single-use token must be blocked on the 2nd transaction', () => {
    const tokenManager = new CapabilityTokenManager(null, { suppressKeyWarning: true });
    const kernel = new DeterministicKernel({ counter: 0 }, { tokenManager });

    const legitimateToken = tokenManager.issueToken({
      agentId: 'worker_01',
      allowedAction: 'query_knowledge_base',
      allowedResource: '*',
      singleUse: true
    });

    const proposal = {
      actionType: 'TOOL_CALL',
      toolName: 'query_knowledge_base',
      parameters: { query: 'update' },
      capabilityToken: legitimateToken
    };

    // First commit: must succeed
    const firstCommit = kernel.executeTransaction({
      agentId: 'worker_01',
      proposal,
      nextStateComputation: (s) => ({ counter: s.counter + 1 })
    });
    assert.strictEqual(firstCommit.success, true);
    assert.strictEqual(kernel.getState().counter, 1);

    // Second commit with identical token: must be rejected as replay
    const secondCommit = kernel.executeTransaction({
      agentId: 'worker_01',
      proposal,
      nextStateComputation: (s) => ({ counter: s.counter + 1 })
    });
    assert.strictEqual(secondCommit.success, false);
    assert.strictEqual(secondCommit.blocked, true);
    assert.ok(secondCommit.reason.includes('replay') || secondCommit.reason.includes('exhausted'));
    assert.strictEqual(kernel.getState().counter, 1, 'State must not be mutated by replay attack');
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Remediation 4: CORS Restriction on Local Testbed Gateway
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  it('Remediation 4 (HIGH): Gateway must reject external origins and only allow localhost CORS', async () => {
    const gateway = new AiTestbedGateway({ port: 0 });
    const info = await gateway.start();

    try {
      // Test external untrusted origin
      const externalRes = await fetch(`http://127.0.0.1:${info.port}/v1/testbed/telemetry`, {
        method: 'GET',
        headers: { 'Origin': 'https://evil-attacker-site.com' }
      });
      assert.strictEqual(
        externalRes.headers.get('access-control-allow-origin'),
        null,
        'External origin must NOT receive Access-Control-Allow-Origin'
      );

      // Test localhost origin
      const localRes = await fetch(`http://127.0.0.1:${info.port}/v1/testbed/telemetry`, {
        method: 'GET',
        headers: { 'Origin': 'http://localhost:3000' }
      });
      assert.strictEqual(
        localRes.headers.get('access-control-allow-origin'),
        'http://localhost:3000',
        'Localhost origin must be permitted'
      );
    } finally {
      await gateway.stop();
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Remediation 5: Supervisor Authentication on Escalation Endpoint (Fail-Closed)
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  it('Remediation 5 (HIGH): Escalation endpoint must reject unauthenticated callers with 401', async () => {
    const gateway = new AiTestbedGateway({
      port: 0,
      supervisorSecret: 'SUPER_SECRET_SUPERVISOR_KEY_99'
    });
    const info = await gateway.start();

    try {
      // Unauthenticated request: must receive 401 Unauthorized
      const unauthRes = await fetch(`http://127.0.0.1:${info.port}/v1/escalation/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticketId: 'TICKET-01' })
      });
      assert.strictEqual(unauthRes.status, 401, 'Unauthenticated escalation resolution must be 401');

      // Authenticated with valid Bearer token
      const authRes = await fetch(`http://127.0.0.1:${info.port}/v1/escalation/resolve`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer SUPER_SECRET_SUPERVISOR_KEY_99'
        },
        body: JSON.stringify({ ticketId: 'TICKET-NONEXISTENT', decision: 'REJECTED' })
      });
      // Should not be 401 (auth passed, 404 ticket not found)
      assert.notStrictEqual(authRes.status, 401);
    } finally {
      await gateway.stop();
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Remediation 6: Multi-Tenant Workspace & Path Traversal Sanitization
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  it('Remediation 6 (HIGH): Gateway must isolate per-agent workspaces and sanitize agent IDs', () => {
    const gateway = new AiTestbedGateway();

    // Normal agent
    const harness1 = gateway.getOrCreateHarness('agent_alpha');
    const tent1 = gateway.activeAgents.get('agent_alpha').tent;

    // Second agent
    const harness2 = gateway.getOrCreateHarness('agent_beta');
    const tent2 = gateway.activeAgents.get('agent_beta').tent;

    assert.notStrictEqual(tent1.tentRoot, tent2.tentRoot, 'Tents must not share the same tentRoot directory');
    assert.ok(tent1.tentRoot.includes('tent_agent_alpha'));
    assert.ok(tent2.tentRoot.includes('tent_agent_beta'));

    // Path traversal attempt in agent ID: ../../etc
    const maliciousHarness = gateway.getOrCreateHarness('../../etc/evil');
    const sanitizedTent = gateway.activeAgents.get('______etc_evil').tent;
    assert.ok(sanitizedTent, 'Sanitized agent entry must exist');
    assert.ok(!sanitizedTent.tentRoot.includes('..'), 'Tent root must not contain directory traversal sequences');
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Remediation 7: Payload Size Limit & DoS Protection in Proxy
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  it('Remediation 7 (HIGH): LiveAIFirewallProxy must reject oversized payloads with HTTP 413', async () => {
    const mockCommander = {
      processAgentMission: async () => ({ success: true })
    };

    const proxy = new LiveAIFirewallProxy(mockCommander, {
      maxBodyBytes: 1024 // Set small 1KB threshold for test
    });
    const info = await proxy.start();

    try {
      // Send 5KB oversized body
      const hugeData = 'A'.repeat(5 * 1024);
      const res = await fetch(info.address, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: hugeData })
      });

      assert.strictEqual(res.status, 413, 'Oversized request body must return HTTP 413 Payload Too Large');
    } finally {
      await proxy.stop();
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Remediation 8: Container DAC_OVERRIDE Capability Removal
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  it('Remediation 8 (MEDIUM): ContainerIsolationEngine must not grant DAC_OVERRIDE in relaxed mode', () => {
    const engine = new ContainerIsolationEngine();
    const config = engine.generateDockerComposeConfig({
      agentId: 'eval_agent',
      relaxedSecurity: true
    });

    const svc = config.services['agent_eval_agent'];
    assert.ok(!svc.cap_add.includes('DAC_OVERRIDE'), 'DAC_OVERRIDE must never be granted');
    assert.ok(!svc.cap_add.includes('SYS_ADMIN'), 'SYS_ADMIN must never be granted');

    // Verification check should flag DAC_OVERRIDE
    const badConfig = {
      privileged: false,
      cap_drop: ['ALL'],
      cap_add: ['DAC_OVERRIDE']
    };
    const check = engine.verifyContainerContainment(badConfig);
    assert.strictEqual(check.compliant, false);
    assert.ok(check.violations.some(v => v.includes('DAC_OVERRIDE_FORBIDDEN')));
  });
});
