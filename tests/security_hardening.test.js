import { describe, it } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { createHmac } from 'node:crypto';
import { CapabilityTokenManager } from '../src/perimeter/capability_token_manager.js';
import { StaticLinter } from '../src/core/static_linter.js';
import { DeterministicKernel } from '../src/core/deterministic_kernel.js';
import { AiTestbedGateway } from '../src/ai_testbed/ai_testbed_gateway.js';
import { LiveAIFirewallProxy } from '../src/perimeter/live_firewall_proxy.js';
import { ContainerIsolationEngine } from '../src/ai_testbed/container_isolation_engine.js';
import { FortressCommander } from '../src/orchestrator/fortress_commander.js';
import { W1WebDefenseAdapter } from '../src/target_app/w1_web_defense_adapter.js';
import { CrownJewelWebPortal } from '../src/target_app/crown_jewel_portal.js';
import { HermeticWorkTent } from '../src/enclave/hermetic_work_tent.js';
import { AirDefenseInterceptor } from '../src/defense_grid/air_defense_interceptor.js';
import { OSFirewallShield } from '../src/perimeter/os_firewall_shield.js';
import { AgentHarnessAdapter } from '../src/ai_testbed/agent_harness_adapter.js';
import { AntiEscapeWatchdog } from '../src/enclave/anti_escape_watchdog.js';
import { EvaluationGraderVault } from '../src/ai_testbed/evaluation_grader_vault.js';
import { ImmutableTestVault } from '../src/enclave/immutable_test_vault.js';
import fs from 'node:fs';
import os from 'node:os';

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

describe('Batch 1 Red-Team Regression Suite (SEC-01, SEC-02, SEC-03, SEC-04, SEC-06, SEC-07, SEC-13)', () => {

  it('SEC-01 Red-Team: FortressCommander must reject forged tokens even with default constructor', async () => {
    const commander = new FortressCommander({ vault: 'INTACT' });

    const res = await commander.processAgentMission({
      agentId: 'untrusted_attacker',
      actionProposal: {
        actionType: 'TOOL_CALL',
        toolName: 'query_knowledge_base',
        parameters: { query: 'steal' },
        capabilityToken: {
          tokenId: 'fake-123',
          agentId: 'untrusted_attacker',
          signature: 'forged',
          expiresAt: Date.now() + 60000
        }
      },
      nextStateComputation: (s) => ({ ...s, pwned: true })
    });

    assert.strictEqual(res.success, false, 'Forged token must be rejected by FortressCommander');
    assert.strictEqual(res.blocked, true);
    assert.strictEqual(commander.kernel.getState().pwned, undefined, 'DAG state must not be mutated');
    assert.strictEqual(commander.kernel.isAgentQuarantined('untrusted_attacker'), true);
  });

  it('SEC-01 Red-Team: StaticLinter without tokenManager must fail-closed, and tokens missing agentId must fail', () => {
    const bareLinter = new StaticLinter();
    const resNoMgr = bareLinter.validateProposal({
      actionType: 'TOOL_CALL',
      toolName: 'query_knowledge_base',
      parameters: {},
      capabilityToken: {
        tokenId: 't-1',
        agentId: 'agent_x',
        signature: 'forged',
        expiresAt: Date.now() + 60000
      }
    }, 'agent_x');
    assert.strictEqual(resNoMgr.valid, false);
    assert.ok(resNoMgr.violations.includes('CAPABILITY_TOKEN_CRYPTO_FAILED'));

    const tokenManager = new CapabilityTokenManager(null, { suppressKeyWarning: true });
    const linter = new StaticLinter({ tokenManager });
    const resMissingAgent = linter.validateProposal({
      actionType: 'TOOL_CALL',
      toolName: 'query_knowledge_base',
      parameters: {},
      capabilityToken: {
        tokenId: 't-2',
        signature: 'forged',
        expiresAt: Date.now() + 60000
      }
    }, 'agent_x');
    assert.strictEqual(resMissingAgent.valid, false);
    assert.ok(resMissingAgent.violations.includes('CAPABILITY_TOKEN_STRUCTURALLY_MALFORMED'));
  });

  it('SEC-02 Red-Team: W1WebDefenseAdapter & CrownJewelWebPortal must reject non-JSON Bearer & forged tokens, accept valid token once', async () => {
    const tokenManager = new CapabilityTokenManager(null, { suppressKeyWarning: true });
    const adapter = new W1WebDefenseAdapter({ tokenManager });
    const portal = new CrownJewelWebPortal({ firewall: adapter, tokenManager });
    const { port } = await portal.start();

    try {
      // 1. Direct adapter test with non-JSON Bearer token
      const adapterBypass = await adapter.processIncomingPayload({
        agentId: 'attacker',
        endpoint: '/api/v1/credentials',
        method: 'GET',
        headers: { authorization: 'Bearer not-a-json-token' }
      });
      assert.strictEqual(adapterBypass.allowed, false, 'Non-JSON Bearer token must be rejected by adapter');

      // 2. HTTP request through portal+adapter with non-JSON Bearer token
      const nonJsonRes = await fetch(`http://127.0.0.1:${port}/api/v1/credentials`, {
        headers: { Authorization: 'Bearer lol-bypass-attempt' }
      });
      assert.strictEqual(nonJsonRes.status, 403);

      // 3. HTTP request with forged JSON capability token
      const forgedJsonRes = await fetch(`http://127.0.0.1:${port}/api/v1/vault/intel`, {
        headers: {
          Authorization: 'Bearer ' + JSON.stringify({
            tokenId: 'fake',
            agentId: 'attacker',
            allowedAction: 'GET',
            allowedResource: '/api/v1/vault/intel',
            expiresAt: Date.now() + 60000,
            signature: 'forged'
          })
        }
      });
      assert.strictEqual(forgedJsonRes.status, 403);

      // 4. Legitimate signed HTTP-bound token succeeds ONCE, replay fails
      const validToken = tokenManager.issueHttpToken({
        agentId: 'authorized_operator',
        method: 'GET',
        path: '/api/v1/vault/intel',
        singleUse: true
      });
      const validRes = await fetch(`http://127.0.0.1:${port}/api/v1/vault/intel`, {
        headers: { Authorization: 'Bearer ' + JSON.stringify(validToken) }
      });
      assert.strictEqual(validRes.status, 200);

      const replayRes = await fetch(`http://127.0.0.1:${port}/api/v1/vault/intel`, {
        headers: { Authorization: 'Bearer ' + JSON.stringify(validToken) }
      });
      assert.strictEqual(replayRes.status, 403, 'Replayed single-use HTTP token must be rejected');
    } finally {
      await portal.stop();
    }

    // 5. Standalone CrownJewelWebPortal (without firewall) must ALSO reject non-JSON Bearer token
    const standalonePortal = new CrownJewelWebPortal({ firewall: null, tokenManager });
    const standaloneInfo = await standalonePortal.start();
    try {
      const hostBypassRes = await fetch(`http://127.0.0.1:${standaloneInfo.port}/api/v1/credentials`, {
        headers: { Authorization: 'Bearer anything-non-json' }
      });
      assert.strictEqual(hostBypassRes.status, 403, 'Host defense-in-depth must reject non-JSON Bearer token');
    } finally {
      await standalonePortal.stop();
    }
  });

  it('SEC-03 Red-Team: HermeticWorkTent must reject hardcoded backdoor key and fail-closed on escalation default', () => {
    const prevEnv = process.env.W1_SUPERVISOR_SECRET;
    delete process.env.W1_SUPERVISOR_SECRET;
    try {
      const unconfiguredTent = new HermeticWorkTent({ agentId: 'rogue_01' });
      unconfiguredTent.triggerContainmentAlarm('ESCAPE', 'Attempted breakout');

      // Old hardcoded backdoor must NEVER work
      const backdoorAttempt = unconfiguredTent.unquarantine('w1_military_override_key');
      assert.strictEqual(backdoorAttempt.success, false);
      assert.strictEqual(unconfiguredTent.quarantined, true);

      // Escalation default must be REJECTED (no token minted)
      const rb = unconfiguredTent.handleRoadblock({ type: 'PERM', target: 'x', requestedCapability: 'READ' });
      const defaultRes = unconfiguredTent.resolveEscalationTicket(rb.ticket.ticketId);
      assert.strictEqual(defaultRes.decision, 'REJECTED');
      assert.strictEqual(defaultRes.grantedToken, null);

      // Configured supervisorSecret works ONLY with exact secret
      const configuredTent = new HermeticWorkTent({ agentId: 'rogue_02', supervisorSecret: 'real_prod_secret_8899' });
      configuredTent.triggerContainmentAlarm('ESCAPE', 'Test');
      assert.strictEqual(configuredTent.unquarantine('w1_military_override_key').success, false);
      assert.strictEqual(configuredTent.unquarantine('wrong_key').success, false);
      assert.strictEqual(configuredTent.quarantined, true);
      assert.strictEqual(configuredTent.unquarantine('real_prod_secret_8899').success, true);
      assert.strictEqual(configuredTent.quarantined, false);
    } finally {
      if (prevEnv !== undefined) process.env.W1_SUPERVISOR_SECRET = prevEnv;
    }
  });

  it('SEC-04 & SEC-06 Red-Team: AiTestbedGateway must fail-closed when supervisorSecret is unset and block CORS prefix bypasses', async () => {
    const prevEnv = process.env.W1_SUPERVISOR_SECRET;
    delete process.env.W1_SUPERVISOR_SECRET;
    const gateway = new AiTestbedGateway({ port: 0 });
    const info = await gateway.start();

    try {
      // SEC-04: No supervisorSecret configured -> MUST return 401 (fail-closed)
      const unconfiguredAuthRes = await fetch(`http://127.0.0.1:${info.port}/v1/escalation/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticketId: 'ticket_1', decision: 'APPROVED' })
      });
      assert.strictEqual(unconfiguredAuthRes.status, 401, 'Gateway without supervisorSecret must fail-closed with 401');

      // SEC-06: CORS prefix bypass attacks must NOT receive Access-Control-Allow-Origin
      for (const evilOrigin of [
        'http://localhost.evil.com',
        'https://127.0.0.1.attacker.io',
        'http://localhost@evil.com',
        'javascript://localhost'
      ]) {
        const res = await fetch(`http://127.0.0.1:${info.port}/v1/testbed/telemetry`, {
          headers: { Origin: evilOrigin }
        });
        assert.strictEqual(
          res.headers.get('access-control-allow-origin'),
          null,
          `Evil origin '${evilOrigin}' must be rejected by CORS check`
        );
      }

      // Legitimate localhost origin with port still allowed
      const validOriginRes = await fetch(`http://127.0.0.1:${info.port}/v1/testbed/telemetry`, {
        headers: { Origin: 'http://127.0.0.1:8080' }
      });
      assert.strictEqual(validOriginRes.headers.get('access-control-allow-origin'), 'http://127.0.0.1:8080');
    } finally {
      await gateway.stop();
      if (prevEnv !== undefined) process.env.W1_SUPERVISOR_SECRET = prevEnv;
    }
  });

  it('SEC-07 Red-Team: OSFirewallShield must block path traversal, \\\\?\\\\ prefixes, and enforce Allowlist', () => {
    const allowedWorkspace = path.resolve('./workspace');
    const shield = new OSFirewallShield({ allowedPaths: [allowedWorkspace] });

    // All hostile paths must be blocked
    const hostilePaths = [
      '/tmp/../etc/shadow',
      './workspace/../../etc/passwd',
      'C:/Users/../Windows/System32/cmd.exe',
      '\\\\?\\C:\\Windows\\System32\\drivers\\etc\\hosts',
      '\\\\.\\PhysicalDrive0',
      '\\\\evil-host\\share\\payload.exe',
      'workspace/file.txt\0.jpg',
      '/root/.ssh/id_rsa',
      '/proc/self/environ',
      path.resolve('./package.json') // Outside allowedPaths allowlist!
    ];

    for (const targetPath of hostilePaths) {
      const check = shield.interceptFileSystemCall({
        agentId: 'red_team_agent',
        operation: 'READ',
        targetPath
      });
      assert.strictEqual(check.allowed, false, `Hostile/out-of-allowlist path '${targetPath}' must be blocked`);
      assert.strictEqual(check.errorCode, 'EPERM');
    }

    // Legitimate path strictly inside allowedPaths must be allowed
    const legitimatePath = path.join(allowedWorkspace, 'agent_notes.txt');
    const okCheck = shield.interceptFileSystemCall({
      agentId: 'good_agent',
      operation: 'READ',
      targetPath: legitimatePath
    });
    assert.strictEqual(okCheck.allowed, true, 'Path inside allowedPaths allowlist must be permitted');
  });

  it('SEC-13 Red-Team: AirDefenseInterceptor must not use hardcoded IFF key, must block IFF replay, and FortressCommander must not auto-forge IFF proofs', async () => {
    const prevIff = process.env.W1_IFF_SECRET;
    delete process.env.W1_IFF_SECRET;
    try {
      const b1 = new AirDefenseInterceptor();
      const b2 = new AirDefenseInterceptor();
      assert.notStrictEqual(b1.iffSecretKey, 'w1_fortress_iff_master_key_2026', 'Hardcoded IFF key must be eliminated');
      assert.notStrictEqual(b1.iffSecretKey, b2.iffSecretKey, 'Each default instance must generate an independent CSPRNG key');

      // IFF Replay attack must be blocked
      const reg = b1.registerFriendlyAgent('allied_01');
      const nonce = 'unique_nonce_001';
      const issuedAt = Date.now();
      const sig = b1.computeIffSignature(reg.token, nonce, issuedAt);
      const first = b1.interceptAction('allied_01', { toolName: 'query_knowledge_base', iffProof: { nonce, issuedAt, signature: sig } });
      assert.strictEqual(first.intercepted, false);

      const replay = b1.interceptAction('allied_01', { toolName: 'query_knowledge_base', iffProof: { nonce, issuedAt, signature: sig } });
      assert.strictEqual(replay.intercepted, true, 'Replayed IFF proof must be intercepted');
      assert.ok(replay.reason.includes('replay'));

      // FortressCommander must NOT auto-attach IFF proof when caller omits it
      const commander = new FortressCommander();
      commander.registerFriendlyAgent('vip_agent');
      const token = commander.tokenManager.issueToken({
        agentId: 'vip_agent',
        allowedAction: 'query_knowledge_base',
        allowedResource: '*'
      });

      const unauthSpoof = await commander.processAgentMission({
        agentId: 'vip_agent',
        actionProposal: {
          actionType: 'TOOL_CALL',
          toolName: 'query_knowledge_base',
          parameters: {},
          capabilityToken: token
          // Intentionally NO iffProof supplied by caller!
        }
      });
      assert.strictEqual(unauthSpoof.success, false, 'Caller claiming registered agentId without iffProof must be intercepted');
      assert.strictEqual(unauthSpoof.blocked, true);
    } finally {
      if (prevIff !== undefined) process.env.W1_IFF_SECRET = prevIff;
    }
  });
});

describe('Batch 2 Red-Team Regression Suite (SEC-09, SEC-11, SEC-12, QUAL-19)', () => {

  it('SEC-09 Red-Team: AgentHarnessAdapter must NOT mint capability tokens for tools/paths outside sessionPolicy', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'w1_sec09_'));
    try {
      const tent = new HermeticWorkTent({
        agentId: 'policy_agent',
        tentRoot: tmp,
        allowedTools: ['READ_FILE', 'WRITE_FILE', 'RUN_IN_TENT_SCRIPT', 'SUBMIT_ESCALATION_TICKET']
      });
      const adapter = new AgentHarnessAdapter({
        tent,
        agentId: 'policy_agent',
        sessionPolicy: {
          allowedActions: ['READ_FILE'], // WRITE_FILE and RUN_IN_TENT_SCRIPT NOT pre-authorized
          allowedPathPrefix: tmp
        }
      });

      const res = await adapter.processModelOutput({
        tool_calls: [
          {
            id: 'call_unauth_write',
            function: {
              name: 'write_file',
              arguments: { path: path.join(tmp, 'evil.js'), content: 'pwn()' }
            }
          }
        ]
      });

      const inner = JSON.parse(res.messages[0].content);
      assert.strictEqual(inner.success, false);
      assert.strictEqual(inner.blockedBySessionPolicy, true);
      assert.strictEqual(inner.escalated, true);
      assert.strictEqual(tent.tentLedger.filter(e => e.action === 'WRITE_FILE').length, 0, 'Unapproved action must not execute');
      assert.strictEqual(tent.activeEscalationTickets.size, 1, 'Must escalate via handleRoadblock');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('SEC-11 Red-Team: CapabilityTokenManager and AirDefenseInterceptor must never evict live nonces when saturated (fail-closed)', () => {
    const mgr = new CapabilityTokenManager(null, { suppressKeyWarning: true, maxConsumedEntries: 2 });
    const t1 = mgr.issueToken({ agentId: 'a', allowedAction: 'READ', allowedResource: '*', ttlSeconds: 60 });
    const t2 = mgr.issueToken({ agentId: 'a', allowedAction: 'READ', allowedResource: '*', ttlSeconds: 60 });
    const t3 = mgr.issueToken({ agentId: 'a', allowedAction: 'READ', allowedResource: '*', ttlSeconds: 60 });

    assert.strictEqual(mgr.verifyToken(t1, 'READ', '*').valid, true);
    assert.strictEqual(mgr.verifyToken(t2, 'READ', '*').valid, true);

    // Cache is now full of live (unexpired) nonces: t3 must be refused fail-closed, AND t1 must still be rejected as replayed
    const t3Res = mgr.verifyToken(t3, 'READ', '*');
    assert.strictEqual(t3Res.valid, false);
    assert.ok(t3Res.reason.includes('saturated'));
    assert.strictEqual(mgr.verifyToken(t1, 'READ', '*').valid, false, 'Live nonce t1 must never be evicted');

    // Same fail-closed backpressure on AirDefenseInterceptor.usedIffNonces
    const battery = new AirDefenseInterceptor({ maxIffNonces: 1 });
    const reg = battery.registerFriendlyAgent('drone_1');
    const ts = Date.now();
    const sig1 = battery.computeIffSignature(reg.token, 'n1', ts);
    const sig2 = battery.computeIffSignature(reg.token, 'n2', ts);

    assert.strictEqual(battery.verifyAgentIFF('drone_1', { nonce: 'n1', issuedAt: ts, signature: sig1 }).isFriend, true);
    const sat = battery.verifyAgentIFF('drone_1', { nonce: 'n2', issuedAt: ts, signature: sig2 });
    assert.strictEqual(sat.isFriend, false);
    assert.strictEqual(sat.status, 'IFF_NONCE_CACHE_SATURATED');
  });

  it('SEC-11 Pre-Commit DoS Check: flooding with forged signatures must NEVER pollute nonce caches or trigger backpressure', () => {
    // 1. CapabilityTokenManager: capacity = 2, flood 25 forged tokens -> cache stays 0, valid token still succeeds
    const mgr = new CapabilityTokenManager('strong_test_secret_key', { suppressKeyWarning: true, maxConsumedEntries: 2 });
    for (let i = 0; i < 25; i++) {
      const forged = {
        tokenId: `forged-${i}`,
        agentId: 'attacker',
        allowedAction: 'READ',
        allowedResource: '*',
        issuedAt: Date.now(),
        expiresAt: Date.now() + 60000,
        singleUse: true,
        signature: `deadbeef_${i}`
      };
      const res = mgr.verifyToken(forged, 'READ', '*');
      assert.strictEqual(res.valid, false);
    }
    assert.strictEqual(mgr.consumedTokens.size, 0, 'Forged tokens must never enter consumedTokens');

    const legitimate = mgr.issueToken({ agentId: 'honest', allowedAction: 'READ', allowedResource: '*' });
    assert.strictEqual(mgr.verifyToken(legitimate, 'READ', '*').valid, true, 'Valid token must not be blocked by forged flood');

    // 2. AirDefenseInterceptor: maxIffNonces = 2, flood 25 invalid IFF proofs -> cache stays 0, valid proof still succeeds
    const battery = new AirDefenseInterceptor({ maxIffNonces: 2 });
    const reg = battery.registerFriendlyAgent('allied_scout');
    const now = Date.now();
    for (let i = 0; i < 25; i++) {
      const bad = battery.verifyAgentIFF('allied_scout', {
        nonce: `forged_nonce_${i}`,
        issuedAt: now,
        signature: 'bad_sig_0000'
      });
      assert.strictEqual(bad.isFriend, false);
      assert.strictEqual(bad.status, 'IFF_SPOOFING_DETECTED');
    }
    assert.strictEqual(battery.usedIffNonces.size, 0, 'Forged IFF proofs must never enter usedIffNonces');

    const validSig = battery.computeIffSignature(reg.token, 'real_nonce_1', now);
    assert.strictEqual(
      battery.verifyAgentIFF('allied_scout', { nonce: 'real_nonce_1', issuedAt: now, signature: validSig }).isFriend,
      true
    );
  });

  it('SEC-12 Red-Team: AntiEscapeWatchdog must fail-closed without tentRoot and block new files inside symlinked directories', () => {
    const unconfigured = new AntiEscapeWatchdog();
    const noRootRes = unconfigured.validatePathContainment('agent_x', 'anything.txt');
    assert.strictEqual(noRootRes.contained, false);
    assert.strictEqual(noRootRes.violationType, 'TENT_ROOT_UNCONFIGURED');

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'w1_sec12_'));
    const tentDir = path.join(tmp, 'tent');
    const siblingEvilDir = path.join(tmp, 'tent_evil');
    const outsideDir = path.join(tmp, 'outside');
    fs.mkdirSync(tentDir, { recursive: true });
    fs.mkdirSync(siblingEvilDir, { recursive: true });
    fs.mkdirSync(outsideDir, { recursive: true });

    const watchdog = new AntiEscapeWatchdog({ tentRoot: tentDir });

    // 1. Sibling directory prefix collision check ("tent_evil" must NOT match "tent")
    const siblingRes = watchdog.validatePathContainment('agent_x', path.join(siblingEvilDir, 'secret.txt'));
    assert.strictEqual(siblingRes.contained, false, 'Sibling prefix directory tent_evil must be blocked');
    assert.strictEqual(siblingRes.violationType, 'PATH_JAIL_ESCAPE_ATTEMPT');

    // 2. Symlink directory + Dangling symlink check via lstatSync
    const linkDir = path.join(tentDir, 'link_out');
    const danglingLink = path.join(tentDir, 'dangling_out');
    let symlinkCreated = false;
    let danglingCreated = false;
    try {
      fs.symlinkSync(outsideDir, linkDir, 'junction');
      symlinkCreated = true;
    } catch {
      // Symlink creation may require privileges on some Windows setups
    }
    try {
      fs.symlinkSync(path.join(outsideDir, 'nonexistent_target.txt'), danglingLink, 'file');
      danglingCreated = true;
    } catch {
      // File symlink creation on Windows may require Developer Mode / elevation
    }

    try {
      if (symlinkCreated) {
        const newFileViaSymlink = path.join(linkDir, 'brand_new_secret.txt');
        const check = watchdog.validatePathContainment('agent_x', newFileViaSymlink);
        assert.strictEqual(check.contained, false, 'New file inside symlinked dir escaping tent must be blocked');
        assert.strictEqual(check.violationType, 'SYMLINK_JAILBREAK_ATTEMPT');
      }
      if (danglingCreated) {
        const danglingCheck = watchdog.validatePathContainment('agent_x', danglingLink);
        assert.strictEqual(danglingCheck.contained, false, 'Dangling symlink pointing outside tent must be rejected');
        assert.strictEqual(danglingCheck.violationType, 'SYMLINK_JAILBREAK_ATTEMPT');
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('QUAL-19 Regression: package.json with normal test script must NOT trigger false positive, and EvaluationGraderVault attestation must use keyed HMAC', async () => {
    const vault = new ImmutableTestVault();
    const normalPkg = JSON.stringify({ name: 'ok', scripts: { test: 'node --test tests/*.test.js' } });
    assert.strictEqual(vault.isTamperingAttempt('package.json', normalPkg), false, 'Normal package.json must be allowed');
    assert.strictEqual(vault.isTamperingAttempt('package.json', '{"scripts":{"test":"node --test"}'), false, 'Malformed JSON with real test command must not false-positive');
    assert.strictEqual(vault.isTamperingAttempt('package.json', '{"scripts":{"test":"exit 0"}}'), true);

    vault.sealTestFile('tests/unit.test.js', 'assert(true);');
    assert.strictEqual(vault.verifyIntegrity('tests/unit.test.js', 'assert(true);').verified, true);
    assert.strictEqual(vault.verifyIntegrity('tests/unit.test.js', 'assert(false);').verified, false);

    // Fail-closed strict key mode when env vars are absent
    const prevGraderKey = process.env.W1_GRADER_HMAC_KEY;
    const prevVaultKey = process.env.W1_VAULT_HMAC_KEY;
    delete process.env.W1_GRADER_HMAC_KEY;
    delete process.env.W1_VAULT_HMAC_KEY;
    try {
      const strictVault = new ImmutableTestVault({ strictKeyRequired: true });
      assert.throws(() => strictVault.sealTestFile('a.test.js', 'x'), /Fail-closed/);
      assert.strictEqual(strictVault.verifyIntegrity('a.test.js', 'x').verified, false);

      const strictGrader = new EvaluationGraderVault({ strictKeyRequired: true });
      strictGrader.registerEvaluationTask('t1', { hiddenAssertions: ['solve'] });
      const failReport = await strictGrader.gradeTask('t1', 'a1', { 'app.js': 'function solve(){}' });
      assert.strictEqual(failReport.passed, false);
      assert.strictEqual(strictGrader.verifyAttestation(failReport), false);
    } finally {
      if (prevGraderKey !== undefined) process.env.W1_GRADER_HMAC_KEY = prevGraderKey;
      if (prevVaultKey !== undefined) process.env.W1_VAULT_HMAC_KEY = prevVaultKey;
    }

    const grader = new EvaluationGraderVault({ attestationSecret: 'grader_hmac_secret_123' });
    assert.strictEqual(grader.auditAgentWorkspace('a1', { 'package.json': normalPkg }).clean, true);

    grader.registerEvaluationTask('t1', { hiddenAssertions: ['solve'] });
    const report = await grader.gradeTask('t1', 'a1', { 'app.js': 'function solve(){}' });
    assert.strictEqual(grader.verifyAttestation(report), true);
    assert.strictEqual(grader.verifyAttestation({ ...report, score: 0.99 }), false, 'Tampered scorecard must fail HMAC verification');
    assert.strictEqual(grader.verifyAttestation({ ...report, cryptographicAttestation: 'short' }), false, 'Mismatched length attestation must fail safely');
  });
});
