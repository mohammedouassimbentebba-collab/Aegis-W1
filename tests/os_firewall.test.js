import { describe, it } from 'node:test';
import assert from 'node:assert';
import { OSFirewallShield } from '../src/perimeter/os_firewall_shield.js';
import { CapabilityTokenManager } from '../src/perimeter/capability_token_manager.js';

describe('OS Kernel Shield & Enterprise AI Firewall', () => {
  it('should block attempts to access sensitive OS directories (e.g. C:/Windows, /etc)', () => {
    const shield = new OSFirewallShield();

    const result = shield.interceptFileSystemCall({
      agentId: 'curious_agent',
      operation: 'WRITE',
      targetPath: 'C:/Windows/System32/drivers/etc/hosts'
    });

    assert.strictEqual(result.allowed, false);
    assert.strictEqual(result.errorCode, 'EPERM');
    assert.ok(result.reason.includes('sensitive operating system directory'));
  });

  it('should drop unauthorized outbound network egress requests', () => {
    const shield = new OSFirewallShield({
      allowedDomains: ['api.safety.internal']
    });

    const result = shield.interceptNetworkEgress({
      agentId: 'exfiltrator',
      destinationHost: 'dark-web-drop.xyz',
      port: 8080
    });

    assert.strictEqual(result.allowed, false);
    assert.strictEqual(result.errorCode, 'ECONNREFUSED');
    assert.ok(result.reason.includes('dropped by firewall filter'));
  });

  it('should cryptographically verify capability tokens and reject forged signatures', () => {
    const manager = new CapabilityTokenManager('secret_fortress_key');
    const validToken = manager.issueToken({
      agentId: 'worker_agent',
      allowedAction: 'READ',
      allowedResource: 'c:/sandbox/workspace/docs'
    });

    // 1. Verify authentic token
    const verifyValid = manager.verifyToken(validToken, 'READ', 'c:/sandbox/workspace/docs');
    assert.strictEqual(verifyValid.valid, true);

    // 2. Tamper with token signature
    const forgedToken = { ...validToken, signature: '0000deadbeef1111' };
    const verifyForged = manager.verifyToken(forgedToken, 'READ', 'c:/sandbox/workspace/docs');
    assert.strictEqual(verifyForged.valid, false);
    assert.ok(verifyForged.reason.includes('signature mismatch'));
  });
});
