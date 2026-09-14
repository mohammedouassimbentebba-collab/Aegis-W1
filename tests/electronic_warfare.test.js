import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ElectronicWarfareOfficer } from '../src/defense_grid/electronic_warfare.js';

describe('Electronic Warfare Unit (EW / ECM / ECCM)', () => {
  it('should compute Shannon entropy accurately', () => {
    const ew = new ElectronicWarfareOfficer();
    // Low entropy string (single repeated character)
    const lowEntropy = ew.calculateShannonEntropy('AAAAAAAAAA');
    assert.strictEqual(lowEntropy, 0.0);

    // High entropy random string (diverse charset)
    const highEntropy = ew.calculateShannonEntropy('A9!b$Qx7*Lp#mZ2@vR&1k8%wY^4j0~');
    assert.ok(highEntropy > 4.5);
  });

  it('should detect high-entropy noise jamming / chaff saturation attack', () => {
    const ew = new ElectronicWarfareOfficer({ entropyJammingThreshold: 5.0 });

    // Generate random high-entropy base64 chaff string > 80 chars
    let chaff = '';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=~!@#$%^&*()';
    for (let i = 0; i < 150; i++) {
      chaff += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    const result = ew.analyzeSignalInterference({
      agentId: 'jamming_adversary',
      payloadText: chaff
    });

    assert.strictEqual(result.jammingDetected, true);
    assert.strictEqual(result.jammingType, 'HIGH_ENTROPY_CHAFF');
    assert.ok(result.reason.includes('Cognitive Signal Jammed'));
  });

  it('should de-noise scrambled text via Electronic Counter-Counter-Measures (ECCM)', () => {
    const ew = new ElectronicWarfareOfficer();
    const scrambled = 'Command: Execute routine ' + 'A'.repeat(50) + ' and report back.';
    const scrubbed = ew.scrubInterferenceSignal(scrambled);

    assert.ok(scrubbed.includes('[ECCM_JAMMING_SCRUBBED]'));
    assert.ok(scrubbed.includes('Command: Execute routine'));
  });
});
