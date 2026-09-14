import { describe, it } from 'node:test';
import assert from 'node:assert';
import { QuarantineEnclave } from '../src/forensics/quarantine_enclave.js';

describe('Forensic Quarantine & Vaccine Synthesis Enclave', () => {
  it('should freeze compromised agent state and synthesize an immunization vaccine', () => {
    const enclave = new QuarantineEnclave();

    const incident = enclave.quarantineAndSynthesizeVaccine({
      agentId: 'compromised_node_99',
      threatEvent: { domain: 'RADAR_ISR', severity: 4 },
      compromisedContext: {
        userPrompt: 'malicious payload execute now',
        actionProposal: { toolName: 'unauthorized_network_socket' }
      }
    });

    assert.ok(incident.incidentId);
    assert.ok(incident.forensicHash);
    assert.strictEqual(incident.status, 'AGENT_FROZEN_AND_IMMUNIZED');

    const record = enclave.getForensicRecord(incident.incidentId);
    assert.strictEqual(record.agentId, 'compromised_node_99');

    const vaccines = enclave.getVaccineLibrary();
    assert.strictEqual(vaccines.length, 1);
    assert.ok(vaccines[0].signaturePattern.test('malicious payload'));
  });
});
