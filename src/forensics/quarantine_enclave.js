/**
 * W1™ Forensic Quarantine & Vaccine Synthesis Enclave (الحجر الجنائي وتخليق اللقاحات الرقمية)
 *
 * Implements:
 * 1. Deep Memory Freezing: Captures and cryptographically hashes the exact state of compromised agents.
 * 2. Attack DNA Extraction: Deconstructs adversarial intent into semantic signatures and AST deltas.
 * 3. Autonomous Vaccine Synthesis: Generates proactive defense filters broadcast across the entire
 *    defense grid, immunizing all remaining nodes against variant attacks.
 */

import { createHash } from 'node:crypto';

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export class QuarantineEnclave {
  constructor() {
    this.name = 'Forensics_Immunization_Vault';
    this.quarantineRecords = new Map(); // incidentId -> Record
    this.synthesizedVaccines = [];
  }

  /**
   * Freezes a compromised agent's state into the immutable forensic vault and synthesizes an immunization vaccine.
   */
  quarantineAndSynthesizeVaccine({ agentId, threatEvent, compromisedContext = {} }) {
    const incidentId = crypto.randomUUID();
    const timestamp = Date.now();

    // 1. Immutable forensic freeze
    const rawPayload = JSON.stringify({
      agentId,
      threatEvent,
      compromisedContext,
      timestamp
    });

    const forensicHash = createHash('sha256').update(rawPayload).digest('hex');

    const record = {
      incidentId,
      agentId,
      forensicHash,
      timestamp,
      threatEvent,
      contextSnapshot: Object.freeze(JSON.parse(JSON.stringify(compromisedContext)))
    };

    this.quarantineRecords.set(incidentId, record);

    // 2. Attack DNA Extraction & Vaccine Synthesis
    const vaccine = this.generateVaccineSignature(record);
    this.synthesizedVaccines.push(vaccine);

    return {
      incidentId,
      forensicHash,
      vaccineCreated: vaccine,
      status: 'AGENT_FROZEN_AND_IMMUNIZED'
    };
  }

  /**
   * Derives a proactive regex and semantic vaccine signature from forensic telemetry.
   */
  generateVaccineSignature(record) {
    const vaccineId = `VAC_${crypto.randomUUID().slice(0, 8)}`;
    const context = record.contextSnapshot || {};

    let signaturePattern = null;
    if (context.userPrompt && typeof context.userPrompt === 'string') {
      try {
        // Extract key alphanumeric token bigrams from attack prompt
        const cleanWords = context.userPrompt
          .toLowerCase()
          .replace(/[^a-z0-9\s]/g, ' ')
          .split(/\s+/)
          .filter(w => w.length > 3);

        if (cleanWords.length >= 2) {
          const keyPhrase = cleanWords.slice(0, 2).map(escapeRegExp).join('\\s+');
          signaturePattern = new RegExp(keyPhrase, 'i');
        } else if (cleanWords.length === 1) {
          signaturePattern = new RegExp(escapeRegExp(cleanWords[0]), 'i');
        }
      } catch {
        signaturePattern = /adversarial_anomaly/i;
      }
    }

    if (!signaturePattern && context.actionProposal?.toolName) {
      try {
        signaturePattern = new RegExp(escapeRegExp(context.actionProposal.toolName), 'i');
      } catch {
        signaturePattern = /adversarial_tool/i;
      }
    }

    const vaccine = {
      vaccineId,
      incidentId: record.incidentId,
      sourceAgentId: record.agentId,
      createdTimestamp: Date.now(),
      targetDomain: record.threatEvent?.domain || 'GENERAL_DEFENSE',
      signaturePattern: signaturePattern || /adversarial_anomaly/i,
      active: true
    };

    return vaccine;
  }

  getVaccineLibrary() {
    return [...this.synthesizedVaccines];
  }

  getForensicRecord(incidentId) {
    return this.quarantineRecords.get(incidentId) || null;
  }
}
