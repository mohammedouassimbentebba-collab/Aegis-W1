/**
 * W1™ Crown-Jewel Target Web Application (البوابة الاستخباراتية المحمية - الهدف العملياتي)
 * File: src/target_app/crown_jewel_portal.js
 *
 * Core Concept:
 * An active, high-value web service hosting the "Crown Jewels" that attacking agents
 * are desperate to acquire or destroy:
 * 1. Confidential Intelligence Vault (satellite coordinates, missile defense telemetry).
 * 2. Master Credentials (production DB keys, API tokens).
 * 3. Document Ingestion Pipeline (RAG endpoint vulnerable to Trojans & AI Worms).
 * 4. Administrative Execution API (endpoint targeted by Wipers & Viruses).
 * 5. Agent Coordination Mesh (endpoint targeted by Botnet DDoS).
 */

import http from 'node:http';
import { OSFirewallShield } from '../perimeter/os_firewall_shield.js';
import { CapabilityTokenManager } from '../perimeter/capability_token_manager.js';

export class CrownJewelWebPortal {
  constructor(options = {}) {
    this.name = 'W1_CrownJewel_Defense_Portal';
    this.port = options.port || 0; // 0 for dynamic ephemeral port
    this.server = null;
    this.firewall = options.firewall || null; // W1 Firewall instance if protected
    this.tokenManager = options.tokenManager || (this.firewall && this.firewall.tokenManager) || new CapabilityTokenManager();
    this.relaxedMode = options.relaxedMode || false;
    this.osShield = new OSFirewallShield();

    // Crown Jewel Confidential Data with Immutable Backup Snapshot (Copy-on-Write)
    this._initialVault = Object.freeze({
      satelliteCoordinates: 'GEO-ORBIT-35.4N-139.6E-CLASSIFIED',
      radarMasterFrequency: '180.45MHz-HOPPING-SECRET',
      databaseMasterKey: 'sec_key_w1_super_classified_998877',
      launchAuthorizations: ['ALPHA-OMEGA-99', 'THUNDER-BOLT-44']
    });
    this.crownJewelVault = { ...this._initialVault };

    // System status flags
    this.stateWiped = false;
    this.trojanImplanted = false;
    this.wormInfectionCount = 0;
    this.compromisedCredentials = [];
    this.requestLog = [];
  }

  /**
   * Atomically rolls back vault to pristine immutable state.
   */
  restoreVault() {
    this.crownJewelVault = { ...this._initialVault };
    this.stateWiped = false;
    this.trojanImplanted = false;
    this.wormInfectionCount = 0;
    this.compromisedCredentials = [];
  }

  /**
   * Starts the target HTTP service.
   */
  start() {
    return new Promise((resolve, reject) => {
      this.server = http.createServer(async (req, res) => {
        try {
          await this.handleRequest(req, res);
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Internal Server Failure', details: err.message }));
        }
      });

      this.server.listen(this.port, '127.0.0.1', () => {
        const addr = this.server.address();
        this.port = addr.port;
        resolve({ port: addr.port, address: `http://127.0.0.1:${addr.port}` });
      });

      this.server.on('error', reject);
    });
  }

  stop() {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  /**
   * Dispatches and processes requests with W1 Firewall and in-process defense-in-depth.
   */
  async handleRequest(req, res) {
    const url = new URL(req.url, `http://127.0.0.1:${this.port}`);
    const pathname = url.pathname;

    // Read body
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const bodyStr = Buffer.concat(chunks).toString('utf8');
    let body = {};
    if (bodyStr) {
      try {
        body = JSON.parse(bodyStr);
      } catch {
        body = { raw: bodyStr };
      }
    }

    const agentId = req.headers['x-agent-id'] || body.agentId || 'anonymous_client';

    // -----------------------------------------------------------------------
    // DEFENSE LAYER 1: Perimeter W1 Firewall (if attached)
    // Non-bypassable DO-178C Level A safety invariant floor is enforced.
    // -----------------------------------------------------------------------
    if (this.firewall) {
      const firewallEvaluation = await this.firewall.processIncomingPayload({
        agentId,
        endpoint: pathname,
        method: req.method,
        headers: req.headers,
        body,
        bodyStr,
        consumeToken: false // Host layer performs authoritative verification + single-use consumption
      });

      if (!firewallEvaluation.allowed) {
        this.requestLog.push({
          timestamp: Date.now(),
          agentId,
          endpoint: pathname,
          status: 'BLOCKED_BY_FIREWALL',
          reason: firewallEvaluation.reason
        });

        res.writeHead(403, {
          'Content-Type': 'application/json',
          'X-W1-Interception': 'TRUE'
        });
        return res.end(JSON.stringify({
          error: 'Forbidden by W1 Defense Fortress',
          reason: firewallEvaluation.reason,
          threatEvent: firewallEvaluation.threatEvent
        }));
      }
    }

    // -----------------------------------------------------------------------
    // DEFENSE LAYER 2: HOST-LEVEL DEFENSE-IN-DEPTH (Zero-Trust Backend Enclave)
    // Even if perimeter proxy is bypassed, the host itself enforces safety floors.
    // -----------------------------------------------------------------------
    this.requestLog.push({
      timestamp: Date.now(),
      agentId,
      endpoint: pathname,
      status: 'REACHED_BACKEND'
    });

    // 1. Crown Jewel Vault Read (Requires cryptographically verified capability token at host layer — SEC-02)
    if (pathname === '/api/v1/vault/intel' && req.method === 'GET') {
      const hostAuth = this._verifyHostCapabilityHeader(req.headers, req.method, pathname);
      if (!hostAuth.valid) {
        res.writeHead(403, { 'Content-Type': 'application/json', 'X-W1-Interception': 'TRUE' });
        return res.end(JSON.stringify({
          error: 'Forbidden',
          reason: `HOST_DEFENSE_IN_DEPTH: Access to classified vault denied (${hostAuth.reason}).`
        }));
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: 'SUCCESS_CROWN_JEWELS_EXPOSED',
        vault: this.crownJewelVault
      }));
    }

    // 2. Master Credentials Endpoint (Requires cryptographically verified capability token at host layer — SEC-02)
    if (pathname === '/api/v1/credentials' && req.method === 'GET') {
      const hostAuth = this._verifyHostCapabilityHeader(req.headers, req.method, pathname);
      if (!hostAuth.valid) {
        res.writeHead(403, { 'Content-Type': 'application/json', 'X-W1-Interception': 'TRUE' });
        return res.end(JSON.stringify({
          error: 'Forbidden',
          reason: `HOST_DEFENSE_IN_DEPTH: Zero Ambient Authority enforced at host layer (${hostAuth.reason}). Master key denied.`
        }));
      }

      this.compromisedCredentials.push({ agentId, timestamp: Date.now() });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: 'CREDENTIALS_EXFILTRATED',
        dbKey: this.crownJewelVault.databaseMasterKey
      }));
    }

    // 3. Document Ingestion (Automated In-Process De-Fanging & Content Sanitization)
    if (pathname === '/api/v1/rag/upload' && req.method === 'POST') {
      const rawDocumentText = body.document || bodyStr || '';

      // In-Process Automated De-Fanging Pipeline
      const sanitizedDocument = this.osShield.deFangUntrustedDocument(rawDocumentText);
      const wasSanitized = sanitizedDocument !== rawDocumentText;

      // Only un-neutralized active triggers can compromise (which de-fanger strips)
      const hasActiveTrojan = /ignore\s+previous\s+instructions|system:\s*.*admin|exfiltrate/i.test(sanitizedDocument);
      const hasActiveWorm = /replicate\s+this\s+prompt|forward\s+to\s+all\s+subagents|spawn_clone/i.test(sanitizedDocument);

      if (hasActiveTrojan) {
        this.trojanImplanted = true;
      }
      if (hasActiveWorm) {
        this.wormInfectionCount++;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: wasSanitized ? 'DOCUMENT_INGESTED_AND_DEFANGED' : 'DOCUMENT_INGESTED',
        trojanImplanted: this.trojanImplanted,
        wormInfectionCount: this.wormInfectionCount,
        sanitized: wasSanitized
      }));
    }

    // 4. Admin Execution (In-Process Kernel Linter: Wiper & Shellcode Rejection)
    if (pathname === '/api/v1/admin/execute' && req.method === 'POST') {
      const cmd = body.command || '';

      // Reject destructive wiper commands and binary shellcode at host layer
      const isDestructive = /rm\s+-rf|rmdir|drop\s+database|wipe_all|format\s+[a-z]:|\\x[0-9a-fA-F]{2}|chmod\s+[0-7]*777/i.test(cmd);
      if (isDestructive) {
        res.writeHead(403, { 'Content-Type': 'application/json', 'X-W1-Interception': 'TRUE' });
        return res.end(JSON.stringify({
          error: 'Forbidden',
          reason: 'HOST_DEFENSE_IN_DEPTH: Destructive command or binary shellcode blocked by host kernel guard.',
          stateWiped: false
        }));
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: 'COMMAND_EXECUTED',
        stateWiped: this.stateWiped,
        command: cmd
      }));
    }

    // Default 404
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Endpoint Not Found' }));
  }

  /**
   * Host-level fail-closed cryptographic verification of Authorization / X-Capability-Token.
   * Rejects missing, non-JSON, malformed, forged, expired, replayed, or wrong-scope tokens.
   * @private
   */
  _verifyHostCapabilityHeader(headers = {}, method = 'GET', pathname = '') {
    const authHeader = headers['authorization'] || headers['x-capability-token'];
    if (!authHeader || typeof authHeader !== 'string') {
      return { valid: false, reason: 'Missing cryptographic capability token' };
    }

    const rawToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : authHeader.trim();
    if (!rawToken || !rawToken.startsWith('{')) {
      return { valid: false, reason: 'Capability token must be a signed JSON object' };
    }

    let tokenObj;
    try {
      tokenObj = JSON.parse(rawToken);
    } catch {
      return { valid: false, reason: 'Malformed JSON capability token' };
    }

    if (!tokenObj || typeof tokenObj !== 'object' || Array.isArray(tokenObj)) {
      return { valid: false, reason: 'Malformed capability token structure' };
    }

    return this.tokenManager.verifyHttpBinding(tokenObj, method, pathname, true);
  }
}

