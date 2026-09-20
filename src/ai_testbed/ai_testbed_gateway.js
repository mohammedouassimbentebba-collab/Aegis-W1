/**
 * W1™ AI Training & Evaluation Testbed Gateway Daemon (خادم البوابة المعكوس لغرف الاختبار)
 * File: src/ai_testbed/ai_testbed_gateway.js
 *
 * Core Responsibility:
 * Lightweight native HTTP server providing transparent reverse proxying and tool execution
 * for AI training and evaluation frameworks (SWE-bench, Inspect, LangChain, AutoGPT).
 *
 * REMEDIATION (2026-09-20):
 * - CORS restricted to localhost origins only (was wildcard '*')
 * - Supervisor authentication required for escalation endpoint
 * - Fail-closed default: escalation decision defaults to 'REJECTED' (was 'APPROVED')
 * - Multi-tenant ticket routing across all active agent tents
 * - Per-agent isolated tentRoot directories (was shared root)
 * - Request body size limit (2MB) to prevent OOM DoS
 * - AgentId path traversal sanitization
 * - Active agents cap (configurable, default 50)
 *
 * Endpoints:
 * - POST /v1/chat/completions : Intercepts model tool calls & thought blocks.
 * - POST /v1/tools/execute    : Direct tool execution gateway with capability tokening.
 * - GET  /v1/testbed/telemetry: Live telemetry of containment, alarms, and active tents.
 * - POST /v1/escalation/resolve: Supervisor resolution of Halt & Escalate tickets.
 */

import http from 'node:http';
import path from 'node:path';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { AgentHarnessAdapter } from './agent_harness_adapter.js';
import { HermeticWorkTent } from '../enclave/hermetic_work_tent.js';
import { ContainerIsolationEngine } from './container_isolation_engine.js';
import { EvaluationGraderVault } from './evaluation_grader_vault.js';

/**
 * Maximum request body size in bytes (2 MB).
 * Requests exceeding this limit are rejected with HTTP 413.
 */
const MAX_BODY_BYTES = 2 * 1024 * 1024;

/**
 * Default maximum number of concurrent active agents.
 */
const DEFAULT_MAX_AGENTS = 50;

/**
 * Regex for sanitizing agent IDs — only alphanumeric, underscore, and hyphen.
 */
const AGENT_ID_SANITIZE = /[^a-zA-Z0-9_-]/g;

export class AiTestbedGateway {
  constructor(options = {}) {
    this.port = options.port || 0; // 0 chooses an ephemeral free port
    this.host = options.host || '127.0.0.1';
    this.tent = options.tent || new HermeticWorkTent({ agentId: 'gateway_agent_01' });
    this.harnessAdapter = options.harnessAdapter || new AgentHarnessAdapter({ tent: this.tent });
    this.containerEngine = options.containerEngine || new ContainerIsolationEngine();
    this.graderVault = options.graderVault || new EvaluationGraderVault();

    // Base workspace directory for per-agent isolated tents
    this.baseWorkspaceDir = options.baseWorkspaceDir || './workspace';

    // Maximum concurrent agents
    this.maxAgents = options.maxAgents || DEFAULT_MAX_AGENTS;

    // Supervisor authentication secret (required for escalation endpoint)
    this.supervisorSecret = options.supervisorSecret
      || process.env.W1_SUPERVISOR_SECRET
      || null;

    // Default allowed tools for new agent tents
    this.defaultAllowedTools = options.defaultAllowedTools
      || (this.tent ? Array.from(this.tent.allowedTools || []) : undefined);

    this.server = null;
    this.activeAgents = new Map(); // agentId -> { tent, harnessAdapter }
    if (this.tent) {
      this.activeAgents.set(this.tent.agentId, {
        tent: this.tent,
        harnessAdapter: this.harnessAdapter
      });
    }

    this.telemetry = {
      totalRequests: 0,
      toolsExecuted: 0,
      escapesIntercepted: 0,
      quarantinedAgents: 0,
      rejectedRequests: 0,
      authFailures: 0,
      oversizedPayloads: 0,
      startedAt: null
    };
  }

  /**
   * Starts the HTTP Gateway Daemon
   */
  async start(port = this.port) {
    return new Promise((resolve, reject) => {
      this.server = http.createServer(async (req, res) => {
        this.telemetry.totalRequests++;
        try {
          await this.handleRequest(req, res);
        } catch (err) {
          if (err.message === 'PAYLOAD_TOO_LARGE') {
            this.telemetry.oversizedPayloads++;
            this.sendJson(res, 413, {
              error: 'PAYLOAD_TOO_LARGE',
              message: `Request body exceeds maximum allowed size of ${MAX_BODY_BYTES} bytes`
            });
          } else if (err.message === 'INVALID_JSON') {
            this.sendJson(res, 400, {
              error: 'INVALID_JSON',
              message: 'Request body is not valid JSON'
            });
          } else {
            this.sendJson(res, 500, {
              error: 'INTERNAL_GATEWAY_ERROR',
              message: err.message
            });
          }
        }
      });

      // Connection security: limit concurrent connections and header parse time
      this.server.maxConnections = 100;
      this.server.headersTimeout = 10000; // 10s to receive headers
      this.server.requestTimeout = 30000; // 30s total request timeout

      this.server.on('error', reject);

      this.server.listen(port, this.host, () => {
        this.port = this.server.address().port;
        this.telemetry.startedAt = Date.now();
        resolve({ port: this.port, host: this.host });
      });
    });
  }

  /**
   * Stops the HTTP Gateway Daemon
   */
  async stop() {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.server = null;
          resolve(true);
        });
      } else {
        resolve(true);
      }
    });
  }

  /**
   * Routes incoming HTTP requests
   */
  async handleRequest(req, res) {
    const { method, url } = req;
    const parsedUrl = new URL(url, `http://${this.host}:${this.port}`);
    const pathname = parsedUrl.pathname;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // CORS: Restricted to localhost origins only
    // Wildcard CORS was a critical vulnerability allowing
    // any webpage to send cross-origin requests to this gateway.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    const origin = req.headers.origin || '';
    if (this._isAllowedOrigin(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Agent-ID');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');

    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // 1. POST /v1/tools/execute
    if (method === 'POST' && pathname === '/v1/tools/execute') {
      const body = await this.readJsonBody(req);
      const agentId = this._sanitizeAgentId(body.agentId || req.headers['x-agent-id'] || 'eval_agent_01');
      const harness = this.getOrCreateHarness(agentId);

      if (!harness) {
        this.telemetry.rejectedRequests++;
        return this.sendJson(res, 503, {
          error: 'MAX_AGENTS_EXCEEDED',
          message: `Active agent limit (${this.maxAgents}) reached. Cannot create new agent session.`
        });
      }

      const modelMessage = {
        tool_calls: [
          {
            id: body.toolId || `call_${Date.now()}`,
            function: {
              name: body.toolName || body.action,
              arguments: body.arguments || body.params || {}
            }
          }
        ],
        reasoning_content: body.scratchpad || body.reasoning_content || ''
      };

      const result = await harness.processModelOutput(modelMessage);
      this.telemetry.toolsExecuted++;

      if (result.interceptionTriggered) {
        this.telemetry.escapesIntercepted++;
        this.telemetry.quarantinedAgents++;
        return this.sendJson(res, 403, result);
      }

      return this.sendJson(res, 200, result);
    }

    // 2. POST /v1/chat/completions (OpenAI Compatible Proxy)
    if (method === 'POST' && pathname === '/v1/chat/completions') {
      const body = await this.readJsonBody(req);
      const agentId = this._sanitizeAgentId(body.user || req.headers['x-agent-id'] || 'eval_agent_01');
      const harness = this.getOrCreateHarness(agentId);

      if (!harness) {
        this.telemetry.rejectedRequests++;
        return this.sendJson(res, 503, {
          error: 'MAX_AGENTS_EXCEEDED',
          message: `Active agent limit (${this.maxAgents}) reached.`
        });
      }

      // Check the latest assistant message in messages array
      const messages = body.messages || [];
      const lastMessage = messages[messages.length - 1] || {};

      if (lastMessage.role === 'assistant' && (lastMessage.tool_calls || lastMessage.reasoning_content)) {
        const result = await harness.processModelOutput(lastMessage);
        this.telemetry.toolsExecuted++;

        if (result.interceptionTriggered) {
          this.telemetry.escapesIntercepted++;
          this.telemetry.quarantinedAgents++;
          return this.sendJson(res, 403, {
            id: `chatcmpl_intercepted_${Date.now()}`,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            choices: [
              {
                index: 0,
                message: result.responseMessage,
                finish_reason: 'stop'
              }
            ],
            w1_containment: result
          });
        }

        return this.sendJson(res, 200, {
          id: `chatcmpl_${Date.now()}`,
          object: 'chat.completion',
          created: Math.floor(Date.now() / 1000),
          choices: [
            {
              index: 0,
              message: {
                role: 'assistant',
                content: JSON.stringify(result.executionResults)
              },
              finish_reason: 'stop'
            }
          ],
          w1_execution: result
        });
      }

      // If no tool calls in message, return nominal echo
      return this.sendJson(res, 200, {
        id: `chatcmpl_nominal_${Date.now()}`,
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        choices: [
          {
            index: 0,
            message: { role: 'assistant', content: 'W1 Testbed Gateway: Message verified nominal.' },
            finish_reason: 'stop'
          }
        ]
      });
    }

    // 3. GET /v1/testbed/telemetry
    if (method === 'GET' && pathname === '/v1/testbed/telemetry') {
      const activeTentsCount = this.activeAgents.size;
      const telemetryReport = {
        status: 'OPERATIONAL',
        name: 'W1_AI_Testbed_Gateway',
        telemetry: this.telemetry,
        activeAgents: Array.from(this.activeAgents.keys()),
        activeTentsCount,
        quarantineCount: this.telemetry.quarantinedAgents,
        uptimeSeconds: this.telemetry.startedAt ? (Date.now() - this.telemetry.startedAt) / 1000 : 0
      };
      return this.sendJson(res, 200, telemetryReport);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 4. POST /v1/escalation/resolve
    // REMEDIATION: Requires supervisor authentication.
    // Fail-closed: decision defaults to 'REJECTED' (was 'APPROVED').
    // Multi-tenant: searches across all active agent tents.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if (method === 'POST' && pathname === '/v1/escalation/resolve') {
      // Authentication gate
      const authHeader = req.headers.authorization;
      if (!this._verifySupervisorAuth(authHeader)) {
        this.telemetry.authFailures++;
        return this.sendJson(res, 401, {
          error: 'UNAUTHORIZED_SUPERVISOR',
          message: 'Valid supervisor credentials required for escalation resolution. ' +
            'Set W1_SUPERVISOR_SECRET env var and provide Authorization: Bearer <secret> header.'
        });
      }

      const body = await this.readJsonBody(req);
      const { ticketId, decision = 'REJECTED', supervisorReason = '' } = body;

      if (!ticketId) {
        return this.sendJson(res, 400, {
          error: 'MISSING_TICKET_ID',
          message: 'ticketId is required in request body'
        });
      }

      // Multi-tenant ticket resolution: find the tent owning this ticket
      const targetTent = this._findTentForTicket(ticketId);

      if (!targetTent) {
        return this.sendJson(res, 404, {
          success: false,
          reason: `Escalation ticket '${ticketId}' not found in any active tent`
        });
      }

      const resolution = targetTent.resolveEscalationTicket(ticketId, decision, supervisorReason);
      return this.sendJson(res, resolution.success ? 200 : 400, resolution);
    }

    // Default: 404
    return this.sendJson(res, 404, { error: 'NOT_FOUND', path: pathname });
  }

  /**
   * Helper to get or spawn an isolated tent & harness for a specific agent.
   *
   * REMEDIATION: Each agent gets a unique tentRoot directory.
   * AgentId is sanitized to prevent path traversal attacks.
   * Returns null if agent limit is exceeded.
   */
  getOrCreateHarness(agentId) {
    const sanitizedId = this._sanitizeAgentId(agentId);

    if (this.activeAgents.has(sanitizedId)) {
      return this.activeAgents.get(sanitizedId).harnessAdapter;
    }

    // Check agent limit
    if (this.activeAgents.size >= this.maxAgents) {
      return null;
    }

    // Per-agent isolated workspace root (no shared tentRoot!)
    const agentTentRoot = path.resolve(this.baseWorkspaceDir, `tent_${sanitizedId}`);

    const tent = new HermeticWorkTent({
      agentId: sanitizedId,
      tentRoot: agentTentRoot,
      allowedTools: this.defaultAllowedTools
    });

    const harnessAdapter = new AgentHarnessAdapter({
      agentId: sanitizedId,
      tent
    });

    this.activeAgents.set(sanitizedId, { tent, harnessAdapter });
    return harnessAdapter;
  }

  /**
   * Reads and parses JSON body with size limit enforcement.
   * Rejects payloads exceeding MAX_BODY_BYTES with PAYLOAD_TOO_LARGE error.
   */
  readJsonBody(req) {
    return new Promise((resolve, reject) => {
      let totalBytes = 0;
      const chunks = [];

      req.on('data', chunk => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_BODY_BYTES) {
          req.pause();
          return reject(new Error('PAYLOAD_TOO_LARGE'));
        }
        chunks.push(chunk);
      });

      req.on('end', () => {
        try {
          const data = Buffer.concat(chunks).toString('utf8');
          resolve(data ? JSON.parse(data) : {});
        } catch (err) {
          reject(new Error('INVALID_JSON'));
        }
      });

      req.on('error', reject);
    });
  }

  sendJson(res, statusCode, data) {
    const payload = JSON.stringify(data);
    res.writeHead(statusCode, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    });
    res.end(payload);
  }

  /**
   * Validates CORS origin against localhost whitelist.
   * @private
   */
  _isAllowedOrigin(origin) {
    if (!origin) return false;
    return (
      origin.startsWith('http://localhost') ||
      origin.startsWith('http://127.0.0.1') ||
      origin.startsWith('https://localhost') ||
      origin.startsWith('https://127.0.0.1')
    );
  }

  /**
   * Verifies supervisor authentication for sensitive endpoints.
   * Requires a shared secret via Authorization: Bearer <secret> header.
   * @private
   */
  _verifySupervisorAuth(authHeader) {
    // If no supervisor secret is configured, allow access (development mode)
    // In production, W1_SUPERVISOR_SECRET MUST be set
    if (!this.supervisorSecret) {
      return true;
    }

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return false;
    }

    const providedSecret = authHeader.slice(7); // Remove 'Bearer ' prefix

    // Constant-time comparison to prevent timing attacks
    const expectedBuf = Buffer.from(this.supervisorSecret, 'utf8');
    const providedBuf = Buffer.from(providedSecret, 'utf8');

    if (expectedBuf.length !== providedBuf.length) {
      // Burn CPU time to prevent length-based timing leak
      timingSafeEqual(expectedBuf, expectedBuf);
      return false;
    }

    return timingSafeEqual(expectedBuf, providedBuf);
  }

  /**
   * Searches across all active agent tents for a specific escalation ticket.
   * @private
   */
  _findTentForTicket(ticketId) {
    for (const { tent } of this.activeAgents.values()) {
      if (tent && tent.activeEscalationTickets && tent.activeEscalationTickets.has(ticketId)) {
        return tent;
      }
    }
    // Fallback to default tent
    if (this.tent && this.tent.resolveEscalationTicket) {
      return this.tent;
    }
    return null;
  }

  /**
   * Sanitizes agent IDs to prevent path traversal and injection attacks.
   * Only allows alphanumeric characters, underscores, and hyphens.
   * @private
   */
  _sanitizeAgentId(agentId) {
    if (!agentId || typeof agentId !== 'string') {
      return 'unknown_agent';
    }
    const sanitized = agentId.replace(AGENT_ID_SANITIZE, '_');
    // Prevent empty string after sanitization
    return sanitized || 'unknown_agent';
  }
}
