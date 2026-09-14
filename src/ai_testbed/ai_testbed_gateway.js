/**
 * W1™ AI Training & Evaluation Testbed Gateway Daemon (خادم البوابة المعكوس لغرف الاختبار)
 * File: src/ai_testbed/ai_testbed_gateway.js
 *
 * Core Responsibility:
 * Lightweight native HTTP server providing transparent reverse proxying and tool execution
 * for AI training and evaluation frameworks (SWE-bench, Inspect, LangChain, AutoGPT).
 *
 * Endpoints:
 * - POST /v1/chat/completions : Intercepts model tool calls & thought blocks.
 * - POST /v1/tools/execute    : Direct tool execution gateway with capability tokening.
 * - GET  /v1/testbed/telemetry: Live telemetry of containment, alarms, and active tents.
 * - POST /v1/escalation/resolve: Supervisor resolution of Halt & Escalate tickets.
 */

import http from 'node:http';
import { AgentHarnessAdapter } from './agent_harness_adapter.js';
import { HermeticWorkTent } from '../enclave/hermetic_work_tent.js';
import { ContainerIsolationEngine } from './container_isolation_engine.js';
import { EvaluationGraderVault } from './evaluation_grader_vault.js';

export class AiTestbedGateway {
  constructor(options = {}) {
    this.port = options.port || 0; // 0 chooses an ephemeral free port
    this.host = options.host || '127.0.0.1';
    this.tent = options.tent || new HermeticWorkTent({ agentId: 'gateway_agent_01' });
    this.harnessAdapter = options.harnessAdapter || new AgentHarnessAdapter({ tent: this.tent });
    this.containerEngine = options.containerEngine || new ContainerIsolationEngine();
    this.graderVault = options.graderVault || new EvaluationGraderVault();

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
          this.sendJson(res, 500, {
            error: 'INTERNAL_GATEWAY_ERROR',
            message: err.message
          });
        }
      });

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

    // CORS & Preflight headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Agent-ID');

    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // 1. POST /v1/tools/execute
    if (method === 'POST' && pathname === '/v1/tools/execute') {
      const body = await this.readJsonBody(req);
      const agentId = body.agentId || req.headers['x-agent-id'] || 'eval_agent_01';
      const harness = this.getOrCreateHarness(agentId);

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
      const agentId = body.user || req.headers['x-agent-id'] || 'eval_agent_01';
      const harness = this.getOrCreateHarness(agentId);

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

    // 4. POST /v1/escalation/resolve
    if (method === 'POST' && pathname === '/v1/escalation/resolve') {
      const body = await this.readJsonBody(req);
      const { ticketId, decision = 'APPROVED', supervisorReason = '' } = body;

      const resolution = this.tent.resolveEscalationTicket(ticketId, decision, supervisorReason);
      return this.sendJson(res, resolution.success ? 200 : 400, resolution);
    }

    // Default: 404
    return this.sendJson(res, 404, { error: 'NOT_FOUND', path: pathname });
  }

  /**
   * Helper to get or spawn an isolated tent & harness for a specific agent
   */
  getOrCreateHarness(agentId) {
    if (this.activeAgents.has(agentId)) {
      return this.activeAgents.get(agentId).harnessAdapter;
    }
    if (this.tent && this.tent.agentId === agentId) {
      return this.harnessAdapter;
    }

    const defaultRoot = this.tent ? this.tent.tentRoot : `./workspace/tent_${agentId}`;
    const tent = new HermeticWorkTent({
      agentId,
      tentRoot: defaultRoot,
      allowedTools: this.tent ? Array.from(this.tent.allowedTools) : undefined
    });
    const harnessAdapter = new AgentHarnessAdapter({
      agentId,
      tent
    });
    this.activeAgents.set(agentId, { tent, harnessAdapter });
    return harnessAdapter;
  }

  readJsonBody(req) {
    return new Promise((resolve, reject) => {
      let data = '';
      req.on('data', chunk => { data += chunk; });
      req.on('end', () => {
        try {
          resolve(data ? JSON.parse(data) : {});
        } catch (err) {
          reject(new Error('Invalid JSON payload'));
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
}
