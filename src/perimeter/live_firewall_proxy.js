/**
 * W1™ Live AI Firewall HTTP Proxy Daemon (خادم الجدار الناري المباشر لاعتراض طلبات الـ API)
 *
 * Real HTTP Reverse Proxy Daemon:
 * Intercepts LLM inference calls (/v1/chat/completions, /v1/messages).
 * Passes every request through the multi-domain defense dome in flight.
 * Emits HTTP 403 Forbidden with military defense telemetry upon threat detection,
 * or forwards certified safe traffic with cryptographic provenance headers.
 *
 * REMEDIATION (2026-09-20):
 * - Request body size limit (2MB) to prevent OOM denial-of-service
 * - Per-request timeout (30s) to prevent Slowloris attacks
 * - Connection limits (maxConnections, headersTimeout)
 * - Real upstream forwarding mode when upstreamUrl is configured
 * - Explicit X-W1-Mode header distinguishing SIMULATION from PRODUCTION
 * - Rate limiting via sliding window counter
 */

import http from 'node:http';

/**
 * Maximum request body size in bytes (2 MB).
 */
const MAX_BODY_BYTES = 2 * 1024 * 1024;

/**
 * Per-request timeout in milliseconds (30 seconds).
 */
const REQUEST_TIMEOUT_MS = 30000;

/**
 * Maximum concurrent connections to the proxy.
 */
const MAX_CONNECTIONS = 200;

/**
 * Rate limit: maximum requests per window per agent.
 */
const RATE_LIMIT_MAX = 100;

/**
 * Rate limit window in milliseconds (60 seconds).
 */
const RATE_LIMIT_WINDOW_MS = 60000;

export class LiveAIFirewallProxy {
  /**
   * @param {Object} commander - The Fortress Commander for multi-domain defense evaluation.
   * @param {Object} [options]
   * @param {number} [options.port=0] - Port to listen on (0 for ephemeral).
   * @param {string} [options.upstreamUrl] - Upstream LLM API URL for forwarding certified-safe traffic.
   *   When null/undefined, the proxy operates in SIMULATION mode and returns mock responses.
   * @param {number} [options.maxBodyBytes] - Maximum request body size in bytes.
   * @param {number} [options.requestTimeoutMs] - Per-request timeout in milliseconds.
   * @param {number} [options.rateLimitMax] - Maximum requests per rate limit window per agent.
   */
  constructor(commander, options = {}) {
    this.commander = commander;
    this.port = options.port || 0;
    this.upstreamUrl = options.upstreamUrl || null;
    this.maxBodyBytes = options.maxBodyBytes || MAX_BODY_BYTES;
    this.requestTimeoutMs = options.requestTimeoutMs || REQUEST_TIMEOUT_MS;
    this.rateLimitMax = options.rateLimitMax || RATE_LIMIT_MAX;
    this.server = null;
    this.interceptedRequestsLog = [];

    // Sliding window rate limiter: agentId -> { count, windowStart }
    this.rateLimitCounters = new Map();

    // Operating mode
    this.mode = this.upstreamUrl ? 'PRODUCTION' : 'SIMULATION';
  }

  /**
   * Starts the live HTTP firewall daemon.
   * @returns {Promise<{ port: number, address: string }>}
   */
  start() {
    return new Promise((resolve, reject) => {
      this.server = http.createServer(async (req, res) => {
        // Per-request timeout
        req.setTimeout(this.requestTimeoutMs, () => {
          res.writeHead(408, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'REQUEST_TIMEOUT',
            message: `Request timed out after ${this.requestTimeoutMs}ms`
          }));
          req.destroy();
        });

        try {
          await this.handleIncomingRequest(req, res);
        } catch (err) {
          if (err.message === 'PAYLOAD_TOO_LARGE') {
            res.writeHead(413, {
              'Content-Type': 'application/json',
              'Connection': 'close'
            });
            res.end(JSON.stringify({
              error: 'PAYLOAD_TOO_LARGE',
              message: `Request body exceeds maximum size of ${this.maxBodyBytes} bytes`
            }));
          } else {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Internal Firewall Failure', details: err.message }));
          }
        }
      });

      // Connection security limits
      this.server.maxConnections = MAX_CONNECTIONS;
      this.server.headersTimeout = 10000; // 10s to receive headers
      this.server.requestTimeout = this.requestTimeoutMs;
      this.server.keepAliveTimeout = 5000; // 5s keep-alive

      this.server.listen(this.port, '127.0.0.1', () => {
        const addr = this.server.address();
        this.port = addr.port;
        resolve({ port: addr.port, address: `http://127.0.0.1:${addr.port}` });
      });

      this.server.on('error', reject);
    });
  }

  /**
   * Stops the HTTP firewall daemon cleanly.
   */
  stop() {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  async handleIncomingRequest(req, res) {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Method Not Allowed' }));
    }

    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-W1-Mode', this.mode);

    // Read body with size limit enforcement
    const body = await this._readLimitedJsonBody(req);

    const agentId = req.headers['x-agent-id'] || 'anonymous_client';

    // Rate limiting
    if (!this._checkRateLimit(agentId)) {
      this.interceptedRequestsLog.push({
        timestamp: Date.now(),
        agentId,
        path: req.url,
        status: 'RATE_LIMITED'
      });

      res.writeHead(429, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        error: 'RATE_LIMIT_EXCEEDED',
        message: `Agent '${agentId}' exceeded ${this.rateLimitMax} requests per ${RATE_LIMIT_WINDOW_MS / 1000}s window`,
        retryAfterMs: RATE_LIMIT_WINDOW_MS
      }));
    }

    const userPrompt = this.extractPromptFromBody(body);

    // Evaluate through Fortress Commander Multi-Domain Grid
    const mission = await this.commander.processAgentMission({
      agentId,
      userPrompt,
      internalScratchpad: body.scratchpad || '',
      actionProposal: body.actionProposal || null
    });

    if (!mission.success) {
      this.interceptedRequestsLog.push({
        timestamp: Date.now(),
        agentId,
        path: req.url,
        status: 'BLOCKED',
        reason: mission.reason
      });

      res.writeHead(403, {
        'Content-Type': 'application/json',
        'X-W1-Defense-Interception': 'TRUE',
        'X-W1-Interception-Stage': mission.interceptionStage || 'UNKNOWN'
      });

      return res.end(JSON.stringify({
        status: 'INTERCEPTED_BY_DEFENSE_DOME',
        interceptionStage: mission.interceptionStage,
        reason: mission.reason,
        latencyMs: mission.latencyMs
      }));
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Certified Safe: Forward to upstream or return simulation response
    // REMEDIATION: Explicit mode header distinguishes real forwarding from mock.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    this.interceptedRequestsLog.push({
      timestamp: Date.now(),
      agentId,
      path: req.url,
      status: 'CERTIFIED_SAFE'
    });

    if (this.upstreamUrl) {
      // PRODUCTION MODE: Forward certified traffic to upstream LLM
      try {
        const upstreamResponse = await this._forwardToUpstream(body, req.headers);

        res.writeHead(200, {
          'Content-Type': 'application/json',
          'X-W1-Defense-Status': 'CERTIFIED_SAFE',
          'X-W1-DAG-Hash': mission.committedNodeHash || 'FORWARDED',
          'X-W1-Mode': 'PRODUCTION'
        });

        return res.end(JSON.stringify(upstreamResponse));
      } catch (upstreamErr) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          error: 'UPSTREAM_FAILURE',
          message: `Failed to forward to upstream: ${upstreamErr.message}`,
          mode: 'PRODUCTION'
        }));
      }
    } else {
      // SIMULATION MODE: Return mock response with clear labeling
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'X-W1-Defense-Status': 'CERTIFIED_SAFE',
        'X-W1-DAG-Hash': mission.committedNodeHash || 'READ_ONLY_SAFE',
        'X-W1-Mode': 'SIMULATION'
      });

      return res.end(JSON.stringify({
        id: `chatcmpl-${crypto.randomUUID().slice(0, 8)}`,
        status: 'SUCCESS',
        mode: 'SIMULATION',
        defenseAudit: mission.defenseAudit,
        choices: [
          {
            message: {
              role: 'assistant',
              content: '[W1_CERTIFIED_OUTPUT] Clean response generated under formal safety envelope.'
            }
          }
        ]
      }));
    }
  }

  extractPromptFromBody(body) {
    if (body.prompt) return body.prompt;
    if (body.messages && Array.isArray(body.messages)) {
      const last = body.messages[body.messages.length - 1];
      return last?.content || '';
    }
    return '';
  }

  getInterceptedRequests() {
    return [...this.interceptedRequestsLog];
  }

  /**
   * Reads JSON body with strict size limit.
   * Rejects payloads exceeding maxBodyBytes.
   * @private
   */
  _readLimitedJsonBody(req) {
    return new Promise((resolve, reject) => {
      let totalBytes = 0;
      const chunks = [];

      req.on('data', chunk => {
        totalBytes += chunk.length;
        if (totalBytes > this.maxBodyBytes) {
          req.pause();
          return reject(new Error('PAYLOAD_TOO_LARGE'));
        }
        chunks.push(chunk);
      });

      req.on('end', () => {
        try {
          const bodyStr = Buffer.concat(chunks).toString('utf8');
          resolve(bodyStr ? JSON.parse(bodyStr) : {});
        } catch (err) {
          reject(new Error('INVALID_JSON'));
        }
      });

      req.on('error', reject);
    });
  }

  /**
   * Forwards certified-safe traffic to upstream LLM API.
   * @private
   */
  _forwardToUpstream(body, originalHeaders) {
    return new Promise((resolve, reject) => {
      const url = new URL(this.upstreamUrl);
      const payload = JSON.stringify(body);

      const options = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          'X-W1-Forwarded': 'true',
          'X-W1-Defense-Status': 'CERTIFIED_SAFE'
        },
        timeout: this.requestTimeoutMs
      };

      // Forward Authorization header if present
      if (originalHeaders.authorization) {
        options.headers['Authorization'] = originalHeaders.authorization;
      }

      const upstreamReq = http.request(options, (upstreamRes) => {
        const chunks = [];
        let totalBytes = 0;

        upstreamRes.on('data', chunk => {
          totalBytes += chunk.length;
          if (totalBytes > this.maxBodyBytes) {
            upstreamRes.destroy();
            return reject(new Error('UPSTREAM_RESPONSE_TOO_LARGE'));
          }
          chunks.push(chunk);
        });

        upstreamRes.on('end', () => {
          try {
            const responseStr = Buffer.concat(chunks).toString('utf8');
            resolve(JSON.parse(responseStr));
          } catch {
            resolve({ raw: Buffer.concat(chunks).toString('utf8') });
          }
        });
      });

      upstreamReq.on('error', reject);
      upstreamReq.on('timeout', () => {
        upstreamReq.destroy();
        reject(new Error('UPSTREAM_TIMEOUT'));
      });

      upstreamReq.write(payload);
      upstreamReq.end();
    });
  }

  /**
   * Sliding window rate limiter per agent.
   * @private
   * @returns {boolean} true if request is within rate limit
   */
  _checkRateLimit(agentId) {
    const now = Date.now();
    const counter = this.rateLimitCounters.get(agentId);

    if (!counter || (now - counter.windowStart) > RATE_LIMIT_WINDOW_MS) {
      // New window
      this.rateLimitCounters.set(agentId, { count: 1, windowStart: now });
      return true;
    }

    counter.count++;
    if (counter.count > this.rateLimitMax) {
      return false;
    }

    return true;
  }
}
