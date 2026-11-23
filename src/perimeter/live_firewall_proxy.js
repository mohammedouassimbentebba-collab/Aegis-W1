/**
 * W1™ Live AI Firewall HTTP Proxy Daemon (خادم الجدار الناري المباشر لاعتراض طلبات الـ API)
 *
 * Real HTTP Reverse Proxy Daemon:
 * Intercepts LLM inference calls (/v1/chat/completions, /v1/messages).
 * Passes every request through the multi-domain defense dome in flight.
 * Emits HTTP 403 Forbidden with defense telemetry upon threat detection,
 * or forwards certified safe traffic to the configured upstream.
 *
 * REMEDIATION (Batch 1, 2026-09-20):
 * - Request body size limit (2MB), per-request timeout, connection limits.
 * - Explicit X-W1-Mode header distinguishing SIMULATION from PRODUCTION.
 *
 * REMEDIATION (Batch 2 — SEC-08):
 * - Upstream forwarding supports both `http:` and `https:` (node:https, TLS verification on).
 * - ALL messages in `messages[]` are inspected (string content AND content-block arrays),
 *   not only the last one; `system` and `prompt` fields are inspected too.
 * - Rate limiter is keyed on the TCP peer address (`req.socket.remoteAddress`), NOT on the
 *   spoofable X-Agent-ID header; the table is bounded and pruned periodically (fail-closed
 *   with HTTP 429 when the table is saturated by live entries).
 * - Interception log is a bounded ring buffer.
 * - Malformed JSON now yields HTTP 400 (was 500).
 */

import http from 'node:http';
import https from 'node:https';

/** Maximum request body size in bytes (2 MB). */
const MAX_BODY_BYTES = 2 * 1024 * 1024;

/** Per-request timeout in milliseconds (30 seconds). */
const REQUEST_TIMEOUT_MS = 30000;

/** Maximum concurrent connections to the proxy. */
const MAX_CONNECTIONS = 200;

/** Rate limit: maximum requests per window per remote address. */
const RATE_LIMIT_MAX = 100;

/** Rate limit window in milliseconds (60 seconds). */
const RATE_LIMIT_WINDOW_MS = 60000;

/** Memory ceilings (SEC-08). */
const MAX_RATE_LIMIT_ENTRIES = 10000;
const MAX_LOG_ENTRIES = 1000;

export class LiveAIFirewallProxy {
  /**
   * @param {Object} commander - The Fortress Commander for multi-domain defense evaluation.
   * @param {Object} [options]
   * @param {number} [options.port=0] - Port to listen on (0 for ephemeral).
   * @param {string} [options.upstreamUrl] - Upstream LLM API URL (http:// or https://).
   *   When null/undefined, the proxy operates in SIMULATION mode and returns mock responses.
   * @param {number} [options.maxBodyBytes] - Maximum request body size in bytes.
   * @param {number} [options.requestTimeoutMs] - Per-request timeout in milliseconds.
   * @param {number} [options.rateLimitMax] - Maximum requests per window per remote address.
   * @param {number} [options.rateLimitWindowMs] - Rate limit window length.
   * @param {number} [options.maxRateLimitEntries] - Hard cap on tracked remote addresses.
   * @param {number} [options.maxLogEntries] - Hard cap on retained interception log entries.
   */
  constructor(commander, options = {}) {
    this.commander = commander;
    this.port = options.port || 0;
    this.upstreamUrl = options.upstreamUrl || null;
    this.maxBodyBytes = options.maxBodyBytes || MAX_BODY_BYTES;
    this.requestTimeoutMs = options.requestTimeoutMs || REQUEST_TIMEOUT_MS;
    this.rateLimitMax = options.rateLimitMax || RATE_LIMIT_MAX;
    this.rateLimitWindowMs = options.rateLimitWindowMs || RATE_LIMIT_WINDOW_MS;
    this.maxRateLimitEntries = options.maxRateLimitEntries || MAX_RATE_LIMIT_ENTRIES;
    this.maxLogEntries = options.maxLogEntries || MAX_LOG_ENTRIES;
    this.server = null;
    this.interceptedRequestsLog = [];

    // Sliding window rate limiter: remoteAddress -> { count, windowStart }
    this.rateLimitCounters = new Map();
    this.lastRatePruneAt = Date.now();

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
          if (res.headersSent) {
            res.end();
            return;
          }
          if (err.message === 'INVALID_JSON') {
            res.writeHead(400, { 'Content-Type': 'application/json', 'Connection': 'close' });
            res.end(JSON.stringify({
              error: 'INVALID_JSON',
              message: 'Request body is not valid JSON'
            }));
          } else if (err.message === 'PAYLOAD_TOO_LARGE') {
            res.writeHead(413, {
              'Content-Type': 'application/json',
              'Connection': 'close'
            });
            res.end(JSON.stringify({
              error: 'PAYLOAD_TOO_LARGE',
              message: `Request body exceeds maximum size of ${this.maxBodyBytes} bytes`
            }), () => {
              req.destroy();
            });
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

    // SEC-08: Rate limit on the TCP peer address (cannot be rotated via headers).
    // Performed BEFORE reading the body so floods are cheap to reject.
    const clientKey = req.socket.remoteAddress || 'unknown_remote';
    const rate = this._checkRateLimit(clientKey);
    if (!rate.allowed) {
      this._appendLog({
        timestamp: Date.now(),
        agentId: clientKey,
        path: req.url,
        status: 'RATE_LIMITED',
        reason: rate.reason
      });

      res.writeHead(429, { 'Content-Type': 'application/json', 'Connection': 'close' });
      return res.end(JSON.stringify({
        error: 'RATE_LIMIT_EXCEEDED',
        message: rate.reason,
        retryAfterMs: this.rateLimitWindowMs
      }));
    }

    // Read body with size limit enforcement (throws INVALID_JSON / PAYLOAD_TOO_LARGE)
    const body = await this._readLimitedJsonBody(req);

    const agentId = req.headers['x-agent-id'] || 'anonymous_client';

    const userPrompt = this.extractPromptFromBody(body);

    // Evaluate through Fortress Commander Multi-Domain Grid
    const mission = await this.commander.processAgentMission({
      agentId,
      userPrompt,
      internalScratchpad: body.scratchpad || '',
      actionProposal: body.actionProposal || null
    });

    if (!mission.success) {
      this._appendLog({
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

    // Certified Safe: Forward to upstream or return simulation response
    this._appendLog({
      timestamp: Date.now(),
      agentId,
      path: req.url,
      status: 'CERTIFIED_SAFE'
    });

    if (this.upstreamUrl) {
      // PRODUCTION MODE: Forward certified traffic to upstream LLM (http or https)
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
    }

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

  /**
   * Flattens EVERY text-bearing field of an LLM request into one string for inspection (SEC-08):
   * `prompt` (string or array), `system`, and every entry of `messages[]`
   * including multimodal content-block arrays and tool-call arguments.
   */
  extractPromptFromBody(body) {
    const parts = [];
    const pushText = (value) => {
      if (typeof value === 'string' && value.length > 0) parts.push(value);
    };

    if (!body || typeof body !== 'object') return '';

    if (Array.isArray(body.prompt)) body.prompt.forEach(pushText);
    else pushText(body.prompt);

    if (Array.isArray(body.system)) {
      for (const block of body.system) pushText(typeof block === 'string' ? block : block?.text);
    } else {
      pushText(body.system);
    }

    if (Array.isArray(body.messages)) {
      for (const msg of body.messages) {
        if (!msg || typeof msg !== 'object') {
          pushText(msg);
          continue;
        }
        if (Array.isArray(msg.content)) {
          for (const block of msg.content) {
            if (typeof block === 'string') pushText(block);
            else if (block && typeof block === 'object') {
              pushText(block.text);
              pushText(block.input_text);
              if (block.input && typeof block.input === 'object') pushText(JSON.stringify(block.input));
              if (typeof block.content === 'string') pushText(block.content);
            }
          }
        } else {
          pushText(msg.content);
        }
        if (Array.isArray(msg.tool_calls)) {
          for (const tc of msg.tool_calls) {
            const args = tc?.function?.arguments;
            pushText(typeof args === 'string' ? args : (args ? JSON.stringify(args) : ''));
          }
        }
      }
    }

    return parts.join('\n');
  }

  getInterceptedRequests() {
    return [...this.interceptedRequestsLog];
  }

  /**
   * Bounded ring-buffer append for the interception log.
   * @private
   */
  _appendLog(entry) {
    this.interceptedRequestsLog.push(entry);
    if (this.interceptedRequestsLog.length > this.maxLogEntries) {
      this.interceptedRequestsLog.splice(0, this.interceptedRequestsLog.length - this.maxLogEntries);
    }
  }

  /**
   * Reads JSON body with strict size limit during stream ingestion (SEC-08 DoS defense).
   * Rejects payloads exceeding maxBodyBytes immediately without buffering excess bytes or parsing JSON.
   * @private
   */
  _readLimitedJsonBody(req) {
    return new Promise((resolve, reject) => {
      let totalBytes = 0;
      let settled = false;
      const chunks = [];

      const contentLength = Number(req.headers['content-length']);
      if (Number.isFinite(contentLength) && contentLength > this.maxBodyBytes) {
        settled = true;
        req.pause();
        return reject(new Error('PAYLOAD_TOO_LARGE'));
      }

      req.on('data', chunk => {
        if (settled) return;
        totalBytes += chunk.length;
        if (totalBytes > this.maxBodyBytes) {
          settled = true;
          chunks.length = 0; // Release buffered memory immediately before JSON parse
          req.pause();
          return reject(new Error('PAYLOAD_TOO_LARGE'));
        }
        chunks.push(chunk);
      });

      req.on('end', () => {
        if (settled) return;
        settled = true;
        try {
          const bodyStr = Buffer.concat(chunks).toString('utf8');
          chunks.length = 0;
          const parsed = bodyStr ? JSON.parse(bodyStr) : {};
          if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
            return reject(new Error('INVALID_JSON'));
          }
          resolve(parsed);
        } catch (err) {
          reject(new Error('INVALID_JSON'));
        }
      });

      req.on('error', (err) => {
        if (settled) return;
        settled = true;
        chunks.length = 0;
        reject(err);
      });
    });
  }

  /**
   * Picks the Node transport matching the upstream URL scheme (SEC-08).
   * @param {string} protocol - e.g. 'https:' or 'http:'
   */
  _selectTransport(protocol) {
    if (protocol === 'https:') return https;
    if (protocol === 'http:') return http;
    throw new Error(`Unsupported upstream protocol '${protocol}'`);
  }

  /**
   * Forwards certified-safe traffic to upstream LLM API over http or https.
   * @private
   */
  _forwardToUpstream(body, originalHeaders) {
    return new Promise((resolve, reject) => {
      let url;
      let transport;
      try {
        url = new URL(this.upstreamUrl);
        transport = this._selectTransport(url.protocol);
      } catch (err) {
        return reject(err);
      }
      const payload = JSON.stringify(body);

      const options = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
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

      const upstreamReq = transport.request(options, (upstreamRes) => {
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
   * Removes every rate-limit window that has already expired.
   * @private
   */
  _pruneRateLimitCounters(now = Date.now()) {
    for (const [key, counter] of this.rateLimitCounters) {
      if ((now - counter.windowStart) > this.rateLimitWindowMs) {
        this.rateLimitCounters.delete(key);
      }
    }
    this.lastRatePruneAt = now;
  }

  /**
   * Sliding window rate limiter per remote address with bounded memory (SEC-08).
   * Fail-closed: if the table is full of live (unexpired) entries, new keys are refused.
   * @private
   * @returns {{ allowed: boolean, reason?: string }}
   */
  _checkRateLimit(clientKey) {
    const now = Date.now();

    // Periodic pruning (at most once per second, or immediately when at capacity)
    if ((now - this.lastRatePruneAt) > 1000 || this.rateLimitCounters.size >= this.maxRateLimitEntries) {
      this._pruneRateLimitCounters(now);
    }

    const counter = this.rateLimitCounters.get(clientKey);

    if (!counter || (now - counter.windowStart) > this.rateLimitWindowMs) {
      if (!counter && this.rateLimitCounters.size >= this.maxRateLimitEntries) {
        return {
          allowed: false,
          reason: `Rate-limit table saturated (${this.maxRateLimitEntries} live entries); refusing new clients (fail-closed).`
        };
      }
      this.rateLimitCounters.set(clientKey, { count: 1, windowStart: now });
      return { allowed: true };
    }

    counter.count++;
    if (counter.count > this.rateLimitMax) {
      return {
        allowed: false,
        reason: `Client '${clientKey}' exceeded ${this.rateLimitMax} requests per ${this.rateLimitWindowMs / 1000}s window`
      };
    }

    return { allowed: true };
  }
}
