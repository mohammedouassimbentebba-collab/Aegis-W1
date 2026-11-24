/**
 * W1™ Durable Defense State Store (SQLite WAL + In-Memory Abstraction)
 * File: src/state/defense_state_store.js
 *
 * Persists critical security state across restarts & local worker processes:
 * - Quarantined agents (quarantined_agents)
 * - Consumed single-use nonces & IFF proofs (consumed_nonces) with TTL Sweeper
 * - Sliding-window rate-limiter counters (rate_limits)
 *
 * Defaults to SQLite WAL via Node 24's built-in `node:sqlite`, with an optional
 * `mode: 'memory'` backend for fast ephemeral tests.
 */

import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const DEFAULT_MAX_NONCES = 100000;
const DEFAULT_MAX_RATE_LIMITS = 50000;
const DEFAULT_SWEEP_INTERVAL_MS = 30000;

export class DefenseStateStore {
  /**
   * @param {Object} [options]
   * @param {'sqlite'|'memory'} [options.mode='sqlite']
   * @param {boolean} [options.memoryOnly=false]
   * @param {string} [options.dbPath] - File path for SQLite WAL database, or ':memory:'.
   * @param {number} [options.maxNonceEntries=100000]
   * @param {number} [options.maxRateLimitEntries=50000]
   * @param {number} [options.sweepIntervalMs=30000] - Set 0 to disable periodic timer.
   */
  constructor(options = {}) {
    this.mode = options.memoryOnly ? 'memory' : (options.mode || 'sqlite');
    this.dbPath = options.dbPath || process.env.W1_STATE_DB_PATH || ':memory:';
    this.maxNonceEntries = Math.max(10, Number(options.maxNonceEntries ?? DEFAULT_MAX_NONCES));
    this.maxRateLimitEntries = Math.max(10, Number(options.maxRateLimitEntries ?? DEFAULT_MAX_RATE_LIMITS));
    this.sweepIntervalMs = Number(options.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS);

    this.closed = false;
    this.db = null;
    this._stmts = null;

    // In-memory store state (also used when mode === 'memory')
    this._memQuarantine = new Map(); // agentId -> { reason, quarantinedAt }
    this._memNonces = new Map(); // nonceId -> expiresAt
    this._memRates = new Map(); // clientKey -> { count, windowStart, windowMs }

    if (this.mode === 'sqlite') {
      this._initSqlite();
    }

    this._sweeperTimer = null;
    if (this.sweepIntervalMs > 0) {
      this._sweeperTimer = setInterval(() => {
        if (!this.closed) {
          this.sweepExpiredSync();
        }
      }, this.sweepIntervalMs);
      if (typeof this._sweeperTimer.unref === 'function') {
        this._sweeperTimer.unref();
      }
    }
  }

  /**
   * @private
   */
  _initSqlite() {
    if (this.dbPath !== ':memory:') {
      fs.mkdirSync(path.dirname(path.resolve(this.dbPath)), { recursive: true });
    }
    this.db = new DatabaseSync(this.dbPath);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      PRAGMA busy_timeout = 5000;

      CREATE TABLE IF NOT EXISTS quarantined_agents (
        agent_id TEXT PRIMARY KEY,
        reason TEXT NOT NULL,
        quarantined_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS consumed_nonces (
        nonce_id TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_consumed_nonces_expires ON consumed_nonces(expires_at);

      CREATE TABLE IF NOT EXISTS rate_limits (
        client_key TEXT PRIMARY KEY,
        count INTEGER NOT NULL,
        window_start INTEGER NOT NULL,
        window_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);
    `);

    this._stmts = {
      getQuarantine: this.db.prepare('SELECT agent_id, reason, quarantined_at FROM quarantined_agents WHERE agent_id = ?'),
      setQuarantine: this.db.prepare(`
        INSERT INTO quarantined_agents (agent_id, reason, quarantined_at)
        VALUES (?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET reason = excluded.reason, quarantined_at = excluded.quarantined_at
      `),
      delQuarantine: this.db.prepare('DELETE FROM quarantined_agents WHERE agent_id = ?'),
      hasNonce: this.db.prepare('SELECT expires_at FROM consumed_nonces WHERE nonce_id = ?'),
      insertNonce: this.db.prepare('INSERT OR IGNORE INTO consumed_nonces (nonce_id, expires_at, consumed_at) VALUES (?, ?, ?)'),
      countNonces: this.db.prepare('SELECT COUNT(*) AS cnt FROM consumed_nonces'),
      sweepNonces: this.db.prepare('DELETE FROM consumed_nonces WHERE expires_at < ?'),
      getRate: this.db.prepare('SELECT count, window_start, window_ms FROM rate_limits WHERE client_key = ?'),
      upsertRate: this.db.prepare(`
        INSERT INTO rate_limits (client_key, count, window_start, window_ms)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(client_key) DO UPDATE SET
          count = excluded.count,
          window_start = excluded.window_start,
          window_ms = excluded.window_ms
      `),
      countRates: this.db.prepare('SELECT COUNT(*) AS cnt FROM rate_limits'),
      sweepRates: this.db.prepare('DELETE FROM rate_limits WHERE (window_start + window_ms) < ?')
    };
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Unified Async Public Interface
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  async isAgentQuarantined(agentId) {
    return this.isAgentQuarantinedSync(agentId);
  }

  async getQuarantineRecord(agentId) {
    if (!agentId) return null;
    if (this.mode === 'memory') {
      const rec = this._memQuarantine.get(agentId);
      return rec ? { agentId, ...rec } : null;
    }
    const row = this._stmts.getQuarantine.get(agentId);
    return row ? { agentId: row.agent_id, reason: row.reason, quarantinedAt: row.quarantined_at } : null;
  }

  async quarantineAgent(agentId, reason = 'Security invariant violation') {
    return this.quarantineAgentSync(agentId, reason);
  }

  async unquarantineAgent(agentId) {
    if (!agentId) return false;
    if (this.mode === 'memory') {
      return this._memQuarantine.delete(agentId);
    }
    const info = this._stmts.delQuarantine.run(agentId);
    return info.changes > 0;
  }

  async consumeNonce(nonceId, expiresAt = Date.now() + 60000) {
    return this.consumeNonceSync(nonceId, expiresAt);
  }

  async isNonceConsumed(nonceId) {
    return this.isNonceConsumedSync(nonceId);
  }

  async checkRateLimit(clientKey, maxRequests = 100, windowMs = 60000) {
    return this.checkRateLimitSync(clientKey, maxRequests, windowMs);
  }

  async sweepExpired(now = Date.now()) {
    return this.sweepExpiredSync(now);
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    if (this._sweeperTimer) {
      clearInterval(this._sweeperTimer);
      this._sweeperTimer = null;
    }
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Synchronous Fast-Path Methods (for Kernel, TokenManager, Proxy)
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  isAgentQuarantinedSync(agentId) {
    if (!agentId || this.closed) return false;
    if (this.mode === 'memory') {
      return this._memQuarantine.has(agentId);
    }
    return Boolean(this._stmts.getQuarantine.get(agentId));
  }

  quarantineAgentSync(agentId, reason = 'Security invariant violation', now = Date.now()) {
    if (!agentId || this.closed) return false;
    if (this.mode === 'memory') {
      this._memQuarantine.set(agentId, { reason: String(reason), quarantinedAt: now });
      return true;
    }
    this._stmts.setQuarantine.run(agentId, String(reason), now);
    return true;
  }

  isNonceConsumedSync(nonceId) {
    if (!nonceId || this.closed) return false;
    if (this.mode === 'memory') {
      return this._memNonces.has(nonceId);
    }
    return Boolean(this._stmts.hasNonce.get(nonceId));
  }

  consumeNonceSync(nonceId, expiresAt = Date.now() + 60000, now = Date.now()) {
    if (!nonceId) {
      return { consumed: false, alreadyUsed: false, reason: 'Missing nonceId' };
    }
    if (this.closed) {
      return { consumed: false, alreadyUsed: false, reason: 'DefenseStateStore is closed' };
    }
    if (expiresAt <= now) {
      return { consumed: false, alreadyUsed: false, reason: 'Token/nonce already expired' };
    }

    if (this.mode === 'memory') {
      if (this._memNonces.has(nonceId)) {
        return { consumed: false, alreadyUsed: true, reason: 'Nonce already consumed (replay blocked)' };
      }
      if (this._memNonces.size >= this.maxNonceEntries) {
        this.sweepExpiredSync(now);
      }
      if (this._memNonces.size >= this.maxNonceEntries) {
        return {
          consumed: false,
          alreadyUsed: false,
          saturated: true,
          reason: 'Nonce replay store saturated with live entries (fail-closed backpressure)'
        };
      }
      this._memNonces.set(nonceId, expiresAt);
      return { consumed: true, alreadyUsed: false };
    }

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this._stmts.hasNonce.get(nonceId);
      if (existing) {
        this.db.exec('COMMIT');
        return { consumed: false, alreadyUsed: true, reason: 'Nonce already consumed (replay blocked)' };
      }

      let count = Number(this._stmts.countNonces.get().cnt);
      if (count >= this.maxNonceEntries) {
        this._stmts.sweepNonces.run(now);
        count = Number(this._stmts.countNonces.get().cnt);
      }
      if (count >= this.maxNonceEntries) {
        this.db.exec('COMMIT');
        return {
          consumed: false,
          alreadyUsed: false,
          saturated: true,
          reason: 'Nonce replay store saturated with live entries (fail-closed backpressure)'
        };
      }

      const info = this._stmts.insertNonce.run(nonceId, expiresAt, now);
      this.db.exec('COMMIT');
      if (info.changes === 0) {
        return { consumed: false, alreadyUsed: true, reason: 'Nonce already consumed (replay blocked)' };
      }
      return { consumed: true, alreadyUsed: false };
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        // Ignore rollback failure
      }
      return { consumed: false, alreadyUsed: false, reason: `State store error: ${err.message}` };
    }
  }

  checkRateLimitSync(clientKey, maxRequests = 100, windowMs = 60000, now = Date.now()) {
    if (this.closed) {
      return { allowed: false, remaining: 0, reason: 'DefenseStateStore is closed (fail-closed)' };
    }
    const key = String(clientKey || 'unknown');

    if (this.mode === 'memory') {
      let rec = this._memRates.get(key);
      if (!rec || (now - rec.windowStart) >= windowMs) {
        if (!rec && this._memRates.size >= this.maxRateLimitEntries) {
          this.sweepExpiredSync(now);
        }
        if (!rec && this._memRates.size >= this.maxRateLimitEntries) {
          return {
            allowed: false,
            remaining: 0,
            reason: 'Rate limiter state saturated (fail-closed).'
          };
        }
        rec = { count: 1, windowStart: now, windowMs };
        this._memRates.set(key, rec);
        return { allowed: true, remaining: Math.max(0, maxRequests - 1), resetAt: now + windowMs };
      }
      rec.count += 1;
      if (rec.count > maxRequests) {
        return {
          allowed: false,
          remaining: 0,
          resetAt: rec.windowStart + windowMs,
          reason: `Rate limit exceeded: >${maxRequests} requests in ${windowMs}ms window.`
        };
      }
      return {
        allowed: true,
        remaining: Math.max(0, maxRequests - rec.count),
        resetAt: rec.windowStart + windowMs
      };
    }

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this._stmts.getRate.get(key);
      if (!existing || (now - existing.window_start) >= windowMs) {
        if (!existing) {
          let cnt = Number(this._stmts.countRates.get().cnt);
          if (cnt >= this.maxRateLimitEntries) {
            this._stmts.sweepRates.run(now);
            cnt = Number(this._stmts.countRates.get().cnt);
          }
          if (cnt >= this.maxRateLimitEntries) {
            this.db.exec('COMMIT');
            return { allowed: false, remaining: 0, reason: 'Rate limiter state saturated (fail-closed).' };
          }
        }
        this._stmts.upsertRate.run(key, 1, now, windowMs);
        this.db.exec('COMMIT');
        return { allowed: true, remaining: Math.max(0, maxRequests - 1), resetAt: now + windowMs };
      }

      const nextCount = existing.count + 1;
      this._stmts.upsertRate.run(key, nextCount, existing.window_start, windowMs);
      this.db.exec('COMMIT');

      if (nextCount > maxRequests) {
        return {
          allowed: false,
          remaining: 0,
          resetAt: existing.window_start + windowMs,
          reason: `Rate limit exceeded: >${maxRequests} requests in ${windowMs}ms window.`
        };
      }
      return {
        allowed: true,
        remaining: Math.max(0, maxRequests - nextCount),
        resetAt: existing.window_start + windowMs
      };
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        // Ignore rollback failure
      }
      return { allowed: false, remaining: 0, reason: `Rate limit store failure: ${err.message}` };
    }
  }

  sweepExpiredSync(now = Date.now()) {
    if (this.closed) return { noncesRemoved: 0, rateLimitsRemoved: 0 };

    if (this.mode === 'memory') {
      let noncesRemoved = 0;
      for (const [k, exp] of this._memNonces) {
        if (exp < now) {
          this._memNonces.delete(k);
          noncesRemoved++;
        }
      }
      let rateLimitsRemoved = 0;
      for (const [k, rec] of this._memRates) {
        if (rec.windowStart + rec.windowMs < now) {
          this._memRates.delete(k);
          rateLimitsRemoved++;
        }
      }
      return { noncesRemoved, rateLimitsRemoved };
    }

    const nonceInfo = this._stmts.sweepNonces.run(now);
    const rateInfo = this._stmts.sweepRates.run(now);
    return {
      noncesRemoved: Number(nonceInfo.changes || 0),
      rateLimitsRemoved: Number(rateInfo.changes || 0)
    };
  }
}
