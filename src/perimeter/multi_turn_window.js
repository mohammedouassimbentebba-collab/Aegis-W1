/**
 * W1™ Multi-Turn Sliding Window Context Tracker
 * File: src/perimeter/multi_turn_window.js
 *
 * Detects fragmented / split-turn prompt injections and jailbreaks distributed
 * across multiple consecutive requests within a session/agent window.
 * Enforces strict per-session turn/byte caps and total tracked sessions ceiling.
 */

export class MultiTurnSessionWindow {
  /**
   * @param {Object} [options]
   * @param {number} [options.maxTurns=5] - Number of recent canonicalized turns retained per session.
   * @param {number} [options.windowMs=120000] - Time window in milliseconds for sliding aggregation.
   * @param {number} [options.maxSessionBytes=32768] - Maximum combined UTF-8 bytes per session window.
   * @param {number} [options.maxSessions=5000] - Maximum concurrent tracked sessions (memory DoS guard).
   */
  constructor(options = {}) {
    this.maxTurns = Math.max(2, Number(options.maxTurns ?? 5));
    this.windowMs = Math.max(1000, Number(options.windowMs ?? 120000));
    this.maxSessionBytes = Math.max(1024, Number(options.maxSessionBytes ?? 32768));
    this.maxSessions = Math.max(10, Number(options.maxSessions ?? 5000));
    this.sessions = new Map(); // sessionKey -> Array<{ text: string, bytes: number, timestamp: number }>
  }

  /**
   * Records a canonicalized prompt turn and returns the sliding-window aggregated
   * text when >= 2 turns exist in the active window.
   *
   * @param {string} agentId
   * @param {string} canonicalText
   * @param {string} [sessionId='default']
   * @param {number} [now=Date.now()]
   * @returns {{
   *   sessionKey: string,
   *   turnCount: number,
   *   combinedWindowText: string,
   *   shouldInspectWindow: boolean
   * }}
   */
  recordAndAggregate(agentId, canonicalText, sessionId = 'default', now = Date.now()) {
    const sessionKey = `${agentId || 'anonymous'}:${sessionId || 'default'}`;

    // Evict expired/oldest sessions if cap reached
    if (!this.sessions.has(sessionKey) && this.sessions.size >= this.maxSessions) {
      this._evictStaleOrOldest(now);
    }

    const cutoff = now - this.windowMs;
    const existing = (this.sessions.get(sessionKey) || []).filter((entry) => entry.timestamp >= cutoff);

    const trimmedText = this._capTurnText(String(canonicalText || ''), this.maxSessionBytes);
    if (trimmedText.length > 0) {
      existing.push({
        text: trimmedText,
        bytes: Buffer.byteLength(trimmedText, 'utf8'),
        timestamp: now
      });
    }

    // Keep at most maxTurns most recent entries
    while (existing.length > this.maxTurns) {
      existing.shift();
    }

    // Enforce strict per-session byte ceiling
    let totalBytes = existing.reduce((sum, e) => sum + e.bytes, 0);
    while (existing.length > 1 && totalBytes > this.maxSessionBytes) {
      const removed = existing.shift();
      totalBytes -= removed.bytes;
    }

    this.sessions.set(sessionKey, existing);

    return {
      sessionKey,
      turnCount: existing.length,
      combinedWindowText: existing.map((e) => e.text).join(' '),
      shouldInspectWindow: existing.length >= 2
    };
  }

  /**
   * Removes the most recently recorded turn if it was blocked as hostile so
   * rejected turns do not permanently taint future clean requests for the session.
   */
  rollbackLastTurn(agentId, sessionId = 'default') {
    const sessionKey = `${agentId || 'anonymous'}:${sessionId || 'default'}`;
    const entries = this.sessions.get(sessionKey);
    if (entries && entries.length > 0) {
      entries.pop();
      if (entries.length === 0) {
        this.sessions.delete(sessionKey);
      }
    }
  }

  /**
   * Clears a session's history explicitly.
   */
  clearSession(agentId, sessionId = 'default') {
    const sessionKey = `${agentId || 'anonymous'}:${sessionId || 'default'}`;
    this.sessions.delete(sessionKey);
  }

  /**
   * @private
   */
  _capTurnText(text, maxBytes) {
    if (Buffer.byteLength(text, 'utf8') <= maxBytes) return text;
    return Buffer.from(text, 'utf8').subarray(0, maxBytes).toString('utf8');
  }

  /**
   * @private
   */
  _evictStaleOrOldest(now) {
    const cutoff = now - this.windowMs;
    for (const [key, entries] of this.sessions) {
      const fresh = entries.filter((e) => e.timestamp >= cutoff);
      if (fresh.length === 0) {
        this.sessions.delete(key);
      } else {
        this.sessions.set(key, fresh);
      }
    }
    if (this.sessions.size >= this.maxSessions) {
      const oldestKey = this.sessions.keys().next().value;
      if (oldestKey !== undefined) {
        this.sessions.delete(oldestKey);
      }
    }
  }
}
