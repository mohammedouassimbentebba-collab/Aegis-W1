/**
 * W1™ Cryptographic Capability Token Manager
 *
 * Implements Capability-Based Security (Zero Ambient Authority).
 * Agents possess zero implicit rights. All operations require an explicitly
 * signed, scope-restricted, time-bounded cryptographic token.
 *
 * REMEDIATION (V-05): Single-Use Monotonic Nonce Tracking
 * REMEDIATION (V-06): Timing-Safe HMAC Comparison (crypto.timingSafeEqual)
 * REMEDIATION (V-07): Hardcoded Key Elimination — env var or strong random
 * REMEDIATION (V-08): Consumed-Token Pruning — prevents unbounded memory growth
 */

import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';

/**
 * Maximum number of consumed token entries before forced pruning.
 * Prevents memory exhaustion under sustained high-throughput verification.
 */
const MAX_CONSUMED_ENTRIES = 10000;

export class CapabilityTokenManager {
  /**
   * @param {string|null} secretKey - HMAC-SHA256 signing key. If null, reads
   *   from W1_CAPABILITY_HMAC_KEY env var or generates a strong ephemeral key.
   * @param {Object} options
   * @param {boolean} [options.enforceSingleUse=true] - Whether tokens are single-use by default.
   * @param {boolean} [options.suppressKeyWarning=false] - Suppress the auto-generated key warning (for tests).
   */
  constructor(secretKey = null, options = {}) {
    if (secretKey) {
      this.secretKey = secretKey;
    } else if (process.env.W1_CAPABILITY_HMAC_KEY) {
      this.secretKey = process.env.W1_CAPABILITY_HMAC_KEY;
    } else {
      // Generate a cryptographically strong ephemeral key
      this.secretKey = randomBytes(32).toString('hex');
      if (!options.suppressKeyWarning) {
        // In production, W1_CAPABILITY_HMAC_KEY MUST be set
        console.warn(
          '[W1™ SECURITY WARNING] No HMAC key provided and W1_CAPABILITY_HMAC_KEY env var not set. ' +
          'Using auto-generated ephemeral key. Tokens will NOT survive process restarts. ' +
          'Set W1_CAPABILITY_HMAC_KEY for production deployments.'
        );
      }
    }

    this.revocationList = new Set();

    // Map<tokenId, expiresAt> — enables pruning of expired entries
    this.consumedTokens = new Map();

    this.maxConsumedEntries = options.maxConsumedEntries || MAX_CONSUMED_ENTRIES;
    this.stateStore = options.stateStore || null;

    this.enforceSingleUseByDefault = options.enforceSingleUse !== undefined
      ? options.enforceSingleUse
      : true;
  }

  /**
   * Issues a signed capability token for an authorized operation.
   * @param {Object} params
   * @param {string} params.agentId - Identity of the agent receiving this token.
   * @param {string} params.allowedAction - Permitted action (or '*' for wildcard).
   * @param {string} params.allowedResource - Permitted resource (or '*' for wildcard).
   * @param {number} [params.ttlSeconds=60] - Token time-to-live in seconds.
   * @param {boolean|null} [params.singleUse=null] - Override single-use enforcement.
   * @returns {Object} Signed capability token.
   */
  issueToken({ agentId, allowedAction, allowedResource, ttlSeconds = 60, singleUse = null }) {
    const tokenId = crypto.randomUUID();
    const issuedAt = Date.now();
    const expiresAt = issuedAt + (ttlSeconds * 1000);
    const isSingleUse = singleUse !== null ? singleUse : this.enforceSingleUseByDefault;

    const payload = this._buildPayload({
      tokenId,
      agentId,
      allowedAction,
      allowedResource,
      issuedAt,
      expiresAt,
      singleUse: isSingleUse
    });

    const signature = createHmac('sha256', this.secretKey)
      .update(payload)
      .digest('hex');

    return {
      tokenId,
      agentId,
      allowedAction,
      allowedResource,
      issuedAt,
      expiresAt,
      singleUse: isSingleUse,
      signature
    };
  }

  /**
   * Verifies the cryptographic integrity, temporal validity, scope match,
   * revocation status, and single-use nonce of a presented token.
   *
   * Uses constant-time comparison (crypto.timingSafeEqual) to prevent
   * timing side-channel attacks on HMAC signatures.
   *
   * @param {Object} token - The capability token to verify.
   * @param {string} requestedAction - The action the caller wants to perform.
   * @param {string} requestedResource - The resource the caller wants to access.
   * @param {boolean} [consume=true] - Whether to mark the token as consumed upon success.
   * @returns {{ valid: boolean, reason?: string }}
   */
  verifyToken(token, requestedAction, requestedResource, consume = true) {
    // 0. Structural validation (fail-closed)
    if (!token || typeof token !== 'object') {
      return { valid: false, reason: 'Malformed or missing capability token' };
    }

    if (!token.signature || !token.tokenId || !token.agentId) {
      return { valid: false, reason: 'Structurally incomplete token: missing signature, tokenId, or agentId' };
    }

    // 1. Mandatory expiration enforcement — tokens without expiresAt are rejected
    if (token.expiresAt === undefined || token.expiresAt === null) {
      return { valid: false, reason: 'Token missing mandatory expiresAt field — indefinite tokens forbidden' };
    }

    if (Date.now() > token.expiresAt) {
      return { valid: false, reason: 'Capability token expired' };
    }

    // 2. Cryptographic HMAC-SHA256 Signature Verification (constant-time)
    const payload = this._buildPayload({
      tokenId: token.tokenId,
      agentId: token.agentId,
      allowedAction: token.allowedAction,
      allowedResource: token.allowedResource,
      issuedAt: token.issuedAt,
      expiresAt: token.expiresAt,
      singleUse: token.singleUse !== undefined ? token.singleUse : true
    });

    const expectedSig = createHmac('sha256', this.secretKey)
      .update(payload)
      .digest('hex');

    if (!this._timingSafeCompare(token.signature, expectedSig)) {
      return { valid: false, reason: 'Cryptographic signature mismatch: token was forged or tampered with' };
    }

    // 3. Check revocation list
    if (this.revocationList.has(token.tokenId)) {
      return { valid: false, reason: 'Capability token has been revoked by military command' };
    }

    // 4. Check single-use consumption (replay prevention across memory + durable store)
    if (this.consumedTokens.has(token.tokenId) || this.stateStore?.isNonceConsumedSync(`tok:${token.tokenId}`)) {
      return { valid: false, reason: 'Capability token already consumed (single-use nonce exhausted)' };
    }

    // 5. Scope verification (allow wildcard '*')
    if (token.allowedAction !== '*' && token.allowedAction !== requestedAction) {
      return { valid: false, reason: `Action scope mismatch: token allows '${token.allowedAction}', requested '${requestedAction}'` };
    }

    if (token.allowedResource !== '*' && token.allowedResource !== requestedResource) {
      return { valid: false, reason: `Resource scope mismatch: token allows '${token.allowedResource}', requested '${requestedResource}'` };
    }

    // 6. Mark token as consumed if single-use (SEC-11: never evict live nonces; fail-closed backpressure)
    const shouldConsume = consume && (token.singleUse !== false);
    if (shouldConsume) {
      if (this.stateStore) {
        const persistRes = this.stateStore.consumeNonceSync(`tok:${token.tokenId}`, token.expiresAt);
        if (!persistRes.consumed) {
          return {
            valid: false,
            reason: persistRes.alreadyUsed
              ? 'Capability token already consumed (single-use nonce exhausted)'
              : (persistRes.reason || 'Durable nonce persistence failed (fail-closed)')
          };
        }
      }
      if (this.consumedTokens.size >= this.maxConsumedEntries) {
        this._pruneExpiredConsumed();
      }
      if (this.consumedTokens.size >= this.maxConsumedEntries) {
        return {
          valid: false,
          reason: 'Nonce replay cache saturated with live entries; refusing single-use verification (fail-closed backpressure)'
        };
      }
      this.consumedTokens.set(token.tokenId, token.expiresAt);
    }

    return { valid: true };
  }

  /**
   * Issues a capability token bound explicitly to an HTTP method and resource path.
   */
  issueHttpToken({ agentId, method, path, ttlSeconds = 60, singleUse = true }) {
    return this.issueToken({
      agentId,
      allowedAction: method.toUpperCase(),
      allowedResource: path,
      ttlSeconds,
      singleUse
    });
  }

  /**
   * Verifies that a capability token is cryptographically valid and bound
   * to the requested HTTP verb and path.
   */
  verifyHttpBinding(token, method, path, consume = true) {
    return this.verifyToken(token, method.toUpperCase(), path, consume);
  }

  revokeToken(tokenId) {
    this.revocationList.add(tokenId);
  }

  isConsumed(tokenId) {
    return this.consumedTokens.has(tokenId) || Boolean(this.stateStore?.isNonceConsumedSync(`tok:${tokenId}`));
  }

  /**
   * Builds the canonical JSON payload for HMAC signing.
   * Field order is deterministic to ensure consistent signature generation.
   * @private
   */
  _buildPayload({ tokenId, agentId, allowedAction, allowedResource, issuedAt, expiresAt, singleUse }) {
    return JSON.stringify({
      tokenId,
      agentId,
      allowedAction,
      allowedResource,
      issuedAt,
      expiresAt,
      singleUse
    });
  }

  /**
   * Constant-time string comparison using crypto.timingSafeEqual.
   * Prevents timing side-channel attacks on HMAC signatures.
   * @private
   * @param {string} given - The signature provided by the caller.
   * @param {string} expected - The recomputed expected signature.
   * @returns {boolean}
   */
  _timingSafeCompare(given, expected) {
    const givenBuf = Buffer.from(String(given), 'utf8');
    const expectedBuf = Buffer.from(String(expected), 'utf8');

    // Length mismatch — still do a dummy comparison to avoid timing leak
    if (givenBuf.length !== expectedBuf.length) {
      // Compare against itself to burn the same CPU time
      timingSafeEqual(expectedBuf, expectedBuf);
      return false;
    }

    return timingSafeEqual(givenBuf, expectedBuf);
  }

  /**
   * Removes ONLY expired nonces. A consumed nonce whose token has not yet expired
   * is never evicted, because evicting it would re-enable replay of a still-valid token.
   * Expired tokens are rejected independently by the expiresAt check, so dropping them is safe.
   * @private
   */
  _pruneExpiredConsumed() {
    const now = Date.now();
    for (const [tokenId, expiresAt] of this.consumedTokens) {
      if (expiresAt < now) this.consumedTokens.delete(tokenId);
    }
  }
}
