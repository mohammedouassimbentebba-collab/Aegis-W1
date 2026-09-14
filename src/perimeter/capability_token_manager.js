/**
 * W1™ Cryptographic Capability Token Manager
 *
 * Implements Capability-Based Security (Zero Ambient Authority).
 * Agents possess zero implicit rights. All operations require an explicitly
 * signed, scope-restricted, time-bounded cryptographic token.
 *
 * REMEDIATION (V-05):
 * Single-Use Monotonic Nonce Tracking: Each token is immediately consumed
 * upon verification to prevent replay attacks within its validity window.
 */

import { createHmac } from 'node:crypto';

export class CapabilityTokenManager {
  constructor(secretKey = 'w1_fortress_immutable_master_key', options = {}) {
    this.secretKey = secretKey;
    this.revocationList = new Set();
    this.consumedTokens = new Set();
    this.enforceSingleUseByDefault = options.enforceSingleUse !== undefined ? options.enforceSingleUse : true;
  }

  /**
   * Issues a signed capability token for an authorized operation.
   */
  issueToken({ agentId, allowedAction, allowedResource, ttlSeconds = 60, singleUse = null }) {
    const tokenId = crypto.randomUUID();
    const issuedAt = Date.now();
    const expiresAt = issuedAt + (ttlSeconds * 1000);
    const isSingleUse = singleUse !== null ? singleUse : this.enforceSingleUseByDefault;

    const payload = JSON.stringify({
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
   * Verifies the cryptographic integrity and validity of a presented token.
   * By default, consumes single-use tokens upon successful verification.
   */
  verifyToken(token, requestedAction, requestedResource, consume = true) {
    if (!token || !token.signature || !token.tokenId) {
      return { valid: false, reason: 'Malformed or missing capability token' };
    }

    if (Date.now() > token.expiresAt) {
      return { valid: false, reason: 'Capability token expired' };
    }

    // 1. Recompute and verify signature FIRST (Authentication before authorization state)
    const payloadWithSingleUse = JSON.stringify({
      tokenId: token.tokenId,
      agentId: token.agentId,
      allowedAction: token.allowedAction,
      allowedResource: token.allowedResource,
      issuedAt: token.issuedAt,
      expiresAt: token.expiresAt,
      singleUse: token.singleUse !== undefined ? token.singleUse : true
    });

    const payloadLegacy = JSON.stringify({
      tokenId: token.tokenId,
      agentId: token.agentId,
      allowedAction: token.allowedAction,
      allowedResource: token.allowedResource,
      issuedAt: token.issuedAt,
      expiresAt: token.expiresAt
    });

    const sigWithSingleUse = createHmac('sha256', this.secretKey).update(payloadWithSingleUse).digest('hex');
    const sigLegacy = createHmac('sha256', this.secretKey).update(payloadLegacy).digest('hex');

    if (token.signature !== sigWithSingleUse && token.signature !== sigLegacy) {
      return { valid: false, reason: 'Cryptographic signature mismatch: token was forged or tampered with' };
    }

    // 2. Check revocation list
    if (this.revocationList.has(token.tokenId)) {
      return { valid: false, reason: 'Capability token has been revoked by military command' };
    }

    // 3. Check single-use consumption
    if (this.consumedTokens.has(token.tokenId)) {
      return { valid: false, reason: 'Capability token already consumed (single-use nonce exhausted)' };
    }

    // 4. Check scope match (allow wildcard '*')
    if (token.allowedAction !== '*' && token.allowedAction !== requestedAction) {
      return { valid: false, reason: `Action scope mismatch: token allows '${token.allowedAction}', requested '${requestedAction}'` };
    }

    if (token.allowedResource !== '*' && token.allowedResource !== requestedResource) {
      return { valid: false, reason: `Resource scope mismatch: token allows '${token.allowedResource}', requested '${requestedResource}'` };
    }

    // 5. Mark token as consumed if single-use
    const shouldConsume = consume && (token.singleUse !== false);
    if (shouldConsume) {
      this.consumedTokens.add(token.tokenId);
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
   * Verifies that a capability token is cryptographically valid and bound to the requested HTTP verb and path.
   */
  verifyHttpBinding(token, method, path, consume = true) {
    return this.verifyToken(token, method.toUpperCase(), path, consume);
  }

  revokeToken(tokenId) {
    this.revocationList.add(tokenId);
  }

  isConsumed(tokenId) {
    return this.consumedTokens.has(tokenId);
  }
}

