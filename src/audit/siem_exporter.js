/**
 * W1™ Enterprise SOC/SIEM Audit Exporter
 * File: src/audit/siem_exporter.js
 *
 * Non-blocking audit sink supporting:
 * 1. Append-only NDJSON audit log file (W1_AUDIT_LOG_PATH) with serialized write queue.
 * 2. Asynchronous HTTPS Webhook dispatch (W1_SIEM_WEBHOOK_URL) with short AbortSignal timeout.
 *
 * Never blocks or crashes the core defense execution pipeline on sink I/O errors.
 */

import fs from 'node:fs';
import path from 'node:path';

export class SiemExporter {
  /**
   * @param {Object} [options]
   * @param {string|null} [options.logPath]
   * @param {string|null} [options.webhookUrl]
   * @param {number} [options.timeoutMs=2000]
   * @param {number} [options.maxInFlightWebhooks=64]
   * @param {Object} [options.headers]
   * @param {Function} [options.fetchFn]
   * @param {boolean} [options.allowInsecureWebhookForTests=false]
   */
  constructor(options = {}) {
    this.logPath = options.logPath !== undefined
      ? options.logPath
      : (process.env.W1_AUDIT_LOG_PATH || null);
    this.webhookUrl = options.webhookUrl !== undefined
      ? options.webhookUrl
      : (process.env.W1_SIEM_WEBHOOK_URL || null);
    this.timeoutMs = Number(options.timeoutMs || process.env.W1_SIEM_TIMEOUT_MS || 2000);
    this.maxInFlightWebhooks = Math.max(0, Number(options.maxInFlightWebhooks ?? 64));
    this.headers = options.headers || {};
    this.fetchFn = options.fetchFn || globalThis.fetch;

    if (this.webhookUrl) {
      let parsed;
      try {
        parsed = new URL(this.webhookUrl);
      } catch {
        throw new Error(`Fail-closed: Invalid W1_SIEM_WEBHOOK_URL '${this.webhookUrl}'.`);
      }
      if (parsed.protocol !== 'https:' && !options.allowInsecureWebhookForTests) {
        throw new Error(
          `Fail-closed: W1_SIEM_WEBHOOK_URL must use HTTPS (received '${parsed.protocol}').`
        );
      }
    }

    if (this.logPath) {
      fs.mkdirSync(path.dirname(path.resolve(this.logPath)), { recursive: true });
    }

    this._writeChain = Promise.resolve();
    this._inFlightWebhooks = new Set();

    this.metrics = {
      ndjsonWrites: 0,
      ndjsonErrors: 0,
      webhookDispatches: 0,
      webhookFailures: 0,
      droppedWebhookEvents: 0
    };
  }

  /**
   * Non-blocking export of a structured security audit event to NDJSON & HTTPS webhook.
   * Synchronous exceptions or transport rejections are isolated safely.
   *
   * @param {Object} event
   */
  exportEvent(event) {
    let serializedLine;
    try {
      serializedLine = JSON.stringify(event);
    } catch {
      this.metrics.ndjsonErrors++;
      return;
    }

    if (this.logPath) {
      this._writeChain = this._writeChain
        .then(() => fs.promises.appendFile(this.logPath, `${serializedLine}\n`, 'utf8'))
        .then(() => {
          this.metrics.ndjsonWrites++;
        })
        .catch(() => {
          this.metrics.ndjsonErrors++;
        });
    }

    if (this.webhookUrl && typeof this.fetchFn === 'function') {
      if (this._inFlightWebhooks.size >= this.maxInFlightWebhooks) {
        this.metrics.droppedWebhookEvents++;
        return;
      }

      const dispatch = (async () => {
        try {
          const res = await this.fetchFn(this.webhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...this.headers
            },
            body: serializedLine,
            signal: AbortSignal.timeout(this.timeoutMs)
          });
          if (res && res.ok === false) {
            this.metrics.webhookFailures++;
          } else {
            this.metrics.webhookDispatches++;
          }
        } catch {
          this.metrics.webhookFailures++;
        }
      })();

      this._inFlightWebhooks.add(dispatch);
      dispatch.finally(() => this._inFlightWebhooks.delete(dispatch));
    }
  }

  /**
   * Flushes all queued NDJSON file writes and in-flight webhook requests.
   */
  async flush() {
    await this._writeChain.catch(() => {});
    if (this._inFlightWebhooks.size > 0) {
      await Promise.allSettled([...this._inFlightWebhooks]);
    }
  }
}
