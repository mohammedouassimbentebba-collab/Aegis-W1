/**
 * W1™ Production Defense Server Entrypoint (نقطة التشغيل الإنتاجية لخوادم الدفاع والبوابة)
 * File: src/server.js
 *
 * REMEDIATION (ARCH-15 / OPS-16):
 * - Replaces non-running `src/index.js` export-only entrypoint for `npm start` and systemd.
 * - Fail-Closed startup: refuses to boot if mandatory production secrets
 *   (W1_CAPABILITY_HMAC_KEY, W1_SUPERVISOR_SECRET) are missing, unless
 *   explicitly enabled for local tests via `allowEphemeralSecrets: true`.
 * - Launches both AiTestbedGateway and LiveAIFirewallProxy with unified FortressCommander.
 * - Handles SIGTERM and SIGINT for clean graceful shutdown.
 */

import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { CapabilityTokenManager } from './perimeter/capability_token_manager.js';
import { FortressCommander } from './orchestrator/fortress_commander.js';
import { AiTestbedGateway } from './ai_testbed/ai_testbed_gateway.js';
import { LiveAIFirewallProxy } from './perimeter/live_firewall_proxy.js';
import { HermeticWorkTent } from './enclave/hermetic_work_tent.js';
import { ContainerIsolationEngine } from './ai_testbed/container_isolation_engine.js';
import { SiemExporter } from './audit/siem_exporter.js';
import { DefenseStateStore } from './state/defense_state_store.js';

function computeShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const counts = new Map();
  for (let i = 0; i < str.length; i++) {
    counts.set(str[i], (counts.get(str[i]) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Validates that a cryptographic secret provides at least 256 bits of material
 * (>= 64 hex chars for hex strings, or >= 32 raw UTF-8 bytes otherwise) AND
 * exhibits genuine character diversity / Shannon entropy (rejects repeated chars
 * like `0000...`, `aaaa...`, short cycles, and trivial sequential patterns).
 */
export function assertMinimumSecretStrength(name, secretValue) {
  if (typeof secretValue !== 'string' || secretValue.length === 0) {
    throw new Error(
      `Fail-closed startup aborted: ${name} is missing or empty. ` +
      'Provide a cryptographically strong secret (minimum 32 bytes / 64 hex chars).'
    );
  }
  const isHex = /^[0-9a-fA-F]+$/.test(secretValue);
  const byteLength = isHex ? Math.floor(secretValue.length / 2) : Buffer.byteLength(secretValue, 'utf8');
  if ((isHex && secretValue.length < 64) || byteLength < 32) {
    throw new Error(
      `Fail-closed startup aborted: ${name} violates minimum 256-bit secret length ` +
      '(requires at least 32 bytes or 64 hex characters).'
    );
  }

  const normalized = isHex ? secretValue.toLowerCase() : secretValue;
  const distinctChars = new Set(normalized).size;
  const entropy = computeShannonEntropy(normalized);
  const doubled = normalized + normalized;
  const shortestPeriod = doubled.indexOf(normalized, 1);
  const isShortRepeatingCycle = shortestPeriod > 0 && shortestPeriod <= 16;

  // Detect monotonic +/-1 stepping patterns (e.g., 0123456789abcdef0123...)
  let monotonicSteps = 0;
  for (let i = 0; i < normalized.length - 1; i++) {
    if (Math.abs(normalized.charCodeAt(i + 1) - normalized.charCodeAt(i)) === 1) {
      monotonicSteps++;
    }
  }
  const monotonicRatio = normalized.length > 1 ? monotonicSteps / (normalized.length - 1) : 0;

  if (distinctChars < 8 || entropy < 3.0 || isShortRepeatingCycle || monotonicRatio >= 0.7) {
    throw new Error(
      `Fail-closed startup aborted: ${name} fails minimum cryptographic entropy/diversity checks ` +
      '(rejected repeated characters, periodic pattern, or sequential secret).'
    );
  }
}

/**
 * Validates and starts the W1™ Defense Gateway & Live Firewall Proxy daemons.
 * Fail-closed when required secrets are absent or weak.
 *
 * @param {Object} [options]
 * @param {string} [options.host]
 * @param {number} [options.gatewayPort]
 * @param {number} [options.proxyPort]
 * @param {string|null} [options.upstreamUrl]
 * @param {string} [options.capabilityHmacKey]
 * @param {string} [options.supervisorSecret]
 * @param {string} [options.iffSecret]
 * @param {number} [options.headersTimeoutMs=10000]
 * @param {number} [options.requestTimeoutMs=30000]
 * @param {number} [options.keepAliveTimeoutMs=5000]
 * @param {boolean} [options.allowEphemeralSecrets=false]
 * @param {boolean} [options.silent=false]
 */
export async function startDefenseServer(options = {}) {
  const allowEphemeral = Boolean(options.allowEphemeralSecrets);

  const capabilityHmacKey = options.capabilityHmacKey || process.env.W1_CAPABILITY_HMAC_KEY || null;
  const supervisorSecret = options.supervisorSecret || process.env.W1_SUPERVISOR_SECRET || null;
  const iffSecret = options.iffSecret || process.env.W1_IFF_SECRET || null;

  if (!allowEphemeral) {
    const missing = [];
    if (!capabilityHmacKey) missing.push('W1_CAPABILITY_HMAC_KEY');
    if (!supervisorSecret) missing.push('W1_SUPERVISOR_SECRET');
    if (missing.length > 0) {
      throw new Error(
        `Fail-closed startup aborted: missing mandatory security secrets [${missing.join(', ')}]. ` +
        'Configure these environment variables (see .env.example) before starting the W1 defense server.'
      );
    }
  }

  // Enforce 256-bit minimum strength on any operator-supplied secrets
  if (capabilityHmacKey) assertMinimumSecretStrength('W1_CAPABILITY_HMAC_KEY', capabilityHmacKey);
  if (supervisorSecret) assertMinimumSecretStrength('W1_SUPERVISOR_SECRET', supervisorSecret);
  if (iffSecret) assertMinimumSecretStrength('W1_IFF_SECRET', iffSecret);

  const effectiveHmacKey = capabilityHmacKey || randomBytes(32).toString('hex');
  const effectiveSupervisorSecret = supervisorSecret || randomBytes(32).toString('hex');
  const effectiveIffSecret = iffSecret || randomBytes(32).toString('hex');

  const host = options.host || process.env.W1_HOST || '127.0.0.1';
  const gatewayPort = options.gatewayPort !== undefined
    ? Number(options.gatewayPort)
    : Number(process.env.W1_GATEWAY_PORT || 8081);
  const proxyPort = options.proxyPort !== undefined
    ? Number(options.proxyPort)
    : Number(process.env.W1_PROXY_PORT || 8080);
  const upstreamUrl = options.upstreamUrl !== undefined
    ? options.upstreamUrl
    : (process.env.W1_UPSTREAM_URL || null);

  const headersTimeoutMs = Number(options.headersTimeoutMs ?? process.env.W1_HEADERS_TIMEOUT_MS ?? 10000);
  const requestTimeoutMs = Number(options.requestTimeoutMs ?? process.env.W1_REQUEST_TIMEOUT_MS ?? 30000);
  const keepAliveTimeoutMs = Number(options.keepAliveTimeoutMs ?? process.env.W1_KEEPALIVE_TIMEOUT_MS ?? 5000);

  const tokenManager = new CapabilityTokenManager(effectiveHmacKey, {
    suppressKeyWarning: Boolean(options.silent)
  });

  const auditLogPath = options.auditLogPath !== undefined
    ? options.auditLogPath
    : (process.env.W1_AUDIT_LOG_PATH || null);
  const siemWebhookUrl = options.siemWebhookUrl !== undefined
    ? options.siemWebhookUrl
    : (process.env.W1_SIEM_WEBHOOK_URL || null);

  const siemExporter = options.siemExporter || (
    (auditLogPath || siemWebhookUrl)
      ? new SiemExporter({ logPath: auditLogPath, webhookUrl: siemWebhookUrl })
      : null
  );

  const stateDbPath = options.stateDbPath !== undefined
    ? options.stateDbPath
    : (process.env.W1_STATE_DB_PATH || ':memory:');
  const stateStore = options.stateStore || new DefenseStateStore({ dbPath: stateDbPath });

  const isolationEngine = options.isolationEngine || new ContainerIsolationEngine();
  const isolationReadyPromise = options.deferRuntimeProbe
    ? Promise.resolve(isolationEngine.verifyHostRuntimePrerequisites())
    : isolationEngine.detectContainerRuntime();

  const commander = new FortressCommander({}, {
    tokenManager,
    stateStore,
    airDefenseOptions: { iffSecretKey: effectiveIffSecret },
    siemExporter,
    onSecurityAuditEvent: options.onSecurityAuditEvent
  });

  const defaultTent = new HermeticWorkTent({
    agentId: 'gateway_agent_01',
    tokenManager,
    supervisorSecret: effectiveSupervisorSecret
  });

  let gateway = null;
  let proxy = null;

  // Sanitized enterprise Kubernetes-style liveness/readiness probe responder (zero secret/path leakage)
  const probeHandler = (pathname) => {
    if (pathname === '/healthz') {
      return {
        statusCode: 200,
        body: { status: 'alive', service: 'w1-defense' }
      };
    }

    const isolationReady = Boolean(isolationEngine.initialized);
    const gatewayReady = Boolean(gateway?.server?.listening);
    const proxyReady = Boolean(proxy?.server?.listening);
    const allReady = isolationReady && gatewayReady && proxyReady;

    return {
      statusCode: allReady ? 200 : 503,
      body: {
        status: allReady ? 'ready' : 'not_ready',
        service: 'w1-defense',
        checks: {
          isolationEngine: isolationReady ? 'ready' : 'initializing',
          gateway: gatewayReady ? 'ready' : 'starting',
          proxy: proxyReady ? 'ready' : 'starting'
        }
      }
    };
  };

  gateway = new AiTestbedGateway({
    host,
    port: gatewayPort,
    tent: defaultTent,
    containerEngine: isolationEngine,
    supervisorSecret: effectiveSupervisorSecret,
    probeHandler
  });

  proxy = new LiveAIFirewallProxy(commander, {
    port: proxyPort,
    upstreamUrl,
    requestTimeoutMs,
    stateStore,
    probeHandler
  });

  const gatewayInfo = await gateway.start();
  const proxyInfo = await proxy.start();

  // Apply strict Slowloris & HTTP socket timeouts across both daemons
  for (const httpSrv of [gateway.server, proxy.server]) {
    if (httpSrv) {
      httpSrv.headersTimeout = headersTimeoutMs;
      httpSrv.requestTimeout = requestTimeoutMs;
      httpSrv.keepAliveTimeout = keepAliveTimeoutMs;
    }
  }

  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    await Promise.allSettled([
      gateway.stop(),
      proxy.stop(),
      siemExporter ? siemExporter.flush() : Promise.resolve(),
      !options.stateStore && stateStore ? stateStore.close() : Promise.resolve()
    ]);
  };

  if (!options.silent) {
    console.log(JSON.stringify({
      event: 'W1_DEFENSE_SERVER_STARTED',
      mode: proxy.mode,
      gateway: `http://${gatewayInfo.host}:${gatewayInfo.port}`,
      proxy: proxyInfo.address,
      timestamp: new Date().toISOString()
    }));
  }

  return {
    gateway,
    proxy,
    commander,
    tokenManager,
    stateStore,
    isolationEngine,
    isolationReadyPromise,
    siemExporter,
    gatewayInfo,
    proxyInfo,
    stop
  };
}

// Direct CLI execution entrypoint (supports SIGTERM & SIGINT graceful shutdown)
let isMainModule = false;
if (process.argv[1]) {
  try {
    isMainModule = realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    isMainModule = false;
  }
}
if (isMainModule) {
  let activeServer = null;

  const shutdown = async (signal) => {
    console.log(JSON.stringify({ event: 'W1_DEFENSE_SERVER_SHUTDOWN', signal }));
    try {
      if (activeServer) await activeServer.stop();
      process.exit(0);
    } catch (err) {
      console.error(JSON.stringify({ event: 'W1_SHUTDOWN_ERROR', error: err.message }));
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  startDefenseServer()
    .then((srv) => {
      activeServer = srv;
    })
    .catch((err) => {
      console.error(JSON.stringify({ event: 'W1_STARTUP_FAILED', error: err.message }));
      process.exit(1);
    });
}
