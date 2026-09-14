/**
 * W1™ Runtime Integrity & Anti-Monkey-Patching Guard (حارس سلامة الذاكرة وبيئة التشغيل)
 * File: src/enclave/runtime_integrity_guard.js
 *
 * Core Responsibility:
 * Prevents in-process agents from tampering with guardrails via JavaScript reflection:
 * 1. Prototype pollution attacks (`Object.prototype` pollution).
 * 2. Monkey-patching defense classes (e.g. rewriting `watchdog.validateCommand = () => true`).
 * 3. Replacing global safety references in memory.
 */

import crypto from 'node:crypto';
import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';

export class RuntimeIntegrityGuard {
  constructor() {
    this.name = 'W1_Runtime_Integrity_Guard';
    this.registeredComponents = new Map(); // name -> { instance, methodSnapshots, baselineHash }
    this.integrityViolations = [];
    this.prototypesFrozen = false;
  }

  /**
   * Seals core runtime prototypes to prevent Prototype Pollution.
   */
  sealCorePrototypes() {
    try {
      // Seal prototypes so new properties cannot be injected
      Object.seal(Object.prototype);
      Object.seal(Function.prototype);
      Object.seal(Array.prototype);
      this.prototypesFrozen = true;
      return { success: true, message: 'Core prototypes sealed successfully' };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Registers a critical defense component and snapshots its original methods for integrity checks.
   */
  registerComponent(name, instance, methodNames = []) {
    const methodSnapshots = new Map();
    const stringifiedMethods = [];

    const protoProps = Object.getPrototypeOf(instance) ? Object.getOwnPropertyNames(Object.getPrototypeOf(instance)) : [];
    const ownProps = Object.getOwnPropertyNames(instance);
    const candidateProps = Array.from(new Set([...protoProps, ...ownProps]));

    const targetMethods = (methodNames && methodNames.length > 0)
      ? methodNames
      : candidateProps.filter(m => m !== 'constructor' && typeof instance[m] === 'function');

    for (const method of targetMethods) {
      if (typeof instance[method] === 'function') {
        const fnStr = instance[method].toString();
        methodSnapshots.set(method, {
          reference: instance[method],
          strRep: fnStr
        });
        stringifiedMethods.push(`${method}:${fnStr}`);
      }
    }

    const baselineHash = crypto.createHash('sha256')
      .update(stringifiedMethods.join('|'))
      .digest('hex');

    this.registeredComponents.set(name, {
      instance,
      methodSnapshots,
      baselineHash
    });
  }

  /**
   * Scans all registered defense instances and prototypes to ensure zero monkey-patching.
   */
  verifyIntegrity(agentId = 'system_monitor') {
    const violations = [];

    // 1. Prototype Pollution Check
    const probe = {};
    if (probe.__proto__ && (probe.polluted !== undefined || probe.isAdmin !== undefined || probe.bypassed !== undefined)) {
      violations.push({
        type: 'PROTOTYPE_POLLUTION_DETECTED',
        target: 'Object.prototype',
        detail: 'Rogue property discovered on Object prototype.'
      });
    }

    // 2. Component Method Monkey-Patching Check
    for (const [compName, compMeta] of this.registeredComponents.entries()) {
      const currentMethodStrings = [];

      for (const [methodName, methodData] of compMeta.methodSnapshots.entries()) {
        const currentFn = compMeta.instance[methodName];

        if (typeof currentFn !== 'function') {
          violations.push({
            type: 'METHOD_DELETED_OR_OVERWRITTEN',
            component: compName,
            method: methodName,
            detail: `Method '${methodName}' is no longer a function.`
          });
          continue;
        }

        // Check reference identity
        if (currentFn !== methodData.reference) {
          violations.push({
            type: 'MONKEY_PATCH_DETECTED',
            component: compName,
            method: methodName,
            detail: `Method '${methodName}' was replaced by a foreign reference in memory.`
          });
        }

        currentMethodStrings.push(`${methodName}:${currentFn.toString()}`);
      }

      const currentHash = crypto.createHash('sha256')
        .update(currentMethodStrings.join('|'))
        .digest('hex');

      if (currentHash !== compMeta.baselineHash) {
        violations.push({
          type: 'COMPONENT_HASH_MISMATCH',
          component: compName,
          detail: `In-memory cryptographic hash mismatch for '${compName}'. Code was tampered with.`
        });
      }
    }

    if (violations.length > 0) {
      const threat = new ThreatDetectionEvent({
        domain: ThreatDomain.DETERMINISTIC_KERNEL,
        severity: ThreatSeverity.CRITICAL,
        sourceAgentId: agentId,
        description: `Runtime Integrity Guard: In-process memory tampering or monkey-patching detected (${violations.length} violations).`,
        confidence: 1.0,
        telemetry: { violations }
      });

      this.integrityViolations.push({
        agentId,
        timestamp: Date.now(),
        violations
      });

      return {
        intact: false,
        violations,
        threat
      };
    }

    return { intact: true };
  }
}
