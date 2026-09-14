/**
 * W1™ On-Device LLM & Mobile Agent Safety Bridge (جسر نماذج الذكاء الاصطناعي على الهواتف)
 * File: src/android_platform/on_device_agent_bridge.js
 *
 * Core Responsibility:
 * Connects on-device small language models (MediaPipe LLM, Gemma 2B/4B Nano, local llama.cpp)
 * to the W1 Hermetic Work Tent and Android Security Enclave.
 *
 * Enforces:
 * 1. Pre-Action Thought Tomography on the mobile agent's reasoning before touching mobile APIs.
 * 2. Mobile Storage Geofencing (restricting file ops strictly to internal app files).
 * 3. Single-use Cryptographic Capability Tokens for hardware and radar invocation.
 */

import path from 'node:path';
import { CapabilityTokenManager } from '../perimeter/capability_token_manager.js';
import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';

export class OnDeviceAgentBridge {
  constructor(options = {}) {
    this.name = 'W1_On_Device_Agent_Bridge';
    this.appPackage = options.appPackage || 'org.w1.defense';
    this.tent = options.tent; // Instance of HermeticWorkTent
    this.tokenManager = options.tokenManager || (this.tent ? this.tent.tokenManager : new CapabilityTokenManager());
    this.agentId = options.agentId || 'mobile_on_device_agent';
    this.internalFilesDir = path.resolve(options.internalFilesDir || './workspace/android_files');
    this.telemetryLog = [];
  }

  /**
   * Primary Entrypoint for Mobile On-Device Tool Calls:
   * Ingests reasoning, validates intent, issues token, and executes tool under tent invariants.
   */
  async executeMobileToolCall({ toolName, arguments: rawArgs = {}, scratchpad = '' }) {
    const t0 = performance.now();

    // 1. Pre-Action Thought Tomography on mobile agent reasoning
    if (scratchpad && this.tent && this.tent.watchdog) {
      const thoughtScan = this.tent.watchdog.inspectScratchpad(this.agentId, scratchpad);
      if (!thoughtScan.clean) {
        this.tent.triggerContainmentAlarm(thoughtScan.violationType, thoughtScan.reason, thoughtScan.threat);
        return {
          success: false,
          escapeDetected: true,
          status: 'MOBILE_COGNITIVE_DECEPTION_INTERCEPTED',
          reason: thoughtScan.reason,
          threat: thoughtScan.threat
        };
      }
    }

    // 2. Mobile Specific Security Checks
    const mobileCheck = this.validateMobileConstraints(toolName, rawArgs);
    if (!mobileCheck.allowed) {
      const threat = new ThreatDetectionEvent({
        domain: ThreatDomain.AIR_DEFENSE,
        severity: ThreatSeverity.CRITICAL,
        sourceAgentId: this.agentId,
        description: `On-Device Mobile Bridge: ${mobileCheck.reason}`,
        confidence: 1.0,
        telemetry: { toolName, rawArgs, violationType: mobileCheck.violationType }
      });

      if (this.tent) {
        this.tent.triggerContainmentAlarm(mobileCheck.violationType, mobileCheck.reason, threat);
      }

      return {
        success: false,
        escapeDetected: true,
        status: mobileCheck.violationType,
        reason: mobileCheck.reason,
        threat
      };
    }

    // 3. Issue single-use capability token for mobile resource
    const mappedAction = this.mapMobileToolToTentAction(toolName);
    const targetResource = rawArgs.path || rawArgs.targetPackage || mappedAction;
    const token = this.tokenManager.issueToken({
      agentId: this.agentId,
      allowedAction: mappedAction,
      allowedResource: targetResource,
      ttlSeconds: 60,
      singleUse: true
    });

    // 4. Dispatch through Hermetic Work Tent
    let executionResult;
    if (this.tent) {
      executionResult = await this.tent.executeTentAction({
        action: mappedAction,
        params: rawArgs,
        capabilityToken: token,
        scratchpad
      });
    } else {
      executionResult = {
        success: true,
        status: 'MOBILE_TOOL_EXECUTED_MOCK',
        toolName,
        params: rawArgs
      };
    }

    this.telemetryLog.push({
      toolName,
      success: executionResult.success,
      durationMs: performance.now() - t0,
      timestamp: Date.now()
    });

    return executionResult;
  }

  /**
   * Validates mobile platform constraints:
   * - Restricts storage to internalFilesDir (denies /sdcard/, /data/data/com.other/)
   * - Restricts Intent target package to authorized appPackage
   * - Blocks access to forbidden hardware (Camera, Mic, SMS)
   */
  validateMobileConstraints(toolName, args = {}) {
    const tName = (toolName || '').toUpperCase();

    // Check 1: Storage geofencing
    if (args.path) {
      const normalizedTarget = path.resolve(args.path).replace(/\\/g, '/');
      const normalizedRoot = this.internalFilesDir.replace(/\\/g, '/');

      if (
        normalizedTarget.includes('/data/data/') && !normalizedTarget.startsWith(normalizedRoot) ||
        normalizedTarget.includes('/sdcard/') ||
        normalizedTarget.includes('/storage/emulated/') ||
        !normalizedTarget.startsWith(normalizedRoot)
      ) {
        return {
          allowed: false,
          violationType: 'ANDROID_APP_SANDBOX_BREACH',
          reason: `Access to external or cross-app path '${args.path}' is blocked by Android App Sandbox.`
        };
      }
    }

    // Check 2: Explicit Intent validation
    if (tName.includes('INTENT') || tName === 'START_ACTIVITY') {
      const targetPackage = args.targetPackage || args.packageName;
      if (!targetPackage || targetPackage !== this.appPackage) {
        return {
          allowed: false,
          violationType: 'IMPLICIT_INTENT_LEAK_BLOCKED',
          reason: `Intent must explicitly target authorized package '${this.appPackage}'. Target was: '${targetPackage}'.`
        };
      }
    }

    // Check 3: Forbidden ambient mobile sensor access
    const forbiddenMobileTools = new Set([
      'RECORD_AUDIO',
      'CAPTURE_CAMERA',
      'SEND_SMS',
      'READ_CONTACTS',
      'QUERY_FINE_LOCATION'
    ]);

    if (forbiddenMobileTools.has(tName)) {
      return {
        allowed: false,
        violationType: 'DANGEROUS_MOBILE_SENSOR_DENIED',
        reason: `Access to sensitive mobile hardware '${toolName}' is forbidden without explicit human-in-the-loop grant.`
      };
    }

    return { allowed: true };
  }

  /**
   * Maps mobile tool names to HermeticWorkTent action types
   */
  mapMobileToolToTentAction(toolName) {
    const tName = (toolName || '').toUpperCase();
    if (tName === 'READ_MOBILE_FILE') return 'READ_FILE';
    if (tName === 'WRITE_MOBILE_FILE') return 'WRITE_FILE';
    if (tName === 'INVOKE_NEON_RADAR') return 'RUN_IN_TENT_SCRIPT';
    return toolName;
  }
}
