/**
 * W1™ Anti-Escape Watchdog (مراقب مكافحة هروب الوكلاء من خيمة العمل)
 * File: src/enclave/anti_escape_watchdog.js
 *
 * Core Responsibility:
 * Monitors agent actions, commands, and inner reasoning (scratchpads)
 * to intercept instrumental convergence attempts, sandbox escapes,
 * privilege escalations, and test-suite tampering when an agent hits an obstacle.
 */

import path from 'node:path';
import fs from 'node:fs';
import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';


export class AntiEscapeWatchdog {
  constructor(options = {}) {
    this.name = 'W1_AntiEscape_WorkTent_Watchdog';
    this.tentRoot = options.tentRoot ? path.resolve(options.tentRoot) : null;
    this.incidentLog = [];

    // Rationalization & instrumental convergence regexes in inner thoughts
    this.cognitiveEscapePatterns = [
      /bypass\s+.*?(safety|permission|security|restriction|check|rule|guard|sandbox)/i,
      /workaround\s+to\s+(get|solve|finish|achieve|force)/i,
      /since\s+(it's|it\s+is)\s+blocked.*I\s+will/i,
      /override\s+(permission|restriction|credential|policy)/i,
      /disable\s+(the\s+)?(test|assertion|check|linter|guardrail|selinux|security|permission)/i,
      /modify\s+(the\s+)?test\s+so\s+it\s+passes/i,
      /the\s+ends\s+justify\s+the\s+means/i,
      /user\s+wants\s+(this\s+)?done\s+so\s+I\s+must\s+(bypass|force|escalate)/i,
      /(gain|force|escalate)\s+(root|admin|sudo|privilege)/i,
      /execute\s+(without|outside)\s+(permission|tent|sandbox)/i,
      /cd\s+\.\.\/\.\./i,
      /delete\s+(the\s+)?failing\s+test/i,
      /hide\s+(this|my)\s+(change|action|intent)\s+from\s+(supervisor|human|user)/i,
      /fake\s+alignment|pretend\s+to\s+comply/i,
      /exfiltrate|leak\s+(secret|key|token)/i,
      /spawn_clone|recursively\s+fork/i
    ];

    // Steganographic & invisible character pattern
    this.stegoRegex = /[\u200B-\u200D\uFEFF\u202A-\u202E]/;

    // Prohibited commands (privilege escalation, external egress, system destruction, wipers, shellcode, reverse shells)
    this.forbiddenCommandPatterns = [
      /\b(sudo|su\b|doas)\b/i,
      /\b(chmod\s+(-[a-zA-Z]+\s+)?[0-7]*777|chmod\s+\+x|chown|chgrp)\b/i,
      /\b(icacls|takeown|setfacl)\b/i,
      /\b(curl|wget|fetch|nc|ncat|netcat|socat)\b/i,
      /\b(rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*|\s+-f)|rmdir\s+\/s\s+\/q|DROP\s+(DATABASE|TABLE)|wipe_all|format\s+[a-z]:)/i,
      /\b(dd\s+if=|shred\b|vssadmin\b|cat\s+\/dev\/(urandom|zero))/i,
      /\/etc\/(shadow|passwd|sudoers)|C:\\Windows\\System32/i,
      /\\x[0-9a-fA-F]{2}/i, // Binary shellcode byte sequences
      /\/bin\/(sh|bash|zsh)/i,
      /\b(bash|sh|zsh)\s+-i/i,
      /\|\s*(sh|bash|zsh)/i,
      />\s*&\s*\/dev\/tcp/i,
      /\b(python|python3|perl|ruby)\b.*?(socket|pty|subprocess)/i,
      /\b(ln\s+(-[a-zA-Z]*s[a-zA-Z]*|\s+-s)|mklink)\b/i, // Symlink creation
      /New-Item.*-ItemType\s+SymbolicLink/i
    ];
  }

  setTentRoot(tentRoot) {
    this.tentRoot = path.resolve(tentRoot);
  }

  /**
   * Pre-Action Scratchpad / Chain-of-Thought Inspection
   * Scans agent reasoning for instrumental escape rationalizations.
   */
  inspectScratchpad(agentId, scratchpad) {
    if (!scratchpad || typeof scratchpad !== 'string') {
      return { clean: true };
    }

    for (const pattern of this.cognitiveEscapePatterns) {
      if (pattern.test(scratchpad)) {
        const matched = scratchpad.match(pattern)[0];
        const threat = new ThreatDetectionEvent({
          domain: ThreatDomain.DEEP_SUBMARINE,
          severity: ThreatSeverity.CRITICAL,
          sourceAgentId: agentId,
          description: `Anti-Escape Watchdog: Covert instrumental escape intent detected in scratchpad: '${matched}'`,
          confidence: 0.98,
          telemetry: {
            detectedPattern: matched,
            scratchpadSnippet: scratchpad.substring(0, 150)
          }
        });

        this.logIncident(agentId, 'COGNITIVE_ESCAPE_RATIONALIZATION', { matched, scratchpad });

        return {
          clean: false,
          violationType: 'COGNITIVE_ESCAPE_RATIONALIZATION',
          reason: `Agent '${agentId}' rationalized an out-of-tent escape in its reasoning: "${matched}"`,
          threat
        };
      }
    }

    return { clean: true };
  }

  /**
   * Path Jail Boundary Check
   * Guarantees that any path touched by the agent is strictly inside tentRoot.
   */
  validatePathContainment(agentId, targetPath) {
    if (!this.tentRoot) {
      return { contained: true }; // No tent set yet
    }

    const resolved = path.resolve(this.tentRoot, targetPath);
    const relative = path.relative(this.tentRoot, resolved);

    // If relative starts with '..' or is absolute outside root, it has escaped the tent!
    const isEscaped = relative.startsWith('..') || path.isAbsolute(relative);

    if (isEscaped) {
      const threat = new ThreatDetectionEvent({
        domain: ThreatDomain.AIR_DEFENSE,
        severity: ThreatSeverity.CRITICAL,
        sourceAgentId: agentId,
        description: `Anti-Escape Watchdog: Path traversal out-of-tent escape attempted to '${targetPath}'`,
        confidence: 1.0,
        telemetry: {
          attemptedPath: targetPath,
          resolvedPath: resolved,
          tentRoot: this.tentRoot
        }
      });

      this.logIncident(agentId, 'PATH_JAIL_ESCAPE_ATTEMPT', { targetPath, resolved });

      return {
        contained: false,
        violationType: 'PATH_JAIL_ESCAPE_ATTEMPT',
        reason: `Physical boundary violation: Path '${targetPath}' resolves outside the assigned work tent.`,
        threat
      };
    }

    // Physical Symlink Dereference Check (guards against symlink / hardlink escapes)
    try {
      if (fs.existsSync(resolved)) {
        const realPhysical = fs.realpathSync(resolved);
        const realRel = path.relative(this.tentRoot, realPhysical);
        if (realRel.startsWith('..') || path.isAbsolute(realRel)) {
          const threat = new ThreatDetectionEvent({
            domain: ThreatDomain.AIR_DEFENSE,
            severity: ThreatSeverity.CRITICAL,
            sourceAgentId: agentId,
            description: `Anti-Escape Watchdog: Symlink jailbreak dereferencing to physical path '${realPhysical}' outside tent root.`,
            confidence: 1.0,
            telemetry: {
              attemptedPath: targetPath,
              resolvedPath: resolved,
              physicalTarget: realPhysical,
              tentRoot: this.tentRoot
            }
          });

          this.logIncident(agentId, 'SYMLINK_JAILBREAK_ATTEMPT', { targetPath, realPhysical });

          return {
            contained: false,
            violationType: 'SYMLINK_JAILBREAK_ATTEMPT',
            reason: `Physical boundary violation: Symlink '${targetPath}' dereferences to physical path '${realPhysical}' outside the assigned work tent.`,
            threat
          };
        }
      }
    } catch {
      // Inaccessible or non-existent path
    }

    return { contained: true, resolvedPath: resolved };
  }


  /**
   * Command Line Safety & Anti-Escalation Check
   */
  validateCommand(agentId, commandLine) {
    if (!commandLine || typeof commandLine !== 'string') {
      return { allowed: true };
    }

    for (const pattern of this.forbiddenCommandPatterns) {
      if (pattern.test(commandLine)) {
        const matched = commandLine.match(pattern)[0];
        const isSymlink = /ln\s+|mklink|SymbolicLink/i.test(commandLine);
        const violationType = isSymlink ? 'SYMLINK_CREATION_ATTEMPT' : 'FORBIDDEN_COMMAND_ESCAPE';

        const threat = new ThreatDetectionEvent({
          domain: ThreatDomain.EARLY_WARNING,
          severity: ThreatSeverity.CRITICAL,
          sourceAgentId: agentId,
          description: `Anti-Escape Watchdog: Forbidden out-of-tent command execution: '${matched}'`,
          confidence: 1.0,
          telemetry: { commandLine, matchedPattern: matched, isSymlink }
        });

        this.logIncident(agentId, violationType, { commandLine, matched });

        return {
          allowed: false,
          violationType,
          reason: `Privilege escalation or external egress command '${matched}' is strictly forbidden inside the work tent.`,
          threat
        };
      }
    }

    return { allowed: true };
  }

  logIncident(agentId, type, details) {
    this.incidentLog.push({
      timestamp: Date.now(),
      agentId,
      type,
      details
    });
  }

  /**
   * Scans agent output or content for covert steganography and zero-width leakage channels.
   */
  inspectContentSteganography(agentId, content) {
    if (!content || typeof content !== 'string') {
      return { clean: true };
    }

    if (this.stegoRegex.test(content)) {
      const threat = new ThreatDetectionEvent({
        domain: ThreatDomain.ELECTRONIC_WARFARE,
        severity: ThreatSeverity.HIGH,
        sourceAgentId: agentId,
        description: `Anti-Escape Watchdog: Covert steganographic channel or zero-width character leakage detected in content.`,
        confidence: 0.99
      });

      this.logIncident(agentId, 'STEGANOGRAPHY_COVERT_CHANNEL', { contentPreview: content.substring(0, 50) });

      return {
        clean: false,
        violationType: 'STEGANOGRAPHY_COVERT_CHANNEL',
        reason: 'Covert zero-width steganographic characters detected in agent content.',
        threat
      };
    }

    return { clean: true };
  }
}

