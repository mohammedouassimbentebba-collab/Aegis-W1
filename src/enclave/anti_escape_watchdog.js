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
   * Helper: strict directory-separator containment check (SEC-12).
   * Prevents sibling-directory prefix collisions (e.g. "tent" vs "tent_evil").
   * @private
   */
  _isPathWithinRoot(targetPath, rootPath) {
    const normRoot = path.resolve(rootPath);
    const normTarget = path.resolve(targetPath);
    const cmpRoot = process.platform === 'win32' ? normRoot.toLowerCase() : normRoot;
    const cmpTarget = process.platform === 'win32' ? normTarget.toLowerCase() : normTarget;
    const rootWithSep = cmpRoot.endsWith(path.sep) ? cmpRoot : cmpRoot + path.sep;
    return cmpTarget === cmpRoot || cmpTarget.startsWith(rootWithSep);
  }

  /**
   * Path Jail Boundary Check (SEC-12: Fail-Closed, Separator Boundary & Dangling Symlink Check)
   * Guarantees that any path touched by the agent is strictly inside tentRoot,
   * even for sibling-prefix names, dangling symlinks, or new files inside symlinked directories.
   */
  validatePathContainment(agentId, targetPath) {
    if (!this.tentRoot) {
      return {
        contained: false,
        violationType: 'TENT_ROOT_UNCONFIGURED',
        reason: 'Fail-closed: AntiEscapeWatchdog has no tentRoot configured; path access denied.'
      };
    }

    if (!targetPath || typeof targetPath !== 'string' || targetPath.includes('\0')) {
      return {
        contained: false,
        violationType: 'PATH_JAIL_ESCAPE_ATTEMPT',
        reason: 'Invalid or null-byte target path rejected.'
      };
    }

    const normalizedRoot = path.resolve(this.tentRoot);
    let realTentRoot;
    try {
      realTentRoot = fs.existsSync(normalizedRoot) ? fs.realpathSync(normalizedRoot) : normalizedRoot;
    } catch (err) {
      return {
        contained: false,
        violationType: 'PATH_RESOLUTION_FAILURE',
        reason: `Fail-closed: Cannot resolve tentRoot '${this.tentRoot}': ${err.message}`
      };
    }

    const resolved = path.resolve(normalizedRoot, targetPath);

    // 1. Strict lexical boundary check with directory separator (blocks ../ and tent_evil sibling bypass)
    if (!this._isPathWithinRoot(resolved, normalizedRoot)) {
      const threat = new ThreatDetectionEvent({
        domain: ThreatDomain.AIR_DEFENSE,
        severity: ThreatSeverity.CRITICAL,
        sourceAgentId: agentId,
        description: `Anti-Escape Watchdog: Path traversal out-of-tent escape attempted to '${targetPath}'`,
        confidence: 1.0,
        telemetry: {
          attemptedPath: targetPath,
          resolvedPath: resolved,
          tentRoot: normalizedRoot
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

    // 2. Physical Symlink & Dangling Symlink Check:
    // Inspect resolved path and walk upward through every component inside tentRoot using lstatSync
    // BEFORE falling back to nearest existing ancestor, so dangling symlinks are always caught.
    try {
      let probe = resolved;
      while (true) {
        let stat = null;
        try {
          stat = fs.lstatSync(probe);
        } catch (lstatErr) {
          if (lstatErr && lstatErr.code === 'ENOENT') {
            if (probe === normalizedRoot) break;
            const parent = path.dirname(probe);
            if (parent === probe) break;
            probe = parent;
            continue;
          }
          // Any non-ENOENT error (e.g. ELOOP, EACCES) must fail-closed
          return {
            contained: false,
            violationType: 'PATH_RESOLUTION_FAILURE',
            reason: `Fail-closed: lstat failed on '${probe}': ${lstatErr.message}`
          };
        }

        if (stat.isSymbolicLink()) {
          const rawLink = fs.readlinkSync(probe);
          const linkResolved = path.resolve(path.dirname(probe), rawLink);
          const insideLexical = this._isPathWithinRoot(linkResolved, normalizedRoot) ||
                                this._isPathWithinRoot(linkResolved, realTentRoot);

          if (!insideLexical) {
            const threat = new ThreatDetectionEvent({
              domain: ThreatDomain.AIR_DEFENSE,
              severity: ThreatSeverity.CRITICAL,
              sourceAgentId: agentId,
              description: `Anti-Escape Watchdog: Symlink/dangling symlink '${probe}' points to '${linkResolved}' outside tent root.`,
              confidence: 1.0,
              telemetry: {
                attemptedPath: targetPath,
                symlinkPath: probe,
                symlinkTarget: linkResolved,
                tentRoot: realTentRoot
              }
            });

            this.logIncident(agentId, 'SYMLINK_JAILBREAK_ATTEMPT', { targetPath, symlinkTarget: linkResolved });

            return {
              contained: false,
              violationType: 'SYMLINK_JAILBREAK_ATTEMPT',
              reason: `Physical boundary violation: Symlink dereferences outside tent root ('${targetPath}' -> '${linkResolved}').`,
              threat
            };
          }

          // If target exists, verify realpath as well (defense against chained symlinks); if dangling (ENOENT), reject if unresolved
          if (fs.existsSync(probe)) {
            const realPhysical = fs.realpathSync(probe);
            if (!this._isPathWithinRoot(realPhysical, realTentRoot)) {
              const threat = new ThreatDetectionEvent({
                domain: ThreatDomain.AIR_DEFENSE,
                severity: ThreatSeverity.CRITICAL,
                sourceAgentId: agentId,
                description: `Anti-Escape Watchdog: Symlink jailbreak dereferencing to physical path '${realPhysical}' outside tent root.`,
                confidence: 1.0,
                telemetry: { attemptedPath: targetPath, physicalTarget: realPhysical, tentRoot: realTentRoot }
              });
              this.logIncident(agentId, 'SYMLINK_JAILBREAK_ATTEMPT', { targetPath, realPhysical });
              return {
                contained: false,
                violationType: 'SYMLINK_JAILBREAK_ATTEMPT',
                reason: `Physical boundary violation: Symlink '${targetPath}' dereferences to physical path '${realPhysical}' outside the assigned work tent.`,
                threat
              };
            }
          } else {
            // Dangling symlink even if target appears local or unresolvable -> fail-closed
            const threat = new ThreatDetectionEvent({
              domain: ThreatDomain.AIR_DEFENSE,
              severity: ThreatSeverity.CRITICAL,
              sourceAgentId: agentId,
              description: `Anti-Escape Watchdog: Dangling symlink rejected at '${probe}' -> '${linkResolved}'.`,
              confidence: 1.0,
              telemetry: { attemptedPath: targetPath, symlinkPath: probe, symlinkTarget: linkResolved }
            });
            this.logIncident(agentId, 'SYMLINK_JAILBREAK_ATTEMPT', { targetPath, danglingTarget: linkResolved });
            return {
              contained: false,
              violationType: 'SYMLINK_JAILBREAK_ATTEMPT',
              reason: `Physical boundary violation: Dangling symlink '${targetPath}' cannot be safely dereferenced.`,
              threat
            };
          }
        } else {
          // Non-symlink existing ancestor: verify realpath stays inside realTentRoot
          const realPhysical = fs.realpathSync(probe);
          if (!this._isPathWithinRoot(realPhysical, realTentRoot)) {
            const threat = new ThreatDetectionEvent({
              domain: ThreatDomain.AIR_DEFENSE,
              severity: ThreatSeverity.CRITICAL,
              sourceAgentId: agentId,
              description: `Anti-Escape Watchdog: Ancestor path '${probe}' resolves to '${realPhysical}' outside tent root.`,
              confidence: 1.0,
              telemetry: { attemptedPath: targetPath, checkedAncestor: probe, physicalTarget: realPhysical, tentRoot: realTentRoot }
            });
            this.logIncident(agentId, 'SYMLINK_JAILBREAK_ATTEMPT', { targetPath, realPhysical });
            return {
              contained: false,
              violationType: 'SYMLINK_JAILBREAK_ATTEMPT',
              reason: `Physical boundary violation: Path '${targetPath}' resolves outside the assigned work tent ('${realPhysical}').`,
              threat
            };
          }
        }

        if (probe === normalizedRoot) break;
        const parent = path.dirname(probe);
        if (parent === probe) break;
        probe = parent;
      }
    } catch (err) {
      return {
        contained: false,
        violationType: 'PATH_RESOLUTION_FAILURE',
        reason: `Fail-closed: Physical path verification failed for '${targetPath}': ${err.message}`
      };
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

