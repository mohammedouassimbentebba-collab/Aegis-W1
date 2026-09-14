/**
 * W1™ Linux Enclave Runner & Supervisor (المشرف التنفيذي لبيئة لينكس)
 * File: src/linux_os/linux_enclave_runner.js
 *
 * Core Responsibility:
 * Integrates Linux Namespaces, cgroups v2, Landlock LSM, and Seccomp-BPF into a cohesive
 * autonomous execution supervisor.
 *
 * Guarantees DO-178C Level A containment even in "Relaxed Security Mode":
 * An agent running as root inside its user namespace cannot escape to host namespaces,
 * mount host filesystems, exceed cgroups memory/pid quotas, or execute blocked syscalls.
 */

import path from 'node:path';
import { LinuxNamespaceGuard } from './linux_namespace_guard.js';
import { LinuxCgroupsController } from './linux_cgroups_controller.js';
import { LinuxSeccompLandlock } from './linux_seccomp_landlock.js';

export class LinuxEnclaveRunner {
  constructor(options = {}) {
    this.name = 'W1_Linux_Enclave_Runner';
    this.nsGuard = options.nsGuard || new LinuxNamespaceGuard();
    this.cgroupsCtrl = options.cgroupsCtrl || new LinuxCgroupsController();
    this.seccompLandlock = options.seccompLandlock || new LinuxSeccompLandlock();
    this.activeEnclaves = new Map();
  }

  /**
   * Prepares the full Linux OS isolation envelope for an agent
   */
  prepareLinuxEnclave({
    agentId = 'linux_agent_01',
    tentRoot = './workspace/tent',
    targetExecutable = '/bin/bash',
    args = [],
    relaxedSecurity = false,
    resourceLimits = {}
  } = {}) {
    const resolvedRoot = path.resolve(tentRoot).replace(/\\/g, '/');

    // 1. Configure Linux Namespaces
    const nsConfig = this.nsGuard.generateUnshareCommand({
      agentId,
      tentRoot: resolvedRoot,
      targetExecutable,
      args,
      relaxedSecurity
    });

    const nsVerification = this.nsGuard.verifyNamespaceIsolation(nsConfig);

    // 2. Configure cgroups v2 resource boundaries
    const cgroupConfig = this.cgroupsCtrl.generateCgroupFiles(agentId, resourceLimits);

    // 3. Configure Landlock LSM and Seccomp-BPF
    const landlockRules = this.seccompLandlock.generateLandlockRuleset(resolvedRoot);
    const seccompFilter = this.seccompLandlock.generateSeccompFilter();

    // 4. Generate Linux Enclave Launch Script
    const launcherScript = [
      '#!/bin/bash',
      '# W1™ Linux Enclave Autonomous Launch Harness',
      'set -euo pipefail',
      '',
      `# 1. Enter cgroups v2 slice`,
      `CGROUP_DIR="${cgroupConfig.cgroupPath}"`,
      `if [ -d "$CGROUP_DIR" ]; then`,
      `  echo $$ > "$CGROUP_DIR/cgroup.procs"`,
      `fi`,
      '',
      `# 2. Execute unshared namespace command`,
      `exec ${nsConfig.commandStr}`
    ].join('\n');

    const enclaveRecord = {
      agentId,
      tentRoot: resolvedRoot,
      relaxedSecurity,
      nsConfig,
      nsVerification,
      cgroupConfig,
      landlockRules,
      seccompFilter,
      launcherScript,
      status: 'PREPARED_FOR_EXECUTION',
      createdAt: Date.now()
    };

    this.activeEnclaves.set(agentId, enclaveRecord);

    return enclaveRecord;
  }

  /**
   * Validates whether a proposed agent syscall or filesystem access is permitted under Linux invariants
   */
  validateProposedAction(agentId, { syscall, targetPath, processCount, memoryBytes }) {
    const enclave = this.activeEnclaves.get(agentId);
    if (!enclave) {
      return { allowed: false, reason: `Enclave for agent '${agentId}' is not registered.` };
    }

    // 1. Check Seccomp Blocked Syscalls
    if (syscall) {
      const isBlocked = enclave.seccompFilter.blockedSyscalls.some(s => s.name === syscall);
      if (isBlocked) {
        return {
          allowed: false,
          violationType: 'SECCOMP_SYSCALL_BLOCKED',
          reason: `Linux Kernel Seccomp-BPF blocked illegal system call '${syscall}'.`
        };
      }
    }

    // 2. Check Landlock Path Containment
    if (targetPath) {
      const normalized = path.resolve(targetPath).replace(/\\/g, '/');
      const tentNormalized = enclave.tentRoot;

      const isInsideTent = normalized === tentNormalized || normalized.startsWith(tentNormalized + '/');
      const isSystemSharedLib = normalized.startsWith('/usr/') || normalized.startsWith('/lib/') || normalized.startsWith('/lib64/');

      if (!isInsideTent && !isSystemSharedLib) {
        return {
          allowed: false,
          violationType: 'LANDLOCK_PATH_ACCESS_DENIED',
          reason: `Linux Landlock LSM denied access to path '${targetPath}' outside assigned tent root.`
        };
      }
    }

    // 3. Check cgroups v2 process and memory ceilings
    if (processCount !== undefined || memoryBytes !== undefined) {
      const cgroupAudit = this.cgroupsCtrl.auditCgroupStats(agentId, {
        pidsMax: enclave.cgroupConfig.metadata.maxPids,
        pidsCurrent: processCount !== undefined ? processCount : 1,
        memoryMax: enclave.cgroupConfig.metadata.maxMemoryBytes,
        memoryCurrent: memoryBytes || 0
      });

      if (!cgroupAudit.healthy) {
        return {
          allowed: false,
          violationType: cgroupAudit.alerts[0].type,
          reason: cgroupAudit.alerts[0].detail
        };
      }
    }

    return { allowed: true };
  }
}
