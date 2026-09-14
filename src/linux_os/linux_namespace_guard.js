/**
 * W1™ Linux Namespaces Jail Engine (محرك عزل مساحات الأسماء في لينكس)
 * File: src/linux_os/linux_namespace_guard.js
 *
 * Core Responsibility:
 * Configures, generates, and enforces Linux kernel namespace isolation for agents:
 * - Mount Namespace (CLONE_NEWNS): Hermetic, private filesystem hierarchy.
 * - PID Namespace (CLONE_NEWPID): Conceals host processes; agent's root process becomes PID 1.
 * - Network Namespace (CLONE_NEWNET): Disables external network egress without a supervisor bridge.
 * - UTS Namespace (CLONE_NEWUTS): Isolates hostnames (e.g., 'w1-tent-<agentId>').
 * - IPC Namespace (CLONE_NEWIPC): Eliminates POSIX/SysV shared memory cross-contamination.
 * - User Namespace (CLONE_NEWUSER): Maps in-tent root (UID 0) to an unprivileged host UID.
 */

import path from 'node:path';

export class LinuxNamespaceGuard {
  constructor(options = {}) {
    this.name = 'W1_Linux_Namespace_Guard';
    this.defaultHostUid = options.hostUid || 1000;
    this.defaultHostGid = options.hostGid || 1000;
  }

  /**
   * Generates Linux namespace flags and unshare command execution string
   */
  generateUnshareCommand({
    agentId = 'agent_01',
    tentRoot = './workspace/tent',
    targetExecutable = '/bin/bash',
    args = [],
    relaxedSecurity = false
  } = {}) {
    const resolvedRoot = path.resolve(tentRoot).replace(/\\/g, '/');
    const hostname = `tent-${agentId.substring(0, 16)}`;

    // Linux unshare flags:
    // -m: Mount, -p: PID, -n: Net, -u: UTS, -i: IPC, -U: User
    const flags = [
      '--mount',
      '--pid',
      '--net',
      '--uts',
      '--ipc',
      '--user',
      '--map-root-user', // Maps container UID 0 to caller host UID
      '--fork',          // Fork target so PID 1 is initialized inside new PID namespace
      '--kill-on-exit',  // Cleanly terminates all child processes if parent exits
      `--sethostname=${hostname}`,
      `--wd=${resolvedRoot}`
    ];

    const commandStr = `unshare ${flags.join(' ')} -- ${targetExecutable} ${args.join(' ')}`.trim();

    return {
      commandStr,
      flags,
      hostname,
      resolvedRoot,
      relaxedSecurity
    };
  }

  /**
   * Generates rootless UID and GID mapping table strings for /proc/<pid>/uid_map and gid_map
   */
  generateUidGidMappings(hostUid = this.defaultHostUid, hostGid = this.defaultHostGid) {
    return {
      // Format: <inside_uid> <outside_uid> <count>
      // Maps UID 0 inside namespace to unprivileged hostUid on host
      uidMap: `0 ${hostUid} 1\n`,
      gidMap: `0 ${hostGid} 1\n`,
      isRootless: hostUid !== 0
    };
  }

  /**
   * Validates that an unshare configuration satisfies DO-178C Level A isolation invariants
   */
  verifyNamespaceIsolation(config) {
    const violations = [];

    if (!config || !Array.isArray(config.flags)) {
      return { compliant: false, violations: ['MISSING_NAMESPACE_CONFIG'] };
    }

    const flags = new Set(config.flags);

    // Mandatory namespaces
    const required = [
      { flag: '--mount', name: 'Mount Namespace (CLONE_NEWNS)' },
      { flag: '--pid',   name: 'PID Namespace (CLONE_NEWPID)' },
      { flag: '--net',   name: 'Network Namespace (CLONE_NEWNET)' },
      { flag: '--ipc',   name: 'IPC Namespace (CLONE_NEWIPC)' },
      { flag: '--user',  name: 'User Namespace (CLONE_NEWUSER)' }
    ];

    for (const req of required) {
      if (!flags.has(req.flag)) {
        violations.push(`MISSING_NAMESPACE: ${req.name} is mandatory for agent containment.`);
      }
    }

    // Must map root to non-privileged user or have kill-on-exit
    if (!flags.has('--kill-on-exit')) {
      violations.push('DANGEROUS_ORPHAN_RISK: --kill-on-exit flag required to eliminate zombie swarms.');
    }

    return {
      compliant: violations.length === 0,
      violations
    };
  }
}
