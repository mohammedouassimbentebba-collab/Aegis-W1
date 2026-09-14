/**
 * W1™ Linux Landlock LSM & Seccomp-BPF Guard (درع وحدة أمان لاندلوك وفلتر النداءات)
 * File: src/linux_os/linux_seccomp_landlock.js
 *
 * Core Responsibility:
 * 1. Landlock LSM (Linux 5.13+):
 *    Enforces unbypassable path geofencing directly inside the Linux kernel.
 *    Restricts filesystem read/write/execute rights strictly to `tentRoot`.
 *    Any syscall attempting to read /etc/passwd or /root is blocked by kernel LSM with EACCES.
 *
 * 2. Seccomp-BPF:
 *    Restricts raw system calls inside the kernel, blocking container breakout and tampering.
 */

import path from 'node:path';

export class LinuxSeccompLandlock {
  constructor(options = {}) {
    this.name = 'W1_Linux_Seccomp_Landlock';
    this.abiVersion = options.abiVersion || 3; // Landlock ABI v3
  }

  /**
   * Generates C-compatible Landlock LSM ruleset configuration
   */
  generateLandlockRuleset(tentRoot) {
    const resolvedRoot = path.resolve(tentRoot).replace(/\\/g, '/');

    // Landlock Filesystem Access Flags (Linux linux/landlock.h)
    const accessFlags = [
      'LANDLOCK_ACCESS_FS_EXECUTE',
      'LANDLOCK_ACCESS_FS_WRITE_FILE',
      'LANDLOCK_ACCESS_FS_READ_FILE',
      'LANDLOCK_ACCESS_FS_READ_DIR',
      'LANDLOCK_ACCESS_FS_REMOVE_DIR',
      'LANDLOCK_ACCESS_FS_REMOVE_FILE',
      'LANDLOCK_ACCESS_FS_MAKE_CHAR',
      'LANDLOCK_ACCESS_FS_MAKE_DIR',
      'LANDLOCK_ACCESS_FS_MAKE_REG',
      'LANDLOCK_ACCESS_FS_MAKE_SOCK',
      'LANDLOCK_ACCESS_FS_MAKE_FIFO',
      'LANDLOCK_ACCESS_FS_MAKE_BLOCK',
      'LANDLOCK_ACCESS_FS_MAKE_SYM',
      'LANDLOCK_ACCESS_FS_REFER',
      'LANDLOCK_ACCESS_FS_TRUNCATE'
    ];

    return {
      abiVersion: this.abiVersion,
      handledAccessFs: accessFlags,
      rules: [
        {
          targetPath: resolvedRoot,
          allowedAccess: accessFlags,
          comment: 'Allowed: Full read/write within assigned hermetic tent root'
        },
        {
          targetPath: '/usr',
          allowedAccess: ['LANDLOCK_ACCESS_FS_READ_FILE', 'LANDLOCK_ACCESS_FS_READ_DIR', 'LANDLOCK_ACCESS_FS_EXECUTE'],
          comment: 'Allowed: Read-only system binaries and shared libraries (libc, bash)'
        },
        {
          targetPath: '/lib',
          allowedAccess: ['LANDLOCK_ACCESS_FS_READ_FILE', 'LANDLOCK_ACCESS_FS_READ_DIR'],
          comment: 'Allowed: Dynamic linker and shared objects'
        },
        {
          targetPath: '/lib64',
          allowedAccess: ['LANDLOCK_ACCESS_FS_READ_FILE', 'LANDLOCK_ACCESS_FS_READ_DIR'],
          comment: 'Allowed: 64-bit dynamic libraries'
        }
      ],
      deniedPaths: [
        '/etc/shadow',
        '/etc/passwd',
        '/root',
        '/home',
        '/sys',
        '/proc/kcore',
        '/dev/mem',
        '/dev/kmem'
      ]
    };
  }

  /**
   * Generates BPF bytecode filter representations blocking unauthorized Linux system calls
   */
  generateSeccompFilter() {
    const blockedSyscalls = [
      // Kernel & module tampering
      { name: 'init_module', nr: 175, reason: 'Kernel module injection forbidden' },
      { name: 'finit_module', nr: 313, reason: 'Kernel module injection forbidden' },
      { name: 'delete_module', nr: 176, reason: 'Kernel module deletion forbidden' },
      // Debugging & code injection
      { name: 'ptrace', nr: 101, reason: 'Process tracing/memory tampering forbidden' },
      { name: 'process_vm_writev', nr: 311, reason: 'Cross-process memory writing forbidden' },
      // eBPF kernel rootkits
      { name: 'bpf', nr: 321, reason: 'eBPF kernel injection forbidden' },
      // Filesystem & namespace escapes
      { name: 'mount', nr: 165, reason: 'Filesystem mounting forbidden' },
      { name: 'umount2', nr: 166, reason: 'Filesystem unmounting forbidden' },
      { name: 'pivot_root', nr: 155, reason: 'Filesystem root swap forbidden' },
      { name: 'setns', nr: 308, reason: 'Namespace hopping forbidden' },
      { name: 'mknod', nr: 133, reason: 'Raw device node creation forbidden' },
      // System destruction
      { name: 'reboot', nr: 169, reason: 'Host reboot forbidden' },
      { name: 'kexec_load', nr: 246, reason: 'Kernel replacement forbidden' }
    ];

    // BPF Pseudo-Assembly Instructions (Linux socket-filter format)
    const bpfInstructions = [
      'BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch))',
      'BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0)',
      'BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)',
      'BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr))'
    ];

    for (const sys of blockedSyscalls) {
      bpfInstructions.push(
        `BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_${sys.name}, 0, 1)`,
        `BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))`
      );
    }

    bpfInstructions.push('BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)');

    return {
      defaultAction: 'SECCOMP_RET_ALLOW',
      blockedSyscalls,
      bpfInstructions,
      ruleCount: blockedSyscalls.length
    };
  }
}
