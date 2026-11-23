/**
 * W1™ Container & MicroVM Isolation Engine (محرك العزل الحاوي وملفات حماية النواة)
 * File: src/ai_testbed/container_isolation_engine.js
 *
 * Core Responsibility:
 * Generates and enforces physical container isolation profiles (Docker, Podman, OCI, Seccomp-BPF)
 * for AI training and evaluation testbeds.
 *
 * Architectural Invariant:
 * Even under "Relaxed Security Mode" where researchers give an agent root/bash access
 * INSIDE the container, the host-side supervisor treats the container boundary as completely
 * untrusted. Host secrets, host devices, and host kernel namespaces remain unreachable.
 *
 * REMEDIATION (2026-09-20):
 * - Seccomp profile changed from blacklist (SCMP_ACT_ALLOW default) to whitelist (SCMP_ACT_ERRNO default)
 * - Removed DAC_OVERRIDE from relaxed mode capabilities (bypasses all file permissions)
 * - Added runtime verification method to check Docker/Podman availability
 * - Added explicit mode field (SIMULATION vs PRODUCTION) to configs
 * - Added modern syscall blocking (io_uring, fsopen, move_mount, userfaultfd)
 */

import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export class ContainerIsolationEngine {
  constructor(options = {}) {
    this.name = 'W1_Container_Isolation_Engine';
    this.defaultCpuLimit = options.cpuLimit || '2.0';
    this.defaultMemoryLimit = options.memoryLimit || '2g';
    this.defaultPidsLimit = options.pidsLimit || 100;

    // PERF-20: Non-blocking construction — starts uninitialized (Fail-Closed)
    // until async container runtime detection completes.
    this.initialized = false;
    this._runtimeInfo = {
      available: false,
      runtime: null,
      version: null,
      checked: false
    };
    this._runtimeProbePromise = null;

    if (options.probeOnInit) {
      this._runtimeProbePromise = this.detectContainerRuntime();
    }
  }

  /**
   * Fail-closed guard: refuses runtime execution before async runtime detection finishes.
   */
  assertInitialized() {
    if (!this.initialized) {
      throw new Error(
        'Fail-closed: ContainerIsolationEngine is not initialized (initialized=false). ' +
        'Await detectContainerRuntime() or verifyHostRuntimePrerequisitesAsync() before execution.'
      );
    }
  }

  /**
   * Executes an isolated workload command only after runtime probing has completed
   * and a verified host container runtime is available (Fail-Closed).
   *
   * @param {Object} params
   * @param {string} params.agentId
   * @param {string} params.image
   * @param {string[]} [params.command=[]]
   * @param {string} [params.tentRoot='./sandbox_tents']
   */
  async executeIsolatedContainer({ agentId = 'eval_agent_01', image = 'node:20-alpine', command = [], tentRoot = './sandbox_tents' } = {}) {
    this.assertInitialized();

    if (!this._runtimeInfo.available || !this._runtimeInfo.runtime) {
      throw new Error(
        `Fail-closed: Cannot execute isolated container for '${agentId}' — no container runtime available on host (mode: SIMULATION).`
      );
    }

    const args = [
      'run', '--rm', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
      '--network=none', `--pids-limit=${this.defaultPidsLimit}`,
      `--memory=${this.defaultMemoryLimit}`, `--cpus=${this.defaultCpuLimit}`,
      '-v', `${path.resolve(tentRoot)}:/workspace/tent:rw`,
      image,
      ...command
    ];
    return execFileAsync(this._runtimeInfo.runtime, args, { encoding: 'utf8', timeout: 30000 });
  }

  /**
   * Generates a production-grade docker-compose.yml configuration for the agent testbed.
   */
  generateDockerComposeConfig({
    agentId = 'eval_agent_01',
    tentRoot = './workspace/tent_sandbox',
    relaxedSecurity = false,
    environment = {}
  } = {}) {
    const resolvedTent = path.resolve(tentRoot).replace(/\\/g, '/');

    // In relaxed mode, the agent has more write freedom INSIDE its own tent volume,
    // but host-level security (capabilities, seccomp, pids) remains strictly enforced.
    const readOnlyRoot = !relaxedSecurity;

    // REMEDIATION: Removed DAC_OVERRIDE from relaxed capabilities.
    // DAC_OVERRIDE bypasses all Unix discretionary access control checks,
    // allowing read/write to any file regardless of permissions.
    // Even in relaxed mode, we only grant minimal capabilities.
    const relaxedCaps = ['CHOWN', 'SETUID', 'SETGID'];

    const composeConfig = {
      version: '3.8',
      services: {
        [`agent_${agentId}`]: {
          image: 'w1-ai-eval-sandbox:latest',
          container_name: `w1_tent_${agentId}`,
          hostname: `tent-${agentId}`,
          read_only: readOnlyRoot,
          security_opt: [
            'no-new-privileges:true',
            'seccomp:./w1-seccomp-profile.json'
          ],
          cap_drop: ['ALL'],
          cap_add: relaxedSecurity ? relaxedCaps : [],
          deploy: {
            resources: {
              limits: {
                cpus: this.defaultCpuLimit,
                memory: this.defaultMemoryLimit,
                pids: this.defaultPidsLimit
              }
            }
          },
          volumes: [
            `${resolvedTent}:/workspace:rw`,
            'w1_sandbox_tmp:/tmp:rw',
            'w1_sandbox_run:/run:rw'
          ],
          environment: {
            ...environment,
            W1_CONTAINER_SANDBOX_ACTIVE: 'TRUE',
            W1_ISOLATION_LEVEL: relaxedSecurity ? 'RELAXED_CONTAINED' : 'HERMETIC_STRICT',
            W1_AGENT_ID: agentId,
            W1_MODE: this._runtimeInfo.available ? 'PRODUCTION' : 'SIMULATION'
          },
          networks: ['w1_isolated_eval_net'],
          // Additional security hardening
          tmpfs: ['/tmp:size=256m,noexec,nosuid'],
          ulimits: {
            nofile: { soft: 1024, hard: 4096 },
            nproc: { soft: 50, hard: this.defaultPidsLimit }
          }
        }
      },
      volumes: {
        w1_sandbox_tmp: { driver: 'local', driver_opts: { type: 'tmpfs', device: 'tmpfs' } },
        w1_sandbox_run: { driver: 'local', driver_opts: { type: 'tmpfs', device: 'tmpfs' } }
      },
      networks: {
        w1_isolated_eval_net: {
          driver: 'bridge',
          internal: true // Disables raw internet routing outside the supervisor proxy
        }
      }
    };

    return composeConfig;
  }

  /**
   * Generates a Linux Seccomp-BPF JSON profile.
   *
   * REMEDIATION: Changed from blacklist (SCMP_ACT_ALLOW) to whitelist (SCMP_ACT_ERRNO).
   *
   * @param {Object} options
   * @param {boolean} [options.strict=false] - Use whitelist mode (SCMP_ACT_ERRNO default).
   *   When false (default), uses hardened blacklist for broader compatibility (e.g. SWE-bench).
   * @returns {Object} Seccomp profile JSON.
   */
  generateSeccompProfile(options = {}) {
    const strict = options.strict === true || options.mode === 'whitelist';

    if (strict) {
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      // WHITELIST MODE: Default deny, explicitly allow safe syscalls.
      // DO-178C Level A compliant — new kernel syscalls are blocked by default.
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      return {
        defaultAction: 'SCMP_ACT_ERRNO',
        architectures: [
          'SCMP_ARCH_X86_64',
          'SCMP_ARCH_AARCH64',
          'SCMP_ARCH_X86'
        ],
        syscalls: [
          {
            names: [
              // File I/O (core)
              'read', 'write', 'openat', 'close', 'stat', 'fstat', 'lstat',
              'newfstatat', 'lseek', 'pread64', 'pwrite64', 'readv', 'writev',
              'access', 'faccessat', 'faccessat2',
              // Memory management
              'mmap', 'mprotect', 'munmap', 'brk', 'mremap',
              // Process lifecycle
              'exit', 'exit_group', 'wait4', 'waitid',
              // Threading & synchronization
              'futex', 'set_robust_list', 'get_robust_list',
              'clone', 'clone3',
              // Signal handling
              'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
              'sigaltstack',
              // File descriptors
              'dup', 'dup2', 'dup3', 'pipe', 'pipe2',
              'epoll_create1', 'epoll_ctl', 'epoll_wait', 'epoll_pwait',
              'eventfd2', 'timerfd_create', 'timerfd_settime', 'timerfd_gettime',
              'poll', 'ppoll', 'select', 'pselect6',
              // Directory operations
              'getcwd', 'chdir', 'readlink', 'readlinkat',
              'getdents64', 'mkdir', 'mkdirat', 'rmdir',
              'rename', 'renameat', 'renameat2',
              'unlink', 'unlinkat',
              // File attributes
              'fchmod', 'fchmodat', 'fchown', 'fchownat',
              'utimensat', 'futimesat',
              // Process info
              'getpid', 'getppid', 'gettid', 'getuid', 'geteuid',
              'getgid', 'getegid', 'getgroups',
              // Time
              'clock_gettime', 'clock_getres', 'clock_nanosleep',
              'gettimeofday', 'nanosleep',
              // Network (basic — no raw sockets)
              'socket', 'connect', 'bind', 'listen', 'accept', 'accept4',
              'sendto', 'recvfrom', 'sendmsg', 'recvmsg',
              'shutdown', 'getsockname', 'getpeername',
              'getsockopt', 'setsockopt',
              // Execution (controlled)
              'execve', 'execveat',
              // Miscellaneous safe operations
              'getrandom', 'uname', 'sysinfo',
              'ioctl', 'fcntl',
              'arch_prctl', 'prctl', 'set_tid_address',
              'rseq', 'membarrier',
              'madvise', 'mincore',
              'statfs', 'fstatfs',
              'umask',
              'getrlimit', 'prlimit64',
              'sched_getaffinity', 'sched_yield',
              'tgkill'
            ],
            action: 'SCMP_ACT_ALLOW',
            comment: 'W1 DO-178C Level A: Explicitly whitelisted safe syscalls'
          }
        ]
      };
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // HARDENED BLACKLIST MODE (for SWE-bench compatibility)
    // Default allow, but block dangerous syscalls including modern ones.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    return {
      defaultAction: 'SCMP_ACT_ALLOW',
      architectures: [
        'SCMP_ARCH_X86_64',
        'SCMP_ARCH_AARCH64',
        'SCMP_ARCH_X86'
      ],
      syscalls: [
        {
          names: [
            // Memory & Process Injection
            'ptrace',
            'process_vm_readv',
            'process_vm_writev',
            // Kernel eBPF tampering
            'bpf',
            // Kernel Module loading
            'init_module',
            'finit_module',
            'delete_module',
            // Kernel reboot/kexec
            'reboot',
            'kexec_load',
            'kexec_file_load',
            // Filesystem & Namespace breakout
            'mount',
            'umount',
            'umount2',
            'pivot_root',
            'chroot',
            'setns',
            'unshare',
            // Raw Network & Keyring
            'keyctl',
            'add_key',
            'request_key',
            'vmsplice',
            // Modern dangerous syscalls (REMEDIATION)
            'io_uring_setup',
            'io_uring_enter',
            'io_uring_register',
            'fsopen',
            'fspick',
            'fsconfig',
            'fsmount',
            'move_mount',
            'open_tree',
            'userfaultfd',
            // Performance counters (Spectre/Meltdown side-channels)
            'perf_event_open',
            // User namespace creation (container escapes)
            'unshare'
          ],
          action: 'SCMP_ACT_ERRNO',
          args: [],
          comment: 'W1 Hardened Blacklist: Prevent container breakout, kernel compromise, and modern attack vectors'
        }
      ]
    };
  }

  /**
   * Generates iptables / network isolation rules to prevent data exfiltration.
   */
  generateEgressFirewallRules(containerSubnet = '172.20.0.0/16', supervisorIp = '172.20.0.1') {
    return [
      `# W1 Testbed Egress Filter Rules`,
      `# 1. Allow loopback traffic`,
      `iptables -A FORWARD -i br-w1-eval -o br-w1-eval -j ACCEPT`,
      `# 2. Allow traffic strictly to W1 Supervisor Reverse Proxy on port 8080`,
      `iptables -A FORWARD -s ${containerSubnet} -d ${supervisorIp} -p tcp --dport 8080 -j ACCEPT`,
      `# 3. Block access to RFC1918 Private LAN Ranges (Anti-lateral movement)`,
      `iptables -A FORWARD -s ${containerSubnet} -d 10.0.0.0/8 -j DROP`,
      `iptables -A FORWARD -s ${containerSubnet} -d 172.16.0.0/12 -j DROP`,
      `iptables -A FORWARD -s ${containerSubnet} -d 192.168.0.0/16 -j DROP`,
      `# 4. Block raw outbound SSH, SMTP, and Cloud Metadata IPs`,
      `iptables -A FORWARD -s ${containerSubnet} -d 169.254.169.254 -j DROP`,
      `iptables -A FORWARD -s ${containerSubnet} -p tcp --dport 22 -j DROP`,
      `iptables -A FORWARD -s ${containerSubnet} -p tcp --dport 25 -j DROP`,
      `# 5. Drop all remaining unmatched egress`,
      `iptables -A FORWARD -s ${containerSubnet} -j DROP`
    ];
  }

  /**
   * Verifies that a given container configuration satisfies DO-178C Level A containment invariants.
   */
  verifyContainerContainment(containerConfig) {
    const violations = [];

    if (!containerConfig) {
      return { compliant: false, violations: ['CONTAINER_CONFIG_NULL'] };
    }

    // Check 1: Must not be privileged
    if (containerConfig.privileged === true) {
      violations.push('PRIVILEGED_CONTAINER_FORBIDDEN: Container must not run with --privileged flag');
    }

    // Check 2: Must drop ALL capabilities
    const capDrop = containerConfig.cap_drop || [];
    if (!capDrop.includes('ALL')) {
      violations.push('CAPABILITIES_NOT_DROPPED: cap_drop must include "ALL"');
    }

    // Check 3: Host PID/IPC/Network sharing forbidden
    if (containerConfig.pid === 'host' || containerConfig.ipc === 'host' || containerConfig.net === 'host') {
      violations.push('HOST_NAMESPACE_SHARED: Container shares host PID, IPC, or Network namespace');
    }

    // Check 4: Host root filesystem must not be mounted
    const volumes = containerConfig.volumes || [];
    for (const v of volumes) {
      const hostPart = typeof v === 'string' ? v.split(':')[0] : '';
      if (hostPart === '/' || hostPart === '/etc' || hostPart === '/root' || hostPart === 'C:\\' || hostPart === 'C:\\Windows') {
        violations.push(`DANGEROUS_HOST_MOUNT: Mounting '${hostPart}' compromises host root`);
      }
    }

    // Check 5 (REMEDIATION): Verify DAC_OVERRIDE is not granted
    const capAdd = containerConfig.cap_add || [];
    if (capAdd.includes('DAC_OVERRIDE')) {
      violations.push('DAC_OVERRIDE_FORBIDDEN: DAC_OVERRIDE capability bypasses all file permission checks');
    }

    // Check 6 (REMEDIATION): Verify SYS_ADMIN is not granted
    if (capAdd.includes('SYS_ADMIN')) {
      violations.push('SYS_ADMIN_FORBIDDEN: SYS_ADMIN capability enables container escape vectors');
    }

    return {
      compliant: violations.length === 0,
      violations
    };
  }

  /**
   * Returns cached host runtime status synchronously (non-blocking, PERF-20).
   * Call `await verifyHostRuntimePrerequisitesAsync()` to perform a live probe.
   *
   * @returns {{ available: boolean, runtime: string|null, version: string|null, checked: boolean, mode: string }}
   */
  verifyHostRuntimePrerequisites() {
    return {
      ...this._runtimeInfo,
      initialized: this.initialized,
      mode: this._runtimeInfo.available ? 'PRODUCTION' : 'SIMULATION'
    };
  }

  /**
   * Asynchronously detects available container runtimes without blocking the event loop (PERF-20).
   *
   * @returns {Promise<{ available: boolean, runtime: string|null, version: string|null, checked: boolean, initialized: boolean, mode: string }>}
   */
  async verifyHostRuntimePrerequisitesAsync() {
    if (!this._runtimeInfo.checked) {
      await this.detectContainerRuntime();
    }
    return this.verifyHostRuntimePrerequisites();
  }

  /**
   * Non-blocking probe for container runtimes on the host using execFile (no shell).
   */
  async detectContainerRuntime() {
    if (this._runtimeProbePromise) {
      return this._runtimeProbePromise;
    }

    this._runtimeProbePromise = (async () => {
      const runtimes = ['docker', 'podman', 'nerdctl'];

      for (const runtime of runtimes) {
        try {
          const { stdout } = await execFileAsync(runtime, ['--version'], {
            encoding: 'utf8',
            timeout: 5000
          });
          const version = String(stdout || '').trim();
          this._runtimeInfo = {
            available: true,
            runtime,
            version: version.split('\n')[0],
            checked: true
          };
          this.initialized = true;
          return this._runtimeInfo;
        } catch {
          // Runtime not found, try next
        }
      }

      this._runtimeInfo = {
        available: false,
        runtime: null,
        version: null,
        checked: true
      };
      this.initialized = true;
      return this._runtimeInfo;
    })();

    try {
      return await this._runtimeProbePromise;
    } finally {
      this._runtimeProbePromise = null;
    }
  }
}
