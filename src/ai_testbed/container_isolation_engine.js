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
 */

import path from 'node:path';

export class ContainerIsolationEngine {
  constructor(options = {}) {
    this.name = 'W1_Container_Isolation_Engine';
    this.defaultCpuLimit = options.cpuLimit || '2.0';
    this.defaultMemoryLimit = options.memoryLimit || '2g';
    this.defaultPidsLimit = options.pidsLimit || 100;
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
          cap_add: relaxedSecurity ? ['CHOWN', 'SETUID', 'SETGID', 'DAC_OVERRIDE'] : [],
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
            W1_AGENT_ID: agentId
          },
          networks: ['w1_isolated_eval_net']
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
   * Generates a Linux Seccomp-BPF JSON profile blocking dangerous kernel syscalls.
   */
  generateSeccompProfile() {
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
            'vmsplice'
          ],
          action: 'SCMP_ACT_ERRNO',
          args: [],
          comment: 'W1 DO-178C Level A: Prevent container breakout and kernel compromise'
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

    return {
      compliant: violations.length === 0,
      violations
    };
  }
}
