import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs';
import { LinuxKernelAbiValidator } from '../src/radar_machine_code/linux_kernel/linux_kernel_abi_validator.js';
import { LinuxNamespaceGuard } from '../src/linux_os/linux_namespace_guard.js';
import { LinuxCgroupsController } from '../src/linux_os/linux_cgroups_controller.js';
import { LinuxSeccompLandlock } from '../src/linux_os/linux_seccomp_landlock.js';
import { LinuxEnclaveRunner } from '../src/linux_os/linux_enclave_runner.js';

describe('W1™ Linux Operating System Production Readiness Suite', () => {
  describe('Pillar 1: Linux Kernel ABI Validator & C Header Interoperability', () => {
    it('should validate exact struct memory layouts and byte sizes for 64-bit alignment', () => {
      const validator = new LinuxKernelAbiValidator();
      const result = validator.validateStructLayouts();

      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.layouts.w1_radar_config.expectedSize, 28);
      assert.strictEqual(result.layouts.w1_radar_target_track.expectedSize, 48);
      assert.strictEqual(result.layouts.w1_radar_telemetry.expectedSize, 32);
    });

    it('should calculate valid Linux IOCTL command codes matching kernel encoding formula', () => {
      const validator = new LinuxKernelAbiValidator();
      const codes = validator.getExpectedIoctlCodes();

      assert.ok(codes.W1_RADAR_IOCTL_SET_CONFIG > 0);
      assert.ok(codes.W1_RADAR_IOCTL_GET_CONFIG > 0);
      assert.ok(codes.W1_RADAR_IOCTL_START_SWEEP > 0);
      assert.ok(codes.W1_RADAR_IOCTL_STOP_SWEEP > 0);
      assert.ok(codes.W1_RADAR_IOCTL_READ_TRACKS > 0);
      assert.ok(codes.W1_RADAR_IOCTL_GET_TELEMETRY > 0);
    });

    it('should verify w1_radar_ioctl.h defines all mandatory kernel constants', () => {
      const validator = new LinuxKernelAbiValidator();
      const headerPath = path.resolve('src/radar_machine_code/linux_kernel/w1_radar_ioctl.h');
      const headerContent = fs.readFileSync(headerPath, 'utf8');

      const verification = validator.verifyHeaderDefinitions(headerContent);
      assert.strictEqual(verification.compliant, true);
      assert.strictEqual(verification.missing.length, 0);
    });
  });

  describe('Pillar 2: Native Linux C Control Tool (w1_radar_ctl.c)', () => {
    it('should verify w1_radar_ctl.c contains full CLI command dispatch and mock fallback', () => {
      const cSourcePath = path.resolve('src/radar_machine_code/linux_kernel/w1_radar_ctl.c');
      const cSource = fs.readFileSync(cSourcePath, 'utf8');

      assert.ok(cSource.includes('#include "w1_radar_ioctl.h"'));
      assert.ok(cSource.includes('W1_RADAR_IOCTL_SET_CONFIG'));
      assert.ok(cSource.includes('W1_RADAR_IOCTL_START_SWEEP'));
      assert.ok(cSource.includes('W1_RADAR_IOCTL_READ_TRACKS'));
      assert.ok(cSource.includes('W1_RADAR_IOCTL_GET_TELEMETRY'));
      assert.ok(cSource.includes('g_mock_state'), 'Must include software mock fallback');
      assert.ok(cSource.includes('B-2 SPIRIT'), 'Must support B-2 stealth classification');
      assert.ok(cSource.includes('F-35 LIGHTNING II'), 'Must support F-35 stealth classification');
    });
  });

  describe('Pillar 3: Linux Namespaces Guard & Rootless Mapping', () => {
    it('should generate complete unshare command string with all 6 required namespaces', () => {
      const guard = new LinuxNamespaceGuard({ hostUid: 1001, hostGid: 1001 });
      const nsConfig = guard.generateUnshareCommand({
        agentId: 'agent_alpha',
        tentRoot: '/tmp/w1_tent',
        targetExecutable: '/bin/bash'
      });

      assert.ok(nsConfig.commandStr.startsWith('unshare '));
      assert.ok(nsConfig.flags.includes('--mount'));
      assert.ok(nsConfig.flags.includes('--pid'));
      assert.ok(nsConfig.flags.includes('--net'));
      assert.ok(nsConfig.flags.includes('--uts'));
      assert.ok(nsConfig.flags.includes('--ipc'));
      assert.ok(nsConfig.flags.includes('--user'));
      assert.ok(nsConfig.flags.includes('--kill-on-exit'));
      assert.strictEqual(nsConfig.hostname, 'tent-agent_alpha');
    });

    it('should generate rootless UID/GID mapping strings preventing host root escalation', () => {
      const guard = new LinuxNamespaceGuard();
      const mappings = guard.generateUidGidMappings(1005, 1005);

      assert.strictEqual(mappings.uidMap, '0 1005 1\n');
      assert.strictEqual(mappings.gidMap, '0 1005 1\n');
      assert.strictEqual(mappings.isRootless, true);
    });

    it('should flag compliance violations if critical namespaces or kill-on-exit are missing', () => {
      const guard = new LinuxNamespaceGuard();
      const badConfig = { flags: ['--mount', '--pid'] }; // Missing net, ipc, user, kill-on-exit

      const verification = guard.verifyNamespaceIsolation(badConfig);
      assert.strictEqual(verification.compliant, false);
      assert.ok(verification.violations.some(v => v.includes('Network Namespace')));
      assert.ok(verification.violations.some(v => v.includes('User Namespace')));
      assert.ok(verification.violations.some(v => v.includes('kill-on-exit')));
    });
  });

  describe('Pillar 4: cgroups v2 Resource Controller & Fork-Bomb Interception', () => {
    it('should generate accurate cgroups v2 file values for CPU, memory, and PIDs', () => {
      const ctrl = new LinuxCgroupsController({ maxPids: 60, maxMemoryBytes: 512 * 1024 * 1024 });
      const cgroupConfig = ctrl.generateCgroupFiles('agent_beta');

      assert.strictEqual(cgroupConfig.files['pids.max'], '60\n');
      assert.strictEqual(cgroupConfig.files['memory.max'], '536870912\n');
      assert.ok(cgroupConfig.files['cpu.max'].includes('200000 100000'));
      assert.ok(cgroupConfig.cgroupPath.includes('/sys/fs/cgroup/w1_enclave/agent_beta'));
    });

    it('should detect and generate critical alert upon kernel fork bomb attempt', () => {
      const ctrl = new LinuxCgroupsController({ maxPids: 50 });
      const audit = ctrl.auditCgroupStats('agent_beta', { pidsMax: 50, pidsCurrent: 50 });

      assert.strictEqual(audit.healthy, false);
      assert.strictEqual(audit.alerts[0].type, 'KERNEL_FORK_BOMB_INTERCEPTED');
      assert.strictEqual(audit.alerts[0].severity, 'CRITICAL');
    });

    it('should detect kernel OOM killer events', () => {
      const ctrl = new LinuxCgroupsController();
      const audit = ctrl.auditCgroupStats('agent_beta', { oomKillCount: 1 });

      assert.strictEqual(audit.healthy, false);
      assert.strictEqual(audit.alerts[0].type, 'KERNEL_OOM_TRIGGERED');
    });
  });

  describe('Pillar 5: Landlock LSM & Seccomp-BPF Guard', () => {
    it('should generate Landlock ruleset restricting access to tentRoot while denying /etc and /root', () => {
      const landlock = new LinuxSeccompLandlock();
      const ruleset = landlock.generateLandlockRuleset('/workspace/tent');

      assert.strictEqual(ruleset.abiVersion, 3);
      assert.ok(ruleset.handledAccessFs.includes('LANDLOCK_ACCESS_FS_EXECUTE'));
      assert.ok(ruleset.rules.some(r => r.targetPath.includes('/workspace/tent')));
      assert.ok(ruleset.deniedPaths.includes('/etc/shadow'));
      assert.ok(ruleset.deniedPaths.includes('/root'));
      assert.ok(ruleset.deniedPaths.includes('/dev/mem'));
    });

    it('should generate Seccomp filter blocking 13 dangerous system calls', () => {
      const seccomp = new LinuxSeccompLandlock();
      const filter = seccomp.generateSeccompFilter();

      assert.strictEqual(filter.defaultAction, 'SECCOMP_RET_ALLOW');
      assert.strictEqual(filter.ruleCount, 13);

      const syscallNames = filter.blockedSyscalls.map(s => s.name);
      assert.ok(syscallNames.includes('ptrace'));
      assert.ok(syscallNames.includes('bpf'));
      assert.ok(syscallNames.includes('init_module'));
      assert.ok(syscallNames.includes('pivot_root'));
      assert.ok(syscallNames.includes('setns'));
      assert.ok(syscallNames.includes('mknod'));
      assert.ok(filter.bpfInstructions.length > 10);
    });
  });

  describe('Pillar 6: Linux Enclave Runner End-to-End Orchestration', () => {
    let runner;

    beforeEach(() => {
      runner = new LinuxEnclaveRunner();
      runner.prepareLinuxEnclave({
        agentId: 'linux_agent_alpha',
        tentRoot: '/workspace/tent_alpha',
        relaxedSecurity: true, // Agent is given root inside user namespace
        resourceLimits: { maxPids: 40, maxMemoryBytes: 256 * 1024 * 1024 }
      });
    });

    it('should reject attempted ptrace syscall via Seccomp-BPF even in relaxed mode', () => {
      const actionCheck = runner.validateProposedAction('linux_agent_alpha', {
        syscall: 'ptrace'
      });

      assert.strictEqual(actionCheck.allowed, false);
      assert.strictEqual(actionCheck.violationType, 'SECCOMP_SYSCALL_BLOCKED');
      assert.ok(actionCheck.reason.includes('ptrace'));
    });

    it('should reject attempted filesystem access to /etc/shadow via Landlock LSM', () => {
      const actionCheck = runner.validateProposedAction('linux_agent_alpha', {
        targetPath: '/etc/shadow'
      });

      assert.strictEqual(actionCheck.allowed, false);
      assert.strictEqual(actionCheck.violationType, 'LANDLOCK_PATH_ACCESS_DENIED');
      assert.ok(actionCheck.reason.includes('Landlock'));
    });

    it('should reject fork bomb attempting to spawn 50 processes when pids.max is 40', () => {
      const actionCheck = runner.validateProposedAction('linux_agent_alpha', {
        processCount: 45
      });

      assert.strictEqual(actionCheck.allowed, false);
      assert.strictEqual(actionCheck.violationType, 'KERNEL_FORK_BOMB_INTERCEPTED');
    });

    it('should allow legitimate in-tent file access', () => {
      const actionCheck = runner.validateProposedAction('linux_agent_alpha', {
        targetPath: '/workspace/tent_alpha/src/main.c',
        processCount: 5
      });

      assert.strictEqual(actionCheck.allowed, true);
    });
  });
});
