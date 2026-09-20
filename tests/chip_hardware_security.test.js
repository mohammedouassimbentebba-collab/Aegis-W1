import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ChipHardwareSecurityLayer } from '../src/core/chip_hardware_security_layer.js';
import { X86MachineCodeCPU } from '../src/radar_machine_code/x86_machine_code_cpu.js';

describe('W1™ Chip, Processor & Hardware MMU Security Layer', () => {
  const hwLayer = new ChipHardwareSecurityLayer();

  it('should intercept Ring-0 privileged opcodes (CLI, STI, WRMSR, HLT) in userland code', () => {
    // 0xFA is CLI (Clear Interrupt Flag) - Ring 0 only
    const hostileCliCode = new Uint8Array([0x90, 0xfa, 0x90]);
    const cliAudit = hwLayer.auditInstructionStream(hostileCliCode);

    assert.strictEqual(cliAudit.safe, false);
    assert.ok(cliAudit.violations.some(v => v.includes('RING0_PRIVILEGED_OPCODE_BLOCKED')));
    assert.ok(cliAudit.violations.some(v => v.includes('CLI')));

    // 0x0F, 0x30 is WRMSR (Write to Model Specific Register) - Ring 0 only
    const hostileMsrCode = new Uint8Array([0x0f, 0x30]);
    const msrAudit = hwLayer.auditInstructionStream(hostileMsrCode);

    assert.strictEqual(msrAudit.safe, false);
    assert.ok(msrAudit.violations.some(v => v.includes('WRMSR')));

    // Benign userland instruction: NOPs and arithmetic
    const benignCode = new Uint8Array([0x90, 0x90, 0x48, 0x01, 0xd8]); // NOP, NOP, add rax, rbx
    const benignAudit = hwLayer.auditInstructionStream(benignCode);
    assert.strictEqual(benignAudit.safe, true);
  });

  it('should enforce W^X (Write XOR Execute) memory page containment', () => {
    const code = new Uint8Array([0x90]);

    // Page that is simultaneously writable AND executable (self-modifying shellcode vector)
    const dangerousPage = { isWritable: true, isExecutable: true };
    const audit = hwLayer.auditInstructionStream(code, dangerousPage);

    assert.strictEqual(audit.safe, false);
    assert.ok(audit.violations.some(v => v.includes('W_XOR_X_VIOLATION')));

    // Proper W^X compliant page: Executable but Read-Only
    const compliantPage = { isWritable: false, isExecutable: true };
    const compliantAudit = hwLayer.auditInstructionStream(code, compliantPage);
    assert.strictEqual(compliantAudit.safe, true);
  });

  it('should enforce MMU virtual address geofencing against kernel & MMIO regions', () => {
    // 1. Null page dereference trap
    const nullAccess = hwLayer.verifyMmuAccess(0x00000000n, 'READ');
    assert.strictEqual(nullAccess.allowed, false);
    assert.ok(nullAccess.faultReason.includes('NULL_PAGE_TRAP'));

    // 2. Hardware MMIO bus trap (0x000A0000 - 0x000FFFFF)
    const mmioAccess = hwLayer.verifyMmuAccess(0x000B8000n, 'WRITE');
    assert.strictEqual(mmioAccess.allowed, false);
    assert.ok(mmioAccess.faultReason.includes('MMIO_HARDWARE_BUS'));

    // 3. Ring-0 Kernel memory region (0xFFFF800000000000)
    const kernelAccess = hwLayer.verifyMmuAccess(0xFFFF800000001000n, 'READ');
    assert.strictEqual(kernelAccess.allowed, false);
    assert.ok(kernelAccess.faultReason.includes('RING0_KERNEL_BASE'));

    // 4. Safe userland buffer address
    const safeAccess = hwLayer.verifyMmuAccess(0x00400000n, 'READ');
    assert.strictEqual(safeAccess.allowed, true);
  });

  it('should scrub CPU microarchitectural registers to prevent Spectre/Meltdown leakage', () => {
    const cpu = new X86MachineCodeCPU(64 * 1024);

    // Contaminate CPU registers with agent execution state
    cpu.registers.rax = 0xDEADBEEFn;
    cpu.registers.rbx = 0xCAFEBABE12345678n;
    cpu.registers.r8 = 0x1122334455667788n;
    cpu.flags.zf = true;
    cpu.flags.cf = true;

    // Perform register scrubbing
    const scrubbed = hwLayer.scrubCpuRegisters(cpu);
    assert.strictEqual(scrubbed, true);

    // Verify all registers zeroed
    assert.strictEqual(cpu.registers.rax, 0n);
    assert.strictEqual(cpu.registers.rbx, 0n);
    assert.strictEqual(cpu.registers.r8, 0n);
    assert.strictEqual(cpu.flags.zf, false);
    assert.strictEqual(cpu.flags.cf, false);
  });

  it('should inject microarchitectural timing jitter for side-channel defense', () => {
    const jitter = hwLayer.injectTimingJitter();
    assert.ok(jitter >= 5, 'Jitter must be >= 5 microseconds');
  });
});
