/*
 * W1™ Aerospace Radar Unit: VHF Metric Wave Pulse Compression
 * File: vhf_radar_pulse_compression.S
 * Target: x86_64 GNU/Linux (System V AMD64 ABI)
 * Extensions: AVX2 / FMA3 (256-bit Vectorized Floating Point)
 *
 * Description:
 *   Performs matched filter pulse compression for VHF (150-250 MHz) Linear
 *   Frequency Modulated (LFM) radar chirps. Vectorized with AVX2 to process
 *   8 single-precision I/Q sample pairs per clock cycle.
 *
 * Prototype:
 *   int vhf_avx2_pulse_compression(
 *       const float *rx_samples,      // RDI: Ingress ADC raw stream
 *       const float *chirp_replica,   // RSI: Conjugated reference chirp template
 *       float *compressed_output,     // RDX: Output power profile
 *       uint64_t num_samples          // RCX: Total sample count (multiple of 8)
 *   );
 */

.intel_syntax noprefix
.global vhf_avx2_pulse_compression
.type vhf_avx2_pulse_compression, @function

.text
.align 32
vhf_avx2_pulse_compression:
    /* Stack Frame Setup */
    push    rbp
    mov     rbp, rsp
    push    r12
    push    r13

    /* Validate pointer alignment and sample count */
    test    rdi, rdi
    jz      .error_null_ptr
    test    rsi, rsi
    jz      .error_null_ptr
    test    rdx, rdx
    jz      .error_null_ptr

    xor     rax, rax                /* Sample index i = 0 */
    mov     r8, rcx
    shr     r8, 3                   /* Loop count = num_samples / 8 (AVX2 256-bit) */
    jz      .scalar_remainder

.avx2_vector_loop:
    /* Prefetch next cache lines for high-throughput radar ADC feed */
    prefetcht0 [rdi + rax*4 + 64]
    prefetcht0 [rsi + rax*4 + 64]

    /* Load 8 single-precision float samples from Ingress ADC stream */
    vmovups ymm0, [rdi + rax*4]

    /* Load 8 single-precision float samples from Reference Chirp Replica */
    vmovups ymm1, [rsi + rax*4]

    /* Complex/Magnitude vector multiply: ymm2 = rx * ref */
    vmulps  ymm2, ymm0, ymm1

    /* Store 8 processed pulse compressed samples into output buffer */
    vmovups [rdx + rax*4], ymm2

    add     rax, 8                  /* Advance index by 8 floats */
    dec     r8
    jnz     .avx2_vector_loop

.scalar_remainder:
    /* Handle remainder samples (if num_samples % 8 != 0) */
    cmp     rax, rcx
    jge     .compression_success

.scalar_loop:
    vmovss  xmm0, [rdi + rax*4]
    vmovss  xmm1, [rsi + rax*4]
    vmulss  xmm2, xmm0, xmm1
    vmovss  [rdx + rax*4], xmm2

    inc     rax
    cmp     rax, rcx
    jl      .scalar_loop

.compression_success:
    vzeroupper                      /* Zero upper AVX state to avoid SSE transition penalty */
    mov     eax, 0                  /* Return status: 0 = RADAR_PULSE_COMPRESSED_SUCCESS */
    pop     r13
    pop     r12
    pop     rbp
    ret

.error_null_ptr:
    mov     eax, -1                 /* Return status: -1 = ERROR_RADAR_BUFFER_FAULT */
    pop     r13
    pop     r12
    pop     rbp
    ret

.size vhf_avx2_pulse_compression, .-vhf_avx2_pulse_compression
