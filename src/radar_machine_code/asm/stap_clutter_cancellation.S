/*
 * W1™ Aerospace Radar Unit: Space-Time Adaptive Processing (STAP) Clutter Nuller
 * File: stap_clutter_cancellation.S
 * Target: x86_64 GNU/Linux (System V AMD64 ABI)
 * Extensions: AVX2 / FMA3 (Fused Multiply-Add)
 *
 * Description:
 *   Applies adaptive 2D space-time weight vectors (W) to antenna array pulses
 *   to place deep spatial/Doppler nulls on ground multipath reflections and
 *   diffuse terrain clutter inherent to VHF metric wave propagation.
 *
 * Prototype:
 *   float stap_avx2_apply_weights(
 *       const float *spatial_channel_vector, // RDI: Antenna array I/Q samples
 *       const float *adaptive_stap_weights,  // RSI: Inverted covariance steering weights
 *       uint64_t dimension                   // RDX: Space-Time degree of freedom (N_elements * N_pulses)
 *   );
 */

.intel_syntax noprefix
.global stap_avx2_apply_weights
.type stap_avx2_apply_weights, @function

.text
.align 32
stap_avx2_apply_weights:
    push    rbp
    mov     rbp, rsp

    /* Initialize 256-bit accumulator to 0.0 */
    vxorps  ymm0, ymm0, ymm0

    xor     rax, rax                /* Index i = 0 */
    mov     rcx, rdx
    shr     rcx, 3                  /* Vector blocks = dimension / 8 */
    jz      .stap_scalar_tail

.stap_avx2_loop:
    /* Load 8 spatial samples and 8 adaptive weights */
    vmovups ymm1, [rdi + rax*4]
    vmovups ymm2, [rsi + rax*4]

    /* Fused Multiply-Add: ymm0 += ymm1 * ymm2 */
    vfmadd231ps ymm0, ymm1, ymm2

    add     rax, 8
    dec     rcx
    jnz     .stap_avx2_loop

    /* Horizontal reduction of ymm0 vector into scalar float (xmm0) */
    vextractf128 xmm1, ymm0, 1      /* Extract upper 128 bits into xmm1 */
    vaddps  xmm0, xmm0, xmm1        /* Add upper and lower 128 bits */
    vhaddps xmm0, xmm0, xmm0        /* Horizontal pairwise sum 1 */
    vhaddps xmm0, xmm0, xmm0        /* Horizontal pairwise sum 2 */

.stap_scalar_tail:
    /* Accumulate remaining scalar elements */
    cmp     rax, rdx
    jge     .stap_complete

.stap_scalar_loop:
    vmovss  xmm1, [rdi + rax*4]
    vmovss  xmm2, [rsi + rax*4]
    vmulss  xmm1, xmm1, xmm2
    vaddss  xmm0, xmm0, xmm1

    inc     rax
    cmp     rax, rdx
    jl      .stap_scalar_loop

.stap_complete:
    vzeroupper
    pop     rbp
    ret

.size stap_avx2_apply_weights, .-stap_avx2_apply_weights
