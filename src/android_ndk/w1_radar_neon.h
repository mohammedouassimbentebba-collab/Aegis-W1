/*
 * W1™ Aerospace Radar: ARM NEON SIMD Radar Processing Engine Header
 * File: src/android_ndk/w1_radar_neon.h
 * Target: Android ARM64 (aarch64) / ARM32 (armeabi-v7a)
 */

#ifndef _W1_RADAR_NEON_H
#define _W1_RADAR_NEON_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Target Classification Constants */
#define W1_NEON_TARGET_CONVENTIONAL   0
#define W1_NEON_TARGET_STEALTH_B2     1
#define W1_NEON_TARGET_STEALTH_F35    2
#define W1_NEON_TARGET_STEALTH_F22    3
#define W1_NEON_TARGET_COGNITIVE_ZERO 4

/* Stealth Mie Resonance Thresholds */
#define W1_MIE_RESONANCE_RATIO_THRESHOLD 1000.0f /* +30 dB gain */

/* Android Mobile Target Track Struct */
typedef struct {
    uint32_t track_id;
    uint32_t classification;
    float azimuth_deg;
    float elevation_deg;
    float range_km;
    float radial_velocity_ms;
    float rcs_vhf_sqm;
    float rcs_x_sqm;
    float mie_resonance_gain;
    bool is_stealth;
} w1_mobile_target_track_t;

/* Function Declarations */

/**
 * Executes high-speed 128-bit ARM NEON vector pulse compression deconvolution.
 */
void w1_neon_matched_filter(
    const float* __restrict__ input_samples,
    const float* __restrict__ chirp_reference,
    float* __restrict__ output_compressed,
    int length
);

/**
 * Evaluates Mie structural resonance ratio (σ_VHF / σ_X) using ARM vector registers.
 */
w1_mobile_target_track_t w1_neon_mie_resonance_eval(
    uint32_t track_id,
    float rcs_vhf,
    float rcs_x,
    float range_km,
    float velocity_ms,
    float azimuth,
    float elevation
);

/**
 * Cell-Averaging Constant False Alarm Rate (CA-CFAR) detector with ARM NEON acceleration.
 */
int w1_neon_cfar_detector(
    const float* __restrict__ power_spectrum,
    uint8_t* __restrict__ detection_mask,
    int length,
    int guard_cells,
    int training_cells,
    float pfa_factor
);

#ifdef __cplusplus
}
#endif

#endif /* _W1_RADAR_NEON_H */
