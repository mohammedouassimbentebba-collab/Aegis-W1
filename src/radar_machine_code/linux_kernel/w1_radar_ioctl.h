/*
 * W1™ Aerospace Radar: Custom Linux Kernel Module IOCTL Interface
 * File: w1_radar_ioctl.h
 * Architecture: Linux Kernel Ring-0 Driver Interface
 */

#ifndef _W1_RADAR_IOCTL_H
#define _W1_RADAR_IOCTL_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#define W1_RADAR_MAGIC 'W'

/* Frequency Bands */
#define W1_BAND_VHF_METRIC     0x01   /* 150 - 250 MHz (λ = 1.2 - 2.0 m): Anti-Stealth Resonant */
#define W1_BAND_UHF_DECIMETRIC 0x02   /* 400 - 800 MHz (λ = 37.5 - 75 cm): Structural Cavity Resonance */
#define W1_BAND_X_CENTIMETRIC  0x03   /* 8 - 12 GHz (λ = 2.5 - 3.75 cm): Conventional Fire Control */

/* Stealth Classification Flags */
#define W1_TARGET_CONVENTIONAL   0x00
#define W1_TARGET_STEALTH_F22    0x01
#define W1_TARGET_STEALTH_F35    0x02
#define W1_TARGET_STEALTH_B2     0x03
#define W1_TARGET_COGNITIVE_ZERO 0x04

/* Radar Hardware Configuration */
struct w1_radar_config {
    uint32_t frequency_band;     /* W1_BAND_VHF_METRIC or W1_BAND_UHF_DECIMETRIC */
    uint32_t carrier_freq_hz;    /* Center frequency in Hz (e.g., 180000000 for 180 MHz) */
    uint32_t pulse_repetition_freq_hz; /* PRF (e.g. 1000 Hz) */
    float    pulse_width_us;     /* Chirp duration in microseconds */
    float    bandwidth_mhz;      /* Chirp bandwidth in MHz */
    uint32_t antenna_elements;   /* Number of active phased-array elements (e.g. 64) */
    uint32_t stap_enabled;       /* 1 = STAP multipath nulling enabled, 0 = disabled */
};

/* Target Telemetry Track Record */
struct w1_radar_target_track {
    uint32_t track_id;
    uint32_t classification;     /* W1_TARGET_* */
    float    azimuth_deg;        /* 0 - 360 deg */
    float    elevation_deg;      /* -10 to +80 deg */
    float    range_km;           /* Distance in kilometers */
    float    radial_velocity_ms; /* Doppler velocity (m/s) */
    float    rcs_vhf_sqm;        /* Observed VHF Radar Cross Section (m²) */
    float    rcs_x_sqm;          /* Observed X-band Radar Cross Section (m²) */
    float    mie_resonance_gain; /* Ratio σ_VHF / σ_X */
    uint64_t detection_timestamp_ns;
};

/* Ring Buffer Telemetry */
struct w1_radar_telemetry {
    uint64_t total_pulses_transmitted;
    uint64_t total_echoes_processed;
    uint32_t active_stealth_tracks;
    uint32_t dropped_samples;
    float    avg_clutter_suppression_db;
};

/* IOCTL Command Definitions */
#define W1_RADAR_IOCTL_SET_CONFIG \
    _IOW(W1_RADAR_MAGIC, 0x01, struct w1_radar_config)

#define W1_RADAR_IOCTL_GET_CONFIG \
    _IOR(W1_RADAR_MAGIC, 0x02, struct w1_radar_config)

#define W1_RADAR_IOCTL_START_SWEEP \
    _IO(W1_RADAR_MAGIC, 0x03)

#define W1_RADAR_IOCTL_STOP_SWEEP \
    _IO(W1_RADAR_MAGIC, 0x04)

#define W1_RADAR_IOCTL_READ_TRACKS \
    _IOR(W1_RADAR_MAGIC, 0x05, struct w1_radar_target_track[32])

#define W1_RADAR_IOCTL_GET_TELEMETRY \
    _IOR(W1_RADAR_MAGIC, 0x06, struct w1_radar_telemetry)

#endif /* _W1_RADAR_IOCTL_H */
