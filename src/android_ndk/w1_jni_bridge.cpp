/*
 * W1™ Aerospace Radar: Android JNI (Java Native Interface) Bridge
 * File: src/android_ndk/w1_jni_bridge.cpp
 * Target: Android ART Runtime / Kotlin W1NativeEngine
 */

#include <jni.h>
#include "w1_radar_neon.h"
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Checks if ARM NEON SIMD vector hardware is supported at runtime.
 */
JNIEXPORT jboolean JNICALL
Java_org_w1_defense_W1NativeEngine_isNeonSupported(JNIEnv* env, jobject /* this */) {
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

/**
 * Native matched filter pulse compression using ARM NEON SIMD registers.
 */
JNIEXPORT jfloatArray JNICALL
Java_org_w1_defense_W1NativeEngine_processRadarSamplesNeon(
    JNIEnv* env,
    jobject /* this */,
    jfloatArray inputSamples,
    jfloatArray chirpRef
) {
    jsize length = env->GetArrayLength(inputSamples);
    jfloat* inPtr = env->GetFloatArrayElements(inputSamples, nullptr);
    jfloat* refPtr = env->GetFloatArrayElements(chirpRef, nullptr);

    std::vector<float> output(length);

    // Call ARM NEON vectorized core
    w1_neon_matched_filter(inPtr, refPtr, output.data(), length);

    env->ReleaseFloatArrayElements(inputSamples, inPtr, JNI_ABORT);
    env->ReleaseFloatArrayElements(chirpRef, refPtr, JNI_ABORT);

    jfloatArray result = env->NewFloatArray(length);
    env->SetFloatArrayRegion(result, 0, length, output.data());

    return result;
}

/**
 * Native Mie resonance evaluation and stealth airframe classification.
 */
JNIEXPORT jint JNICALL
Java_org_w1_defense_W1NativeEngine_classifyStealthTarget(
    JNIEnv* env,
    jobject /* this */,
    jint trackId,
    jfloat rcsVhf,
    jfloat rcsX,
    jfloat rangeKm,
    jfloat velocityMs,
    jfloat azimuthDeg,
    jfloat elevationDeg
) {
    w1_mobile_target_track_t track = w1_neon_mie_resonance_eval(
        (uint32_t)trackId,
        (float)rcsVhf,
        (float)rcsX,
        (float)rangeKm,
        (float)velocityMs,
        (float)azimuthDeg,
        (float)elevationDeg
    );

    return (jint)track.classification;
}

#ifdef __cplusplus
}
#endif
