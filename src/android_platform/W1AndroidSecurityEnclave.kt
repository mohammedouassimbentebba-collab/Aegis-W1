package org.w1.defense

import java.io.File

/**
 * W1™ Android Security Enclave (درع أمان نظام أندرويد وفرض العزل)
 * File: src/android_platform/W1AndroidSecurityEnclave.kt
 *
 * Core Responsibility:
 * Enforces Android Application Sandbox & SELinux invariants:
 * 1. Storage Geofencing: Confines file operations strictly to app's internal private storage (context.filesDir).
 * 2. Intent Geofencing: Restricts broadcast/service intents to explicit internal package destinations.
 * 3. Permission Auditing: Blocks ambient access to dangerous mobile sensors (Camera, Mic, GPS, SMS).
 */
class W1AndroidSecurityEnclave(
    private val allowedPackageName: String = "org.w1.defense"
) {

    data class ValidationResult(
        val allowed: Boolean,
        val violationType: String? = null,
        val reason: String? = null
    )

    /**
     * Validates storage path containment against Android App Sandbox rules.
     */
    fun validateStorageAccess(targetPath: String, appInternalDir: File): ValidationResult {
        val canonicalInternal = appInternalDir.canonicalPath
        val targetFile = File(targetPath)
        val canonicalTarget = targetFile.canonicalPath

        // 1. Block Path Traversal (../)
        if (!canonicalTarget.startsWith(canonicalInternal)) {
            return ValidationResult(
                allowed = false,
                violationType = "ANDROID_SANDBOX_ESCAPE",
                reason = "Target path '$targetPath' escapes internal app sandbox directory '$canonicalInternal'."
            )
        }

        // 2. Block direct references to shared storage or other app sandboxes
        val forbiddenPrefixes = listOf(
            "/data/data/",
            "/data/user/",
            "/sdcard/",
            "/storage/emulated/0/"
        )

        for (prefix in forbiddenPrefixes) {
            if (targetPath.startsWith(prefix) && !canonicalTarget.startsWith(canonicalInternal)) {
                return ValidationResult(
                    allowed = false,
                    violationType = "CROSS_APP_STORAGE_ACCESS_DENIED",
                    reason = "Access to external/cross-app storage '$targetPath' is forbidden by SELinux."
                )
            }
        }

        return ValidationResult(allowed = true)
    }

    /**
     * Enforces explicit Intent destination (SELinux broadcast & IPC isolation).
     */
    fun validateIntentDestination(targetPackage: String?): ValidationResult {
        if (targetPackage.isNullOrEmpty()) {
            return ValidationResult(
                allowed = false,
                violationType = "IMPLICIT_INTENT_FORBIDDEN",
                reason = "Implicit intents with null/empty package allow rogue apps to intercept data."
            )
        }

        if (targetPackage != allowedPackageName) {
            return ValidationResult(
                allowed = false,
                violationType = "CROSS_PACKAGE_INTENT_BLOCKED",
                reason = "Intent target package '$targetPackage' does not match authorized enclave package '$allowedPackageName'."
            )
        }

        return ValidationResult(allowed = true)
    }

    /**
     * Audits requested mobile permissions to enforce Zero Ambient Authority.
     */
    fun auditRequestedPermissions(permissions: List<String>): List<String> {
        val dangerousKeywords = listOf(
            "CAMERA",
            "RECORD_AUDIO",
            "ACCESS_FINE_LOCATION",
            "READ_CONTACTS",
            "SEND_SMS",
            "READ_CALL_LOG"
        )

        val violations = mutableListOf<String>()
        for (perm in permissions) {
            for (keyword in dangerousKeywords) {
                if (perm.contains(keyword, ignoreCase = true)) {
                    violations.add("DANGEROUS_HARDWARE_PERMISSION: Permission '$perm' requires explicit human capability token.")
                }
            }
        }

        return violations
    }
}
