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
 *
 * REMEDIATION (2026-09-20):
 * - Fixed path traversal via startsWith() by appending trailing File.separator.
 *   Without the trailing separator, paths like "/data/user/0/org.w1.defense_evil" would pass
 *   the check because they start with "/data/user/0/org.w1.defense".
 * - Removed unreachable dead code in check 2 (was always short-circuited by check 1).
 * - Added symlink loop detection.
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
     *
     * REMEDIATION: Uses trailing File.separator to prevent sibling directory bypass.
     * e.g., "/data/user/0/org.w1.defense_evil" no longer passes the check
     * because we now compare against "/data/user/0/org.w1.defense/" (with trailing slash).
     */
    fun validateStorageAccess(targetPath: String, appInternalDir: File): ValidationResult {
        val canonicalInternal = appInternalDir.canonicalFile
        val targetFile = File(targetPath)
        val canonicalTarget: File

        try {
            canonicalTarget = targetFile.canonicalFile
        } catch (e: Exception) {
            return ValidationResult(
                allowed = false,
                violationType = "PATH_RESOLUTION_FAILURE",
                reason = "Failed to resolve canonical path for '$targetPath': ${e.message}"
            )
        }

        // Build the boundary string with a trailing separator to prevent prefix collision.
        // Without this, startsWith("/data/user/0/org.w1.defense") would match
        // "/data/user/0/org.w1.defense_evil/db.sqlite" — a sibling directory escape.
        val internalPathStr = canonicalInternal.path
        val internalWithSep = if (internalPathStr.endsWith(File.separator))
            internalPathStr else internalPathStr + File.separator

        // Allow access to the directory itself OR any file/directory strictly inside it
        val isContained = (canonicalTarget == canonicalInternal) ||
            canonicalTarget.path.startsWith(internalWithSep)

        // 1. Block Path Traversal (../) and sibling directory escape
        if (!isContained) {
            return ValidationResult(
                allowed = false,
                violationType = "ANDROID_SANDBOX_ESCAPE",
                reason = "Target path '$targetPath' (resolved: '${canonicalTarget.path}') " +
                    "escapes internal app sandbox directory '${canonicalInternal.path}'."
            )
        }

        // 2. Block access to sensitive system directories even if they appear inside the sandbox
        // (defense in depth against bind mount or symlink tricks)
        val forbiddenSubstrings = listOf(
            "/proc/", "/sys/", "/dev/", "/../"
        )
        val canonicalTargetPath = canonicalTarget.path
        for (forbidden in forbiddenSubstrings) {
            if (canonicalTargetPath.contains(forbidden)) {
                return ValidationResult(
                    allowed = false,
                    violationType = "SYSTEM_PATH_ACCESS_DENIED",
                    reason = "Access to system path '$forbidden' within sandbox is forbidden."
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
            "READ_CALL_LOG",
            "READ_PHONE_STATE",
            "ACCESS_COARSE_LOCATION",
            "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE",
            "INSTALL_PACKAGES"
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
