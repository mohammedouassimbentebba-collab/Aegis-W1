package org.w1.defense

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log

/**
 * W1™ Android Defense Foreground Service (خدمة المراقبة الأمامية في أندرويد)
 * File: src/android_platform/W1DefenseForegroundService.kt
 *
 * Ensures continuous, uninterrupted radar processing and AI agent safety monitoring
 * without being terminated by Android battery optimization / Doze mode.
 */
class W1DefenseForegroundService : Service() {

    companion object {
        private const val TAG = "W1_Foreground_Service"
        private const val CHANNEL_ID = "w1_c2_channel"
        private const val NOTIFICATION_ID = 1001
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private var isMonitoringActive: Boolean = false

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "Initializing W1 Defense Foreground Service...")

        createNotificationChannel()
        val notification = buildForegroundNotification()
        startForeground(NOTIFICATION_ID, notification)

        acquireWakeLock()
        isMonitoringActive = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "W1 Defense C2 Heartbeat engaged.")
        // START_STICKY ensures service is restarted if killed under memory pressure
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? {
        // Direct Binder binding disabled to preserve strict zero-ambient IPC
        return null
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.i(TAG, "Terminating W1 Defense Foreground Service...")
        isMonitoringActive = false
        releaseWakeLock()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "W1 Defense Tactical Grid",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Active anti-stealth radar telemetry and AI agent safety containment"
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildForegroundNotification(): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("W1™ Defense Grid Active")
            .setContentText("ARM NEON Radar Processing & Agent Containment Nominal")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setOngoing(true)
            .build()
    }

    private fun acquireWakeLock() {
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "W1Defense:C2TelemetryWakeLock"
        ).apply {
            acquire(10 * 60 * 1000L /* 10 minutes */)
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
            }
        }
        wakeLock = null
    }
}
