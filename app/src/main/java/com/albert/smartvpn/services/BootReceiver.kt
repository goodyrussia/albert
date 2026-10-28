package com.albert.smartvpn.services

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.albert.smartvpn.vpn.SmartVpnService

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            // Verify VPN permission is already granted by Android
            if (VpnService.prepare(context) == null) {
                val startIntent = Intent(context, SmartVpnService::class.java).apply {
                    action = SmartVpnService.ACTION_START
                }
                context.startService(startIntent)
            }
        }
    }
}
