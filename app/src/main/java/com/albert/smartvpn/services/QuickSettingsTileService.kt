package com.albert.smartvpn.services

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi
import com.albert.smartvpn.vpn.SmartVpnService

@RequiresApi(Build.VERSION_CODES.N)
class QuickSettingsTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTileState(false)
    }

    override fun onClick() {
        super.onClick()
        val tile = qsTile ?: return

        if (tile.state == Tile.STATE_ACTIVE) {
            val stopIntent = Intent(this, SmartVpnService::class.java).apply {
                action = SmartVpnService.ACTION_STOP
            }
            startService(stopIntent)
            updateTileState(false)
        } else {
            val prepareIntent = VpnService.prepare(this)
            if (prepareIntent == null) {
                val startIntent = Intent(this, SmartVpnService::class.java).apply {
                    action = SmartVpnService.ACTION_START
                }
                startService(startIntent)
                updateTileState(true)
            }
        }
    }

    private fun updateTileState(isActive: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (isActive) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = if (isActive) "Smart VPN (Active)" else "Smart VPN"
        tile.updateTile()
    }
}
