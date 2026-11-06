package com.likfridman.dpibypass

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** Плитка в шторке: включить/выключить обход одним касанием. */
class ToggleTile : TileService() {
    override fun onStartListening() = refresh()

    override fun onClick() {
        if (Engine.running || Engine.starting) {
            BypassVpnService.stop(this)
        } else if (VpnService.prepare(this) == null) {
            Engine.starting = true
            BypassVpnService.start(this)
        } else {
            // нужно разрешение на VPN - открываем приложение
            val i = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(android.app.PendingIntent.getActivity(this, 0, i, android.app.PendingIntent.FLAG_IMMUTABLE))
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(i)
            }
        }
        qsTile?.let { it.state = if (Engine.running || Engine.starting) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE; it.updateTile() }
    }

    private fun refresh() {
        qsTile?.let {
            it.state = if (Engine.running || Engine.starting) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            it.updateTile()
        }
    }
}
