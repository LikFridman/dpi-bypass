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
        } else if (VpnService.prepare(this) == null && Store.consentOK(this) && Store.chosenSites(this) != null) {
            Engine.starting = true
            BypassVpnService.start(this)
        } else {
            // нужно разрешение на VPN, согласие или выбор сервисов - открываем приложение
            val i = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(android.app.PendingIntent.getActivity(this, 0, i, android.app.PendingIntent.FLAG_IMMUTABLE))
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(i)
            }
        }
        refresh()
    }

    private fun refresh() {
        qsTile?.let {
            val on = Engine.running || Engine.starting
            it.state = if (on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            if (Build.VERSION.SDK_INT >= 29) {
                it.subtitle = when {
                    Engine.starting && !Engine.running -> "подбор…"
                    Engine.running -> Engine.results.values.let { r -> if (r.isEmpty()) "on" else "${r.count { p -> p.ok }}/${r.size} ok" }
                    else -> "off"
                }
            }
            it.updateTile()
        }
    }

    companion object {
        /** Обновить плитку (обход включился / выключился) */
        fun update(ctx: android.content.Context) {
            runCatching { requestListeningState(ctx, android.content.ComponentName(ctx, ToggleTile::class.java)) }
        }
    }
}
