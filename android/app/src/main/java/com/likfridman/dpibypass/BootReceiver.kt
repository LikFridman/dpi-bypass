package com.likfridman.dpibypass

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

/** Включение обхода после перезагрузки телефона (если включено в параметрах). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (!Store.boot(ctx)) return
        if (VpnService.prepare(ctx) != null) return // разрешения на VPN ещё нет
        Engine.log("Телефон включился - запускаю обход")
        BypassVpnService.start(ctx)
    }
}
