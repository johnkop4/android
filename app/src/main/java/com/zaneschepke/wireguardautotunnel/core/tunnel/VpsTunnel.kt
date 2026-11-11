package com.zaneschepke.wireguardautotunnel.core.tunnel

import com.wgtunnel.parser.Config
import com.zaneschepke.wireguardautotunnel.BuildConfig
import com.zaneschepke.wireguardautotunnel.domain.model.TunnelConfig

/**
 * The one and only tunnel of this build, the connection to the VPS peer. The values are baked in at
 * build time (see the VPS_WG_* fields in app/build.gradle.kts), there is no way to add, import,
 * edit or delete tunnels from the app.
 */
object VpsTunnel {
    const val NAME = "VPS"

    private fun quickConfig(): String = buildString {
        fun line(key: String, value: String) {
            if (value.isNotBlank()) appendLine("$key = ${value.trim()}")
        }
        appendLine("[Interface]")
        line("PrivateKey", BuildConfig.VPS_WG_PRIVATE_KEY)
        line("Address", BuildConfig.VPS_WG_ADDRESS)
        line("DNS", BuildConfig.VPS_WG_DNS)
        appendLine()
        appendLine("[Peer]")
        line("PublicKey", BuildConfig.VPS_WG_PEER_PUBLIC_KEY)
        line("PresharedKey", BuildConfig.VPS_WG_PRESHARED_KEY)
        line("Endpoint", BuildConfig.VPS_WG_ENDPOINT)
        line("AllowedIPs", BuildConfig.VPS_WG_ALLOWED_IPS)
        line("PersistentKeepalive", BuildConfig.VPS_WG_PERSISTENT_KEEPALIVE)
    }

    /** Fails when the build has no (or an invalid) VPS configuration. */
    fun tunnelConfig(): Result<TunnelConfig> = runCatching {
        val config = Config.parseQuickString(quickConfig())
        config.validate()
        TunnelConfig(name = NAME, quickConfig = config.asQuickString(), isPrimaryTunnel = true)
    }
}
