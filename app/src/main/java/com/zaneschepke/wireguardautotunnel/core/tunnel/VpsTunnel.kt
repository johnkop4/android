package com.zaneschepke.wireguardautotunnel.core.tunnel

import com.wgtunnel.parser.Config
import com.zaneschepke.wireguardautotunnel.BuildConfig
import com.zaneschepke.wireguardautotunnel.core.vps.VpsProvision
import com.zaneschepke.wireguardautotunnel.domain.model.TunnelConfig

/**
 * The one and only tunnel of this build, the connection to the VPS peer. There is no way to add,
 * import, edit or delete tunnels from the app. The interface side (key, address, DNS) is not part
 * of the build: the key is generated on the device and the rest comes from the server when
 * connecting, see VpsProvisioner.
 */
object VpsTunnel {
    const val NAME = "VPS"

    // Documentation range (RFC 5737), stands in until the server has assigned the real values.
    // The tunnel can not be started in that state, every start goes through the provisioner first.
    private const val UNASSIGNED_ADDRESS = "192.0.2.1/32"
    private const val UNASSIGNED_ENDPOINT = "192.0.2.1:51820"

    private fun quickConfig(privateKey: String, provision: VpsProvision?): String = buildString {
        fun line(key: String, value: String?) {
            if (!value.isNullOrBlank()) appendLine("$key = ${value.trim()}")
        }
        // What the server says wins over the values of the build
        val peerKey =
            provision?.serverPublicKey
                ?: BuildConfig.VPS_WG_PEER_PUBLIC_KEY.ifBlank {
                    Config.generatePublicKeyFromPrivateKey(privateKey)
                }
        appendLine("[Interface]")
        line("PrivateKey", privateKey)
        line("Address", provision?.address ?: UNASSIGNED_ADDRESS)
        line("DNS", provision?.dns)
        appendLine()
        appendLine("[Peer]")
        line("PublicKey", peerKey)
        line("PresharedKey", BuildConfig.VPS_WG_PRESHARED_KEY)
        line(
            "Endpoint",
            provision?.endpoint ?: BuildConfig.VPS_WG_ENDPOINT.ifBlank { UNASSIGNED_ENDPOINT },
        )
        line("AllowedIPs", provision?.allowedIps ?: BuildConfig.VPS_WG_ALLOWED_IPS)
        line("PersistentKeepalive", BuildConfig.VPS_WG_PERSISTENT_KEEPALIVE)
    }

    fun tunnelConfig(privateKey: String, provision: VpsProvision?): Result<TunnelConfig> =
        runCatching {
            val config = Config.parseQuickString(quickConfig(privateKey, provision))
            config.validate()
            TunnelConfig(name = NAME, quickConfig = config.asQuickString(), isPrimaryTunnel = true)
        }
}
