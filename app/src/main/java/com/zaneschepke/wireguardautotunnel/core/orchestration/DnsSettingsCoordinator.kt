package com.zaneschepke.wireguardautotunnel.core.orchestration

import com.wgtunnel.backend.Backend
import com.wgtunnel.backend.model.dns.DnsBoostrapMode

class DnsSettingsCoordinator(private val backend: Backend) {

    /** Peer endpoints are always resolved with the system resolver, it is not configurable. */
    suspend fun applyDnsSettings() {
        backend.setBootstrapDnsMode(DnsBoostrapMode.System)
    }
}
