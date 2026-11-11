package com.zaneschepke.wireguardautotunnel.core.orchestration

import android.content.Context
import com.zaneschepke.wireguardautotunnel.core.tunnel.TunnelProvider
import com.zaneschepke.wireguardautotunnel.core.tunnel.VpsTunnel
import com.zaneschepke.wireguardautotunnel.core.vps.VpsProvisioner
import com.zaneschepke.wireguardautotunnel.domain.enums.BootstrapDnsProtocol
import com.zaneschepke.wireguardautotunnel.domain.enums.TunnelMode
import com.zaneschepke.wireguardautotunnel.domain.repository.DnsSettingsRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.GeneralSettingRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.LockdownSettingsRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.TunnelRepository
import com.zaneschepke.wireguardautotunnel.service.tile.AutoTunnelTileRefresher
import com.zaneschepke.wireguardautotunnel.service.tile.TunnelTileRefresher
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import timber.log.Timber

class AppBoostrapCoordinator(
    private val settingsRepository: GeneralSettingRepository,
    private val dnsRepository: DnsSettingsRepository,
    private val tunnelRepository: TunnelRepository,
    private val lockdownRepository: LockdownSettingsRepository,
    private val tunnelProvider: TunnelProvider,
    private val dnsSettingsCoordinator: DnsSettingsCoordinator,
    private val vpsProvisioner: VpsProvisioner,
) {

    private val _isReady = MutableStateFlow(false)
    val isReady: StateFlow<Boolean> = _isReady.asStateFlow()

    suspend fun bootstrap(context: Context) = coroutineScope {
        val criticalTasks =
            listOf(
                async { bootstrapDns() },
                async { ensureGlobalConfig() },
                async { ensureVpsTunnel() },
                async { restoreBackendConfiguration() },
            )

        try {
            criticalTasks.awaitAll()
            _isReady.value = true
            Timber.d("App bootstrap completed successfully")
        } catch (e: Exception) {
            Timber.e(e, "One or more critical bootstrap tasks failed")
            _isReady.value = true
        } finally {
            TunnelTileRefresher.refresh(context)
            AutoTunnelTileRefresher.refresh(context)
        }
    }

    private suspend fun bootstrapDns() {
        // Older installs may still hold a custom peer resolver, reset it
        val dnsSettings = dnsRepository.getDnsSettings()
        if (
            dnsSettings.bootstrapDnsProtocol != BootstrapDnsProtocol.SYSTEM ||
                dnsSettings.bootstrapDnsEndpoint != null
        ) {
            dnsRepository.upsert(
                dnsSettings.copy(
                    bootstrapDnsProtocol = BootstrapDnsProtocol.SYSTEM,
                    bootstrapDnsEndpoint = null,
                )
            )
        }
        dnsSettingsCoordinator.applyDnsSettings()
    }

    private suspend fun ensureGlobalConfig() {
        tunnelRepository.ensureGlobalConfigExists()
    }

    /**
     * Keeps the tunnel list locked to the single VPS tunnel. Anything else that found its
     * way into the database (older installs, a restored backup) is removed.
     */
    private suspend fun ensureVpsTunnel() {
        val expected =
            vpsProvisioner.expectedTunnelConfig().getOrElse {
                Timber.e(it, "Could not build the VPS tunnel configuration")
                null
            }
        val userTunnels = tunnelRepository.getAll().filterNot { it.isGlobalConfig }
        val current =
            if (expected == null) null else userTunnels.firstOrNull { it.name == VpsTunnel.NAME }
        val stale = userTunnels.filter { it.id != current?.id }
        if (stale.isNotEmpty()) tunnelRepository.delete(stale)
        if (expected == null) return

        when {
            current == null -> tunnelRepository.save(expected)
            current.quickConfig != expected.quickConfig ||
                !current.isPrimaryTunnel ||
                current.groupId != null ||
                current.entryTunnelId != null ->
                tunnelRepository.save(
                    current.copy(
                        quickConfig = expected.quickConfig,
                        isPrimaryTunnel = true,
                        groupId = null,
                        entryTunnelId = null,
                    )
                )
        }
    }

    private suspend fun restoreBackendConfiguration() {
        val settings = settingsRepository.getGeneralSettings()

        when (settings.tunnelMode) {
            TunnelMode.LOCK_DOWN -> {
                val lockdownSettings = lockdownRepository.getLockdownSettings()
                tunnelProvider.setLockDown(lockdownSettings).onFailure {
                    Timber.w(it, "Failed to restore lockdown/kill-switch on startup")
                }
            }
            else -> Unit
        }
    }
}
