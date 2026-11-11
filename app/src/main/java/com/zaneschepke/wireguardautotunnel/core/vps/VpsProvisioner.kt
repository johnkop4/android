package com.zaneschepke.wireguardautotunnel.core.vps

import com.wgtunnel.parser.Config
import com.wgtunnel.parser.crypto.Key
import com.zaneschepke.wireguardautotunnel.core.auth.GoogleTokenProvider
import com.zaneschepke.wireguardautotunnel.core.tunnel.VpsTunnel
import com.zaneschepke.wireguardautotunnel.data.DataStoreManager
import com.zaneschepke.wireguardautotunnel.domain.model.TunnelConfig
import com.zaneschepke.wireguardautotunnel.domain.repository.TunnelRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import timber.log.Timber

/** [needsSignIn] means the user has to open the app (or sign in again) before it can work. */
class VpsProvisionException(val detail: String?, val needsSignIn: Boolean = false) :
    Exception(detail)

/**
 * Gets the interface side of the VPS tunnel from the server. The WireGuard key pair is made on the
 * device and only the public key is sent, the server answers with the address and DNS to use.
 */
class VpsProvisioner(
    private val dataStoreManager: DataStoreManager,
    private val tunnelRepository: TunnelRepository,
    private val tokenProvider: GoogleTokenProvider,
    private val ioDispatcher: CoroutineDispatcher,
) {

    /** The tunnel as it should be stored right now, built from the last server answer if any. */
    suspend fun expectedTunnelConfig(): Result<TunnelConfig> {
        val privateKey = privateKey()
        return VpsTunnel.tunnelConfig(privateKey, storedProvision())
    }

    /**
     * Registers this device with the server and returns [tunnel] with the config to run. When the
     * server can not be asked (offline, started in the background with an expired token) the last
     * answer is reused for as long as it is still valid.
     */
    suspend fun provision(tunnel: TunnelConfig): Result<TunnelConfig> =
        try {
            Result.success(provisionOrThrow(tunnel))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.w(e, "VPS provisioning failed")
            Result.failure(e)
        }

    private suspend fun provisionOrThrow(tunnel: TunnelConfig): TunnelConfig {
        if (!VpsApi.isConfigured) throw VpsProvisionException("No server address in this build")
        val privateKey = privateKey()
        val publicKey = Config.generatePublicKeyFromPrivateKey(privateKey)

        val provision =
            try {
                register(publicKey).also {
                    dataStoreManager.saveToDataStore(DataStoreManager.vpsProvision, it.toJson())
                }
            } catch (e: VpsProvisionException) {
                // No token to ask with
                storedProvision()?.takeIf { it.isUsable() } ?: throw e
            } catch (e: VpsApiException) {
                val code = e.httpCode
                when {
                    code == 401 -> throw VpsProvisionException(e.message, needsSignIn = true)
                    // The server said no, an older answer must not be used to get around that
                    code != null && code < 500 -> throw VpsProvisionException(e.message)
                    else ->
                        storedProvision()?.takeIf { it.isUsable() }
                            ?: throw VpsProvisionException(e.message)
                }
            }

        val expected = VpsTunnel.tunnelConfig(privateKey, provision).getOrThrow()
        if (tunnel.quickConfig == expected.quickConfig) return tunnel
        return tunnel.copy(quickConfig = expected.quickConfig).also { tunnelRepository.save(it) }
    }

    private suspend fun register(publicKey: String): VpsProvision {
        suspend fun call(token: String) =
            withContext(ioDispatcher) { VpsApi.registerPeer(token, publicKey) }

        val token = tokenProvider.idToken() ?: throw VpsProvisionException(null, needsSignIn = true)
        return try {
            call(token)
        } catch (e: VpsApiException) {
            if (e.httpCode != 401) throw e
            // Most likely expired on the way, try once more with a new one
            val renewed =
                tokenProvider.idToken(forceRefresh = true)
                    ?: throw VpsProvisionException(null, needsSignIn = true)
            call(renewed)
        }
    }

    /** Forgets the address of the account that signed out, the next one gets its own. */
    suspend fun onSignedOut() {
        dataStoreManager.removeFromDataStore(DataStoreManager.vpsProvision)
        val expected = expectedTunnelConfig().getOrNull() ?: return
        val current = tunnelRepository.findByTunnelName(VpsTunnel.NAME) ?: return
        if (current.quickConfig != expected.quickConfig) {
            tunnelRepository.save(current.copy(quickConfig = expected.quickConfig))
        }
    }

    private suspend fun storedProvision(): VpsProvision? =
        dataStoreManager.getFromStore(DataStoreManager.vpsProvision)?.let {
            runCatching { VpsProvision.fromJson(it) }.getOrNull()
        }

    /**
     * The server ties a public key to one Google account, so the key is kept across sign-outs of
     * the same account and replaced as soon as another account uses the device.
     */
    private suspend fun privateKey(): String {
        val account = dataStoreManager.getFromStore(DataStoreManager.authUserId)
        val stored = dataStoreManager.getFromStore(DataStoreManager.vpsWgPrivateKey)
        val owner = dataStoreManager.getFromStore(DataStoreManager.vpsWgKeyOwner)

        val reusable = !stored.isNullOrBlank() && (account == null || owner == null || owner == account)
        val key =
            if (reusable) stored
            else {
                dataStoreManager.removeFromDataStore(DataStoreManager.vpsProvision)
                Key.generatePrivateKey().toBase64().also {
                    dataStoreManager.saveToDataStore(DataStoreManager.vpsWgPrivateKey, it)
                }
            }
        if (account != null && owner != account) {
            dataStoreManager.saveToDataStore(DataStoreManager.vpsWgKeyOwner, account)
        }
        return key
    }
}
