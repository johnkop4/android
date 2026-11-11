package com.zaneschepke.wireguardautotunnel.core.auth

import android.app.Activity
import android.content.Context
import android.util.Base64
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.zaneschepke.wireguardautotunnel.BuildConfig
import com.zaneschepke.wireguardautotunnel.domain.model.AuthState
import com.zaneschepke.wireguardautotunnel.domain.repository.AuthRepository
import java.lang.ref.WeakReference
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import timber.log.Timber

/**
 * Hands out Google ID tokens for the signed in account, the server wants one on every request. They
 * only live for about an hour, so the token is kept in memory and silently renewed when it ran out.
 */
class GoogleTokenProvider(
    private val appContext: Context,
    private val authRepository: AuthRepository,
) {
    @Volatile private var cached: String? = null
    @Volatile private var activity: WeakReference<Activity>? = null

    /** A silent renewal works best on top of a visible activity. */
    fun attach(activity: Activity) {
        this.activity = WeakReference(activity)
    }

    fun remember(idToken: String) {
        cached = idToken
    }

    fun clear() {
        cached = null
    }

    /** Null when no token can be had without the user, e.g. started in the background. */
    suspend fun idToken(forceRefresh: Boolean = false): String? {
        if (!forceRefresh) cached?.takeIf(::isFresh)?.let { return it }

        val clientId = BuildConfig.GOOGLE_WEB_CLIENT_ID.trim()
        if (clientId.isBlank()) return null
        val context = activity?.get() ?: appContext
        val token =
            try {
                withTimeoutOrNull(RENEW_TIMEOUT_MS) {
                    val option =
                        GetGoogleIdOption.Builder()
                            .setServerClientId(clientId)
                            .setFilterByAuthorizedAccounts(true)
                            .setAutoSelectEnabled(true)
                            .build()
                    val request = GetCredentialRequest.Builder().addCredentialOption(option).build()
                    val credential =
                        CredentialManager.create(context).getCredential(context, request).credential
                    if (
                        credential is CustomCredential &&
                            credential.type ==
                                GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
                    ) {
                        GoogleIdTokenCredential.createFrom(credential.data).idToken
                    } else null
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Timber.w(e, "Could not renew the Google ID token")
                null
            } ?: return null

        // With several accounts on the device a different one could have been picked
        val expected = (authRepository.state.value as? AuthState.SignedIn)?.user?.id
        val actual = claims(token)?.optString("sub")
        if (expected != null && actual != expected) {
            Timber.w("Renewed ID token belongs to another account, ignoring it")
            return null
        }
        cached = token
        return token
    }

    private fun isFresh(idToken: String): Boolean {
        val exp = claims(idToken)?.optLong("exp", 0L) ?: 0L
        return exp - EXPIRY_MARGIN_SECONDS > System.currentTimeMillis() / 1000
    }

    companion object {
        private const val RENEW_TIMEOUT_MS = 20_000L
        private const val EXPIRY_MARGIN_SECONDS = 60L

        // Only reads the claims. The signature is verified by the server, not on the device.
        fun claims(idToken: String): JSONObject? =
            runCatching {
                    val payload = idToken.split(".")[1]
                    val json =
                        Base64.decode(
                            payload,
                            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
                        )
                    JSONObject(String(json, Charsets.UTF_8))
                }
                .onFailure { Timber.w(it, "Could not decode id token claims") }
                .getOrNull()
    }
}
