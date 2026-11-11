package com.zaneschepke.wireguardautotunnel.core.auth

import android.content.Context
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.Credential
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialOption
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.NoCredentialException
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.zaneschepke.wireguardautotunnel.BuildConfig
import com.zaneschepke.wireguardautotunnel.core.orchestration.AutoTunnelCoordinator
import com.zaneschepke.wireguardautotunnel.core.orchestration.TunnelCoordinator
import com.zaneschepke.wireguardautotunnel.core.vps.VpsProvisioner
import com.zaneschepke.wireguardautotunnel.domain.model.AuthUser
import com.zaneschepke.wireguardautotunnel.domain.repository.AuthRepository
import kotlinx.coroutines.CancellationException
import timber.log.Timber

sealed interface SignInResult {
    data class Success(val user: AuthUser) : SignInResult

    data object Cancelled : SignInResult

    /** No OAuth web client id was baked into this build. */
    data object NotConfigured : SignInResult

    data class Failed(val message: String?) : SignInResult
}

/**
 * Google account sign-in through Credential Manager. A Google account has no separate sign-up step,
 * picking an account for the first time is the sign-up.
 */
class GoogleSignInClient(
    private val appContext: Context,
    private val authRepository: AuthRepository,
    private val tunnelCoordinator: TunnelCoordinator,
    private val autoTunnelCoordinator: AutoTunnelCoordinator,
    private val tokenProvider: GoogleTokenProvider,
    private val vpsProvisioner: VpsProvisioner,
) {

    /** [activityContext] must be an Activity context, the account picker is shown on top of it. */
    suspend fun signIn(activityContext: Context): SignInResult {
        val clientId = BuildConfig.GOOGLE_WEB_CLIENT_ID.trim()
        if (clientId.isBlank()) return SignInResult.NotConfigured

        val credentialManager = CredentialManager.create(activityContext)
        return try {
            val credential =
                try {
                    credentialManager.request(
                        activityContext,
                        GetGoogleIdOption.Builder()
                            .setServerClientId(clientId)
                            .setFilterByAuthorizedAccounts(false)
                            .setAutoSelectEnabled(false)
                            .build(),
                    )
                } catch (e: NoCredentialException) {
                    // No account on the device yet, fall back to the full Google sign-in flow
                    credentialManager.request(
                        activityContext,
                        GetSignInWithGoogleOption.Builder(clientId).build(),
                    )
                }
            val user =
                credential.toAuthUser()
                    ?: return SignInResult.Failed("Unexpected credential type: ${credential.type}")
            authRepository.setUser(user)
            SignInResult.Success(user)
        } catch (e: CancellationException) {
            throw e
        } catch (e: GetCredentialCancellationException) {
            SignInResult.Cancelled
        } catch (e: Exception) {
            Timber.e(e, "Google sign-in failed")
            SignInResult.Failed(e.message)
        }
    }

    suspend fun signOut() {
        // The tunnel is only for signed in users, bring everything down first
        runCatching { autoTunnelCoordinator.disable() }.onFailure { Timber.e(it) }
        runCatching { tunnelCoordinator.stopActiveTunnels() }.onFailure { Timber.e(it) }
        authRepository.clear()
        tokenProvider.clear()
        runCatching { vpsProvisioner.onSignedOut() }.onFailure { Timber.e(it) }
        try {
            CredentialManager.create(appContext).clearCredentialState(ClearCredentialStateRequest())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.w(e, "Failed to clear credential state")
        }
    }

    private suspend fun CredentialManager.request(
        context: Context,
        option: CredentialOption,
    ): Credential {
        val request = GetCredentialRequest.Builder().addCredentialOption(option).build()
        return getCredential(context, request).credential
    }

    private fun Credential.toAuthUser(): AuthUser? {
        if (
            this !is CustomCredential ||
                type != GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
        ) {
            return null
        }
        val google = GoogleIdTokenCredential.createFrom(data)
        // Kept for the server, which verifies it when the tunnel is started
        tokenProvider.remember(google.idToken)
        val claims = GoogleTokenProvider.claims(google.idToken)
        val email = claims?.optString("email").takeUnless { it.isNullOrBlank() } ?: google.id
        return AuthUser(
            // "sub" is the stable Google account id, the email can change
            id = claims?.optString("sub").takeUnless { it.isNullOrBlank() } ?: google.id,
            email = email,
            displayName = google.displayName,
        )
    }
}
