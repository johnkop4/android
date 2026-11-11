package com.zaneschepke.wireguardautotunnel.data.repository

import com.zaneschepke.wireguardautotunnel.data.DataStoreManager
import com.zaneschepke.wireguardautotunnel.domain.model.AuthState
import com.zaneschepke.wireguardautotunnel.domain.model.AuthUser
import com.zaneschepke.wireguardautotunnel.domain.repository.AuthRepository
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.plus

class DataStoreAuthRepository(
    private val dataStoreManager: DataStoreManager,
    applicationScope: CoroutineScope,
    ioDispatcher: CoroutineDispatcher,
) : AuthRepository {

    override val state: StateFlow<AuthState> =
        dataStoreManager.preferencesFlow
            .map { prefs ->
                val id = prefs?.get(DataStoreManager.authUserId)
                val email = prefs?.get(DataStoreManager.authUserEmail)
                if (id.isNullOrBlank() || email.isNullOrBlank()) {
                    AuthState.SignedOut
                } else {
                    AuthState.SignedIn(
                        AuthUser(
                            id = id,
                            email = email,
                            displayName = prefs[DataStoreManager.authUserName],
                        )
                    )
                }
            }
            .stateIn(
                scope = applicationScope + ioDispatcher,
                started = SharingStarted.Eagerly,
                initialValue = AuthState.Loading,
            )

    override suspend fun isSignedIn(): Boolean {
        return !dataStoreManager.getFromStore(DataStoreManager.authUserId).isNullOrBlank()
    }

    override suspend fun setUser(user: AuthUser) {
        dataStoreManager.saveToDataStore(DataStoreManager.authUserEmail, user.email)
        dataStoreManager.saveToDataStore(DataStoreManager.authUserName, user.displayName.orEmpty())
        // Written last, it is the key that marks the session as signed in
        dataStoreManager.saveToDataStore(DataStoreManager.authUserId, user.id)
    }

    override suspend fun clear() {
        dataStoreManager.removeFromDataStore(DataStoreManager.authUserId)
        dataStoreManager.removeFromDataStore(DataStoreManager.authUserEmail)
        dataStoreManager.removeFromDataStore(DataStoreManager.authUserName)
    }
}
