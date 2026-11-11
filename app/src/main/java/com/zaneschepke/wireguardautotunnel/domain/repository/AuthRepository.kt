package com.zaneschepke.wireguardautotunnel.domain.repository

import com.zaneschepke.wireguardautotunnel.domain.model.AuthState
import com.zaneschepke.wireguardautotunnel.domain.model.AuthUser
import kotlinx.coroutines.flow.StateFlow

interface AuthRepository {
    val state: StateFlow<AuthState>

    /** Reads straight from storage, safe to call before [state] has loaded. */
    suspend fun isSignedIn(): Boolean

    suspend fun setUser(user: AuthUser)

    suspend fun clear()
}
