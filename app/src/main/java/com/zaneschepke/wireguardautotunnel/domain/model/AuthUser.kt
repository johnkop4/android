package com.zaneschepke.wireguardautotunnel.domain.model

data class AuthUser(val id: String, val email: String, val displayName: String? = null)

sealed interface AuthState {
    data object Loading : AuthState

    data object SignedOut : AuthState

    data class SignedIn(val user: AuthUser) : AuthState
}
