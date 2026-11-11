package com.zaneschepke.wireguardautotunnel.ui.screens.auth

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.zaneschepke.wireguardautotunnel.R
import com.zaneschepke.wireguardautotunnel.core.auth.GoogleSignInClient
import com.zaneschepke.wireguardautotunnel.core.auth.SignInResult
import kotlinx.coroutines.launch
import org.koin.compose.koinInject

@Composable
fun SignInScreen(signInClient: GoogleSignInClient = koinInject()) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val focusRequester = remember { FocusRequester() }

    var inProgress by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val notConfigured = stringResource(R.string.sign_in_not_configured)
    val failed = stringResource(R.string.sign_in_failed)

    LaunchedEffect(Unit) { runCatching { focusRequester.requestFocus() } }

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        modifier =
            Modifier.fillMaxSize()
                .background(MaterialTheme.colorScheme.surface)
                .systemBarsPadding()
                .padding(24.dp),
    ) {
        Icon(
            Icons.Outlined.VpnKey,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(56.dp),
        )
        Text(
            text = stringResource(R.string.sign_in_title),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface,
            textAlign = TextAlign.Center,
        )
        Text(
            text = stringResource(R.string.sign_in_subtitle),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.outline,
            textAlign = TextAlign.Center,
        )
        Button(
            enabled = !inProgress,
            onClick = {
                inProgress = true
                error = null
                scope.launch {
                    // On success the auth state flips and this screen leaves the composition
                    when (val result = signInClient.signIn(context)) {
                        is SignInResult.Success,
                        SignInResult.Cancelled -> Unit
                        SignInResult.NotConfigured -> error = notConfigured
                        is SignInResult.Failed ->
                            error = listOfNotNull(failed, result.message).joinToString("\n")
                    }
                    inProgress = false
                }
            },
            modifier = Modifier.widthIn(max = 360.dp).fillMaxWidth().focusRequester(focusRequester),
        ) {
            if (inProgress) {
                CircularProgressIndicator(
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.size(18.dp),
                )
            } else {
                Text(stringResource(R.string.sign_in_with_google))
            }
        }
        error?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                textAlign = TextAlign.Center,
            )
        }
    }
}
