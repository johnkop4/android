package com.zaneschepke.wireguardautotunnel.core.vps

import android.annotation.SuppressLint
import com.zaneschepke.wireguardautotunnel.BuildConfig
import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import org.json.JSONObject

/** What the server hands out for a registered peer, see `POST /peers`. */
data class VpsProvision(
    val address: String,
    val serverPublicKey: String,
    val endpoint: String,
    val dns: String,
    val allowedIps: String,
    val subscribed: Boolean,
    /** Unix seconds, null when the peer has no time limit. */
    val expiresAt: Long?,
) {
    fun isUsable(nowSeconds: Long = System.currentTimeMillis() / 1000): Boolean =
        expiresAt == null || expiresAt > nowSeconds

    fun toJson(): String =
        JSONObject()
            .put("address", address)
            .put("server_public_key", serverPublicKey)
            .put("endpoint", endpoint)
            .put("dns", dns)
            .put("allowed_ips", allowedIps)
            .put("subscribed", subscribed)
            .put("expires_at", expiresAt ?: JSONObject.NULL)
            .toString()

    companion object {
        fun fromJson(json: String): VpsProvision {
            val o = JSONObject(json)
            return VpsProvision(
                address = o.getString("address"),
                serverPublicKey = o.getString("server_public_key"),
                endpoint = o.getString("endpoint"),
                dns = o.optString("dns"),
                allowedIps = o.optString("allowed_ips").ifBlank { "0.0.0.0/0, ::/0" },
                subscribed = o.optBoolean("subscribed", false),
                expiresAt = if (o.isNull("expires_at")) null else o.getLong("expires_at"),
            )
        }
    }
}

/** [httpCode] is null when the server could not be reached or its answer made no sense. */
class VpsApiException(message: String, val httpCode: Int? = null, cause: Throwable? = null) :
    Exception(message, cause)

/**
 * Client for the peer provisioning API on the VPS. The server is reached by IP with a self-signed
 * certificate, so instead of the system trust store the connection only accepts the one certificate
 * whose SHA-256 fingerprint was baked into the build (VPS_API_CERT_SHA256).
 */
object VpsApi {
    private const val CONNECT_TIMEOUT_MS = 8_000
    private const val READ_TIMEOUT_MS = 10_000

    private val baseUrl: String
        get() = BuildConfig.VPS_API_URL.trim().trimEnd('/')

    /** The Google ID token must never travel over plain http. */
    val isConfigured: Boolean
        get() = baseUrl.startsWith("https://")

    /** Blocking, call from an IO dispatcher. */
    fun registerPeer(idToken: String, publicKey: String): VpsProvision {
        if (!isConfigured) throw VpsApiException("No https server address in this build")
        val url = URL("$baseUrl/peers")
        val connection =
            try {
                (url.openConnection() as HttpsURLConnection).apply {
                    pinnedFingerprint()?.let { pin ->
                        val context = SSLContext.getInstance("TLS")
                        context.init(null, arrayOf(PinnedTrustManager(pin)), null)
                        sslSocketFactory = context.socketFactory
                        // Trust is tied to one exact certificate, its name does not add anything
                        setHostnameVerifier { host, _ -> host == url.host }
                    }
                    requestMethod = "POST"
                    connectTimeout = CONNECT_TIMEOUT_MS
                    readTimeout = READ_TIMEOUT_MS
                    doOutput = true
                    setRequestProperty("Authorization", "Bearer $idToken")
                    setRequestProperty("Content-Type", "application/json")
                    setRequestProperty("Accept", "application/json")
                }
            } catch (e: VpsApiException) {
                throw e
            } catch (e: Exception) {
                throw VpsApiException("Could not set up the server connection", cause = e)
            }

        try {
            val code: Int
            val body: String
            try {
                connection.outputStream.use {
                    it.write(JSONObject().put("public_key", publicKey).toString().toByteArray())
                }
                code = connection.responseCode
                body =
                    (if (code in 200..299) connection.inputStream else connection.errorStream)
                        ?.bufferedReader()
                        ?.use { it.readText() }
                        .orEmpty()
            } catch (e: Exception) {
                throw VpsApiException(e.message ?: "Server unreachable", cause = e)
            }

            if (code !in 200..299) {
                // FastAPI answers errors with {"detail": "..."}
                val detail =
                    runCatching { JSONObject(body).optString("detail") }
                        .getOrNull()
                        .takeUnless { it.isNullOrBlank() }
                throw VpsApiException(detail ?: "HTTP $code", httpCode = code)
            }
            return try {
                VpsProvision.fromJson(body)
            } catch (e: Exception) {
                throw VpsApiException("Unexpected server response", cause = e)
            }
        } finally {
            connection.disconnect()
        }
    }

    /** Accepts `AB:CD:..`, plain hex and the full `sha256 Fingerprint=AB:CD:..` line of openssl. */
    private fun pinnedFingerprint(): ByteArray? {
        val raw = BuildConfig.VPS_API_CERT_SHA256.substringAfterLast('=').trim()
        if (raw.isEmpty()) return null
        val hex = raw.filterNot { it == ':' || it.isWhitespace() }
        if (hex.length != 64 || hex.any { Character.digit(it, 16) < 0 }) {
            throw VpsApiException("VPS_API_CERT_SHA256 is not a SHA-256 fingerprint")
        }
        return ByteArray(32) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    @SuppressLint("CustomX509TrustManager")
    private class PinnedTrustManager(private val pin: ByteArray) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            throw CertificateException("Client certificates are not supported")
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            val leaf = chain?.firstOrNull() ?: throw CertificateException("Empty chain")
            leaf.checkValidity()
            val fingerprint = MessageDigest.getInstance("SHA-256").digest(leaf.encoded)
            if (!MessageDigest.isEqual(fingerprint, pin)) {
                throw CertificateException("Server certificate does not match the pinned one")
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
}
