package at.asitplus.wallet.app.common.attestation

import at.asitplus.openid.DurationSecondsIntSerializer
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.app.common.data.SettingsRepository
import at.asitplus.wallet.app.common.keys.HolderKeyStorage
import io.github.aakira.napier.Napier
import io.ktor.client.HttpClient
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.appendEncodedPathSegments
import io.ktor.http.contentType
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Duration

class KeyAttestationHelper(
    private val config: SettingsRepository,
    private val httpClient: HttpClient,
) {
    private fun keyAttestationEndpoint() = config.walletProviderHost.map {
        URLBuilder(it).apply {
            appendEncodedPathSegments(PATH_UNIT)
        }
    }

    /** Requests a key attestation of [keys], in order, from the wallet provider. */
    suspend fun requestKeyAttestation(
        keys: List<CryptoPublicKey>,
        instanceAttestation: JwsCompactTyped<JsonWebToken>,
        pop: JwsCompactTyped<JsonWebToken>,
        nonce: String?,
        preferredKeyStorageStatusPeriod: Duration?,
        supportedAlgorithms: Collection<String>?

    ): JwsCompactTyped<KeyAttestationJwt> {
        Napier.d("Requesting key attestation for keys ${keys.map { it.toJsonWebKey().jwkThumbprint }}")
        return httpClient.post(Url(keyAttestationEndpoint().first())) {
            contentType(ContentType.Application.Json)
            setBody(
                KeyAttestationRequest(
                    token = instanceAttestation.jws.toString(),
                    keys = keys.map { it.toJsonWebKey() },
                    proof = pop.jws.toString(),
                    nonce = nonce,
                    keyStorage = setOf(HolderKeyStorage.KEY_STORAGE),
                    userAuthentication = setOf(HolderKeyStorage.USER_AUTHENTICATION),
                    preferredKeyStorageStatusPeriod = preferredKeyStorageStatusPeriod,
                    supportedAlgorithms = supportedAlgorithms,
                )
            )
        }.let { response ->
            when (response.status) {
                HttpStatusCode.OK -> {
                    JwsCompactTyped<KeyAttestationJwt>(response.bodyAsText())
                }
                else -> {
                    throw Throwable(message = "Server responded with an error", cause = Throwable(response.bodyAsText()))
                }
            }
        }
    }
}

@Serializable
private data class KeyAttestationRequest(
    @SerialName("token") val token: String,
    @SerialName("proof") val proof: String,
    @SerialName("keys") val keys: List<JsonWebKey>,
    @SerialName("nonce") val nonce: String?,
    @SerialName("key_storage") val keyStorage: Set<String>,
    @SerialName("user_authentication") val userAuthentication: Set<String>,
    @SerialName("preferred_key_storage_status_period")
    @Serializable(with = DurationSecondsIntSerializer::class)
    val preferredKeyStorageStatusPeriod: Duration?,
    @SerialName("supported_algorithms") val supportedAlgorithms: Collection<String>?,
)
