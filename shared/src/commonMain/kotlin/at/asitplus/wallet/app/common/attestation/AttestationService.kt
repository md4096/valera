package at.asitplus.wallet.app.common.attestation

import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.ClientNonceResponse
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.wallet.app.common.BuildContext
import at.asitplus.wallet.app.common.HttpService
import at.asitplus.wallet.app.common.data.SettingsRepository
import at.asitplus.wallet.lib.oauth2.OAuth2ProtocolClient.LoadInstanceAttestationInput
import at.asitplus.wallet.lib.oidvci.OpenId4VciClient.KeyAttestationInput
import io.github.aakira.napier.Napier
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.http.URLBuilder
import io.ktor.http.appendEncodedPathSegments
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

class AttestationService(
    private val config: SettingsRepository,
    buildContext: BuildContext,
    httpService: HttpService,
) {
    private val scope = CoroutineScope(Dispatchers.IO)
    private val httpClient = httpService.buildHttpClient()

    private fun challengeEndpoint() = config.walletProviderHost.map {
        URLBuilder(it).apply {
            appendEncodedPathSegments(PATH_NONCE)
        }
    }

    private val instanceAttestationHelper = InstanceAttestationHelper(
        config = config,
        httpClient = httpClient,
        buildContext = buildContext,
    )

    private val keyAttestationHelper = KeyAttestationHelper(config, httpClient)
    val bufferedInstanceAttestation = MutableStateFlow<JwsCompactTyped<JsonWebToken>?>(null)

    suspend fun reset() {
        bufferedInstanceAttestation.emit(null)
        instanceAttestationHelper.reset()
    }

    suspend fun getInstanceAttestationKeyMaterial() = instanceAttestationHelper.keyMaterial()

    fun currentInstanceAttestation() = instanceAttestationHelper.currentInstanceAttestation()

    suspend fun restoreInstanceAttestation(attestation: JwsCompactTyped<JsonWebToken>) {
        bufferedInstanceAttestation.emit(null)
        instanceAttestationHelper.restoreInstanceAttestation(attestation)
    }

    suspend fun loadInstanceAttestation(input: LoadInstanceAttestationInput) = catching {
        ensureWalletProviderAttestationEnabled()
        requestInstanceAttestation(input)
    }

    /** Loads a key attestation of the keys of [input]. VC-K's proof creators check the attested keys. */
    suspend fun loadKeyAttestation(input: KeyAttestationInput) = catching {
        ensureWalletProviderAttestationEnabled()
        fetchKeyAttestation(input)
    }

    fun getWalletProviderHost() = config.walletProviderHost
    fun setWalletProviderHost(host: String) = scope.launch {
        config.set(walletProviderHost = host)
        reset()
    }

    private suspend fun requestInstanceAttestation(
        input: LoadInstanceAttestationInput,
    ): JwsCompactTyped<JsonWebToken> {
        if (allowBuffer()) {
            bufferedInstanceAttestation.firstOrNull()?.let { buffer ->
                if (buffer.hasRemainingClientStatusPeriod(input.preferredClientStatusPeriod ?: PREFERRED_DEFAULT_TTL)) {
                    Napier.d("AttestationService: Use buffered instance attestation")
                    return buffer
                }
            }
        }


        Napier.d("AttestationService: Request new instance attestation")
        return instanceAttestationHelper.instanceAttestation(input.preferredClientStatusPeriod ?: PREFERRED_DEFAULT_TTL)
            .also {
                if (allowBuffer()) {
                    bufferedInstanceAttestation.emit(it)
                }
            }
    }

    private suspend fun fetchKeyAttestation(
        input: KeyAttestationInput,
    ): JwsCompactTyped<KeyAttestationJwt> {
        require(input.keys.isNotEmpty()) { "No keys to attest" }
        Napier.d("AttestationService: Request new key attestation")
        val instanceAttestation = requestInstanceAttestation(
            LoadInstanceAttestationInput(
                authorizationServer = "",
                credentialIssuer = input.credentialIssuer ?: "",
                preferredClientStatusPeriod = PREFERRED_DEFAULT_TTL
            )
        )

        val pop = instanceAttestationHelper.buildProofOfPossession(
            audience = config.walletProviderHost.first(), nonce = getChallenge()
        )

        return keyAttestationHelper.requestKeyAttestation(
            keys = input.keys,
            instanceAttestation = instanceAttestation,
            pop = pop,
            nonce = input.clientNonce,
            preferredKeyStorageStatusPeriod = input.preferredKeyStorageStatusPeriod,
            supportedAlgorithms = input.supportedAlgorithms
        )
    }


    private fun JwsCompactTyped<JsonWebToken>.hasRemainingClientStatusPeriod(ttl: Duration): Boolean {
        val now = Clock.System.now()
        return payload.expiration?.let { it > now + 10.seconds } == true && payload.clientStatus?.expiration?.let { it > now + ttl } == true
    }

    private suspend fun getChallenge() = catchingUnwrapped {
        httpClient.get(challengeEndpoint().first().build()) {}.body<ClientNonceResponse>().clientNonce
    }.onFailure {
        Napier.e("AttestationService: Error receiving challenge. $it")
    }.getOrNull()

    private suspend fun ensureWalletProviderAttestationEnabled() {
        if (!config.walletProviderAttestationEnabled.first()) {
            throw WalletProviderAttestationDisabledException()
        }
    }

}

class WalletProviderAttestationDisabledException : IllegalStateException(
    "The issuing service requires wallet provider attestation, but wallet provider attestation is disabled in settings."
)

fun allowBuffer() = false
