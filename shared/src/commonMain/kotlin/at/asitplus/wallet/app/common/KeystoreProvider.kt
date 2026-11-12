package at.asitplus.wallet.app.common

import AppResetRequiredException
import at.asitplus.KmmResult
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.app.common.keys.HolderKeyFactory
import at.asitplus.wallet.app.common.keys.LEGACY_CERT_STORAGE_KEY
import at.asitplus.wallet.app.common.keys.PersistentSelfSignedCertKey
import at.asitplus.wallet.app.common.keys.PlatformHolderKeyFactory
import at.asitplus.wallet.app.common.keys.certificateStorageKey
import data.storage.DataStoreService
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext


open class KeystoreService(
    private val dataStoreService: DataStoreService,
    /** Runs the keystore calls of the session one after the other, also those of [holderKeyFactory]. */
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(1),
    /** Tests replace it with one that doesn't need the platform keystore. */
    val holderKeyFactory: HolderKeyFactory = PlatformHolderKeyFactory(dispatcher),
) {

    @Deprecated("Use HolderKeyManager.legacyKey()")
    @Throws(Throwable::class)
    open suspend fun getSigner(): KeyMaterial = catchingUnwrapped {
        val signer = holderKeyFactory.load(Configuration.KS_ALIAS) ?: holderKeyFactory.create(Configuration.KS_ALIAS)
        PersistentSelfSignedCertKey(signer, Configuration.KS_ALIAS, dataStoreService)
    }.getOrElse { FallBackKeyMaterial(it) }

    /**
     * Reads the public key currently held under [Configuration.KS_ALIAS] directly from the platform
     * key store, bypassing any cached [KeyMaterial]/[Signer]. Returns null when no usable key exists.
     *
     * Used to detect when an in-memory key material has gone stale relative to the hardware key
     * (e.g. after the key was invalidated and re-created): signing an OID4VCI credential-request proof
     * with a stale key surfaces only as an opaque issuer-side rejection in
     * [at.asitplus.wallet.lib.oidvci.ProofValidator.validateJwtProof].
     */
    open suspend fun liveSigningPublicKey(): CryptoPublicKey? =
        holderKeyFactory.load(Configuration.KS_ALIAS)?.publicKey

    open suspend fun testSigner(): Boolean = withContext(dispatcher) {
        catchingUnwrapped {
            PlatformSigningProvider.let { provider ->
                // Best effort, there may be no key to delete yet
                val _ = provider.deleteSigningKey(Configuration.KS_CAPABILITY_ALIAS)
                provider.createSigningKey(Configuration.KS_CAPABILITY_ALIAS)
            }
        }.isSuccess
    }

    suspend fun testAttestation() = withContext(dispatcher) {
        catchingUnwrapped {
            // Best effort, there may be no key to delete yet
            val _ = PlatformSigningProvider.deleteSigningKey(Configuration.KS_CAPABILITY_ALIAS)
            PlatformSigningProvider.createSigningKey(Configuration.KS_CAPABILITY_ALIAS) {
                ec {}
                hardware {
                    attestation {
                        this.challenge = "CHALLENGE".encodeToByteArray()
                    }
                }
            }.getOrThrow()
        }.isSuccess
    }

    companion object {
        @Throws(AppResetRequiredException::class)
        fun checkKeyMaterialValid() {
            PlatformSigningProvider.let { provider ->
                runBlocking {
                    Configuration.KS_ALIASES_OLDER_THAN_THE_HILLS.forEach { alias ->
                        provider.getSignerForKey(alias).onSuccess {
                            throw AppResetRequiredException
                        }
                    }
                }
            }

        }

        /**
         * Deletes the holder key, the keys of older versions, the self-signed certificate of the holder key, and the
         * holder key registry.
         */
        fun clearKeyMaterial(dataStoreService: DataStoreService) {
            PlatformSigningProvider.let { provider ->
                runBlocking {
                    (Configuration.KS_ALIASES_OLDER_THAN_THE_HILLS + Configuration.KS_ALIAS).forEach { alias ->
                        provider.getSignerForKey(alias).onSuccess {
                            provider.deleteSigningKey(alias)
                        }
                    }
                    dataStoreService.deletePreference(LEGACY_CERT_STORAGE_KEY)
                    dataStoreService.deletePreference(certificateStorageKey(Configuration.KS_ALIAS))
                    dataStoreService.deletePreference(Configuration.DATASTORE_KEY_HOLDER_KEYS)
                }
            }
        }
    }

    //TMP for iOS
    @Deprecated("Use HolderKeyManager.legacyKey()")
    @Suppress("DEPRECATION")
    @Throws(Throwable::class)
    fun getSignerBlocking() = runBlocking { getSigner() }
}

/**
 * Fallback class if KeyMaterial initialization throws on startup.
 * Allows to handle errors with the default navigation procedure.
 */
class FallBackKeyMaterial(
    val reason: Throwable,
    override val signatureAlgorithm: SignatureAlgorithm = SignatureAlgorithm.ECDSAwithSHA256,
    override val publicKey: CryptoPublicKey = EphemeralKeyWithoutCert().publicKey,
    override val identifier: String = ""
) : KeyMaterial {
    @SecretExposure
    override fun exportPrivateKey(): KmmResult<CryptoPrivateKey.WithPublicKey<*>> {
        throw NotImplementedError()
    }

    override suspend fun sign(data: SignatureInput): SignatureResult<*> {
        throw NotImplementedError()
    }

    override fun getUnderLyingSigner(): Signer {
        throw NotImplementedError()
    }

    override suspend fun getCertificate(): X509Certificate? {
        throw NotImplementedError()
    }

}
