package at.asitplus.wallet.app.common

import AppResetRequiredException
import at.asitplus.KmmResult
import at.asitplus.catchingUnwrapped
import at.asitplus.io.MultiBase
import at.asitplus.io.multibaseDecode
import at.asitplus.io.multibaseEncode
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.KeyWithSelfSignedCert
import at.asitplus.wallet.app.common.keys.HolderKeyFactory
import at.asitplus.wallet.app.common.keys.PlatformHolderKeyFactory
import data.storage.DataStoreService
import io.github.aakira.napier.Napier
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext


private const val CERT_STORAGE_KEY = "MB64_CERT_SELF_SIGNED"

/** Preference key of the self-signed certificate of the holder key under [alias]. */
internal fun certificateStorageKey(alias: String) = "$CERT_STORAGE_KEY:$alias"

open class KeystoreService(
    private val dataStoreService: DataStoreService,
    /** Runs the keystore calls of the session one after the other, also those of [holderKeyFactory]. */
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(1),
    private val holderKeyFactory: HolderKeyFactory = PlatformHolderKeyFactory(dispatcher),
) {

    @Throws(Throwable::class)
    open suspend fun getSigner(): KeyMaterial = catchingUnwrapped { initSigner() }
        .getOrElse { FallBackKeyMaterial(it) }

    @Throws(Throwable::class)
    private suspend fun initSigner(alias: String): KeyWithSelfSignedCert {
        val signer = holderKeyFactory.load(alias) ?: holderKeyFactory.create(alias)
        return KeyWithPersistentSelfSignedCert(signer, alias, signer.publicKey.didEncoded, 30)
    }

    @Throws(Throwable::class)
    private suspend fun initSigner(): KeyWithSelfSignedCert = initSigner(Configuration.KS_ALIAS)

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

    inner class KeyWithPersistentSelfSignedCert(
        private val signer: Signer,
        alias: String,
        customKeyId: String,
        lifetimeInSeconds: Long
    ) : KeyWithSelfSignedCert(listOf(), customKeyId, lifetimeInSeconds), Signer by signer {
        override fun getUnderLyingSigner() = signer

        private val certificateKey = certificateStorageKey(alias)
        private val crtMut = Mutex()
        private var _certificate: X509Certificate? = null
        override suspend fun getCertificate(): X509Certificate? {
            crtMut.withLock {
                _certificate?.also { return it }
                repeat(3) {
                    (X509Certificate.load()?.let {
                        if (it.decodedPublicKey.getOrNull()?.equalsCryptographically(signer.publicKey) == true)
                            return it
                        else {
                            Napier.d { "Pre-stored Certificate mismatch. deleting!" }
                            dataStoreService.deletePreference(certificateKey)
                            null
                        }
                    }) ?: super.getCertificate()?.let { it.store(); _certificate = it; return it }
                }
            }
            Napier.w { "Could not load or generate self-signed certificate!" }
            return _certificate
        }

        private suspend fun X509Certificate.Companion.load(): X509Certificate? =
            dataStoreService.getPreference(certificateKey).map { it?.multibaseDecode() }
                .map { it?.let { X509Certificate.decodeFromDer(it) } }
                .firstOrNull()
                .also { Napier.d { "Loaded certificate" + it?.encodeToTlv()?.prettyPrint() } }


        private suspend fun X509Certificate.store() {
            Napier.d { "Persistently storing certificate" }
            dataStoreService.setPreference(
                encodeToDer().multibaseEncode(MultiBase.Base.BASE64),
                certificateKey
            )
        }

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
         * Deletes the holder key, the keys of older versions, and the self-signed certificate of the holder key.
         */
        fun clearKeyMaterial(dataStoreService: DataStoreService) {
            PlatformSigningProvider.let { provider ->
                runBlocking {
                    (Configuration.KS_ALIASES_OLDER_THAN_THE_HILLS + Configuration.KS_ALIAS).forEach { alias ->
                        provider.getSignerForKey(alias).onSuccess {
                            provider.deleteSigningKey(alias)
                        }
                    }
                    dataStoreService.deletePreference(CERT_STORAGE_KEY)
                    dataStoreService.deletePreference(certificateStorageKey(Configuration.KS_ALIAS))
                }
            }
        }
    }

    //TMP for iOS
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
