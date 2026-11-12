package at.asitplus.wallet.app.common.keys

import at.asitplus.io.MultiBase
import at.asitplus.io.multibaseDecode
import at.asitplus.io.multibaseEncode
import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.lib.agent.KeyWithSelfSignedCert
import data.storage.DataStoreService
import io.github.aakira.napier.Napier
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Where the certificate of the single holder key was stored before there was one per alias. */
internal const val LEGACY_CERT_STORAGE_KEY = "MB64_CERT_SELF_SIGNED"

/** Where the certificate of the key under [alias] is stored. */
internal fun certificateStorageKey(alias: String) = "$LEGACY_CERT_STORAGE_KEY:$alias"

/** Key under [alias] with a persisted self-signed certificate, created again if it doesn't match the key. */
class PersistentSelfSignedCertKey(
    private val signer: Signer,
    alias: String,
    private val dataStoreService: DataStoreService,
    lifetimeInSeconds: Long = 30,
) : KeyWithSelfSignedCert(listOf(), signer.publicKey.didEncoded, lifetimeInSeconds), Signer by signer {
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
