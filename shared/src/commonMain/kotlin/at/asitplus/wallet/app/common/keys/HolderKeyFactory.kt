package at.asitplus.wallet.app.common.keys

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.supreme.dsl.PREFERRED
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.app.common.Configuration
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext

/** Creates, loads and deletes holder keys by alias; the only place that knows the keystore and the key profile. */
interface HolderKeyFactory {
    suspend fun create(alias: String): Signer

    /** `null` if there is no key under [alias]. */
    suspend fun load(alias: String): Signer?

    /** Deletes by [alias], also if its signer cannot be loaded; succeeds if the key is already absent. */
    suspend fun delete(alias: String)
}

/** [HolderKeyFactory] on the platform keystore: EC P-256 keys bound to biometry, in secure hardware if available. */
class PlatformHolderKeyFactory(
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(1),
) : HolderKeyFactory {

    override suspend fun create(alias: String): Signer = withContext(dispatcher) {
        PlatformSigningProvider.createSigningKey(alias = alias) {
            ec {
                curve = ECCurve.SECP_256_R_1
                purposes {
                    keyAgreement = true
                    signing = true
                }
            }
            hardware {
                backing = PREFERRED
                protection {
                    factors {
                        biometry = true
                    }
                    timeout = Configuration.BIOMETRIC_TIMEOUT
                }
            }
        }.getOrThrow()
    }

    override suspend fun load(alias: String): Signer? = withContext(dispatcher) {
        PlatformSigningProvider.getSignerForKey(alias).getOrNull()
    }

    override suspend fun delete(alias: String): Unit = withContext(dispatcher) {
        PlatformSigningProvider.deleteSigningKey(alias).getOrThrow()
    }
}
