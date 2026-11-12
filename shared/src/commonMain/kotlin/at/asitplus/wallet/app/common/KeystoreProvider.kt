package at.asitplus.wallet.app.common

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.wallet.app.common.keys.HolderKeyFactory
import at.asitplus.wallet.app.common.keys.PlatformHolderKeyFactory
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext

/** The platform keystore: the [holderKeyFactory] and the checks of its capabilities. */
open class KeystoreService(
    /** Runs the keystore calls of the session one after the other, also those of [holderKeyFactory]. */
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(1),
    /** Tests replace it with one that doesn't need the platform keystore. */
    val holderKeyFactory: HolderKeyFactory = PlatformHolderKeyFactory(dispatcher),
) {

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
}
