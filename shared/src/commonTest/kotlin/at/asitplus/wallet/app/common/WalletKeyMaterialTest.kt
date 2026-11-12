@file:OptIn(SecretExposure::class)

package at.asitplus.wallet.app.common

import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.UnlockFailed
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class WalletKeyMaterialTest {

    @Test
    fun unlockFailureCallsTheCurrentCallback() = runTest {
        val callbacks = SigningUiCallbacks()
        val keyMaterial = walletKeyMaterial(callbacks) { SignatureResult.Failure(UnlockFailed()) }
        var calls = 0
        callbacks.onUnauthenticated = { calls++ }

        keyMaterial.sign(byteArrayOf(1))

        assertEquals(1, calls)
    }

    @Test
    fun successAndErrorDoNotCallTheCallback() = runTest {
        val callbacks = SigningUiCallbacks()
        var calls = 0
        callbacks.onUnauthenticated = { calls++ }

        walletKeyMaterial(callbacks) { it }.sign(byteArrayOf(1))
        walletKeyMaterial(callbacks) { SignatureResult.Error(IllegalStateException()) }.sign(byteArrayOf(1))

        assertEquals(0, calls)
    }

    @Test
    fun keyMaterialsOfASessionShareTheCallbacks() = runTest {
        val callbacks = SigningUiCallbacks()
        val first = walletKeyMaterial(callbacks) { SignatureResult.Failure(UnlockFailed()) }
        val second = walletKeyMaterial(callbacks) { SignatureResult.Failure(UnlockFailed()) }
        var calls = 0
        callbacks.onUnauthenticated = { calls++ }

        first.sign(byteArrayOf(1))
        second.sign(byteArrayOf(1))

        assertEquals(2, calls)
    }

    /**
     * Builds a [WalletKeyMaterial] over an ephemeral key whose signer maps the real signature result with [result].
     */
    private fun walletKeyMaterial(
        callbacks: SigningUiCallbacks,
        result: (SignatureResult<*>) -> SignatureResult<*>,
    ): WalletKeyMaterial {
        val key = EphemeralKeyWithoutCert()
        val realSigner = key.getUnderLyingSigner()
        val signer = object : Signer by realSigner {
            // Delegation forwards the overloads with a default body as well, so override each one in use
            override suspend fun sign(data: SignatureInput) = result(realSigner.sign(data))
            override suspend fun sign(data: ByteArray) = result(realSigner.sign(data))
        }
        val keyMaterial = object : KeyMaterial by key {
            override fun getUnderLyingSigner(): Signer = signer
        }
        return WalletKeyMaterial(keyMaterial, callbacks)
    }
}
