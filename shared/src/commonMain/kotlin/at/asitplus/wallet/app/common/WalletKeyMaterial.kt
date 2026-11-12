package at.asitplus.wallet.app.common

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.os.PlatformSigningProviderSigner
import at.asitplus.valera.resources.Res
import at.asitplus.valera.resources.biometric_authentication_prompt_title
import at.asitplus.wallet.lib.agent.KeyMaterial
import io.github.aakira.napier.Napier
import org.jetbrains.compose.resources.getString

open class WalletKeyMaterial(
    val keyMaterial: KeyMaterial,
    private val uiCallbacks: SigningUiCallbacks,
) : KeyMaterial by keyMaterial {

    init {
        // Napier.i won't print anything to logcat, because it's not initialized yet
        println("Using this WalletKeyMaterial: ${joseCompliantSerializer.encodeToString(keyMaterial.jsonWebKey)}")
    }

    override suspend fun sign(
        data: ByteArray
    ): SignatureResult<CryptoSignature.RawByteEncodable> = run {
        Napier.d("WalletKeyMaterial.sign using key ${keyMaterial.jsonWebKey.jwkThumbprint}")
        when (val signer = keyMaterial.getUnderLyingSigner()) {
            is PlatformSigningProviderSigner<*, *> -> {
                val promptTitle = getString(Res.string.biometric_authentication_prompt_title)
                signer.sign(data) {
                    unlockPrompt {
                        message = promptTitle
                    }
                }
            }

            else -> signer.sign(data)
        }.also {
            if (it is SignatureResult.Failure) uiCallbacks.onUnauthenticated?.invoke()
        }
    }
}
