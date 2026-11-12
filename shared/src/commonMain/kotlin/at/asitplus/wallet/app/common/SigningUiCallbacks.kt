package at.asitplus.wallet.app.common

/** The UI callbacks for signing with a holder key, shared by every [WalletKeyMaterial] of the session. */
class SigningUiCallbacks {
    /** Called when the user didn't unlock the key, e.g. cancelled the biometric prompt. */
    var onUnauthenticated: (() -> Unit)? = null
}
