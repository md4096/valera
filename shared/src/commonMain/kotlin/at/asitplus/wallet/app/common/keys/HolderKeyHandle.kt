package at.asitplus.wallet.app.common.keys

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/** What [HolderKeyRegistry] persists per key. Sealed, so other kinds of keys can be added without a migration. */
@Serializable
sealed interface HolderKeyHandle {
    /** JWK thumbprint, the registry key. */
    val thumbprint: String

    /** When the key was registered. */
    val createdAt: Instant

    /** A key in the platform keystore. */
    @Serializable
    @SerialName("platform")
    data class Platform(
        /** Alias of the key in the platform keystore. */
        val alias: String,
        override val thumbprint: String,
        override val createdAt: Instant,
    ) : HolderKeyHandle
}
