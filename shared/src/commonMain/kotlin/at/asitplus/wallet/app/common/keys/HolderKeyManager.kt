package at.asitplus.wallet.app.common.keys

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.app.common.Configuration
import at.asitplus.wallet.app.common.SigningUiCallbacks
import at.asitplus.wallet.app.common.WalletKeyMaterial
import at.asitplus.wallet.lib.agent.KeyMaterial
import data.storage.DataStoreService
import io.github.aakira.napier.Napier
import kotlinx.coroutines.flow.first
import kotlin.time.Clock

/**
 * The holder keys of the wallet: allocates them for issuance and finds the key a credential is bound to. The rest of
 * the app depends on this instead of on a single key.
 *
 * Only the main app allocates keys and writes the registry; the iOS extension only resolves keys.
 */
class HolderKeyManager(
    private val registry: HolderKeyRegistry,
    private val factory: HolderKeyFactory,
    private val signingUi: SigningUiCallbacks,
    private val dataStoreService: DataStoreService,
    private val clock: Clock = Clock.System,
) {

    /**
     * The key material of [boundKey]. Fails if the key is gone or its alias now holds another key. Falls back to the
     * legacy key, for a process that hasn't migrated it yet.
     */
    suspend fun resolve(boundKey: CryptoPublicKey): KmmResult<KeyMaterial> = catching {
        val thumbprint = boundKey.holderKeyThumbprint
        val handle = registry.get(thumbprint)
        val alias = when (handle) {
            is HolderKeyHandle.Platform -> handle.alias
            null -> Configuration.KS_ALIAS
        }
        val signer = factory.load(alias)
        // Without the key: it ends up as the cause in VC-K's validation reports
        if (signer?.publicKey?.holderKeyThumbprint != thumbprint) throw HolderKeyNotFoundException(
            when {
                handle == null -> "Unknown holder key"
                signer == null -> "No holder key under alias $alias"
                else -> "The holder key under alias $alias has been replaced"
            }
        )
        keyMaterial(signer, alias)
    }

    /** The legacy holder key, created if there is none, and registered. */
    suspend fun legacyKey(): WalletKeyMaterial {
        val signer = factory.load(Configuration.KS_ALIAS) ?: factory.create(Configuration.KS_ALIAS)
        register(Configuration.KS_ALIAS, signer)
        return keyMaterial(signer, Configuration.KS_ALIAS)
    }

    /** Registers the legacy key, if any, and moves its certificate to its alias. Idempotent. */
    suspend fun migrateLegacyKey() {
        factory.load(Configuration.KS_ALIAS)?.let { register(Configuration.KS_ALIAS, it) }
        dataStoreService.getPreference(LEGACY_CERT_STORAGE_KEY).first()?.let { legacy ->
            val target = certificateStorageKey(Configuration.KS_ALIAS)
            dataStoreService.updatePreference(target) { it ?: legacy }
            dataStoreService.deletePreference(LEGACY_CERT_STORAGE_KEY)
            Napier.i("HolderKeyManager: Moved the certificate of the legacy key to $target")
        }
    }

    /** Whether no keys of older app versions are present; otherwise the app has to be reset. */
    suspend fun isValid(): Boolean =
        Configuration.KS_ALIASES_OLDER_THAN_THE_HILLS.none { factory.load(it) != null }

    /**
     * Deletes all keys and their certificates as far as it can, so that a reset always finishes. A key that can't be
     * deleted stays registered, so a later reset deletes it. If the registry can't be read, deletes the keys under the
     * fixed aliases and clears the registry.
     */
    suspend fun deleteAll() {
        val registered = catchingUnwrapped { registry.all() }
            .onFailure { Napier.w("HolderKeyManager: The registry can't be read, deleting the fixed aliases only", it) }
            .getOrNull()
        val registeredAliases = registered.orEmpty().associate {
            when (it) {
                is HolderKeyHandle.Platform -> it.thumbprint to it.alias
            }
        }
        val aliases = registeredAliases.values + Configuration.KS_ALIASES_OLDER_THAN_THE_HILLS + Configuration.KS_ALIAS
        val failed = aliases.distinct().filterNot { alias ->
            catchingUnwrapped {
                factory.delete(alias)
                dataStoreService.deletePreference(certificateStorageKey(alias))
            }.onFailure { Napier.w("HolderKeyManager: Deleting the holder key under alias $alias failed", it) }
                .isSuccess
        }.toSet()
        dataStoreService.deletePreference(LEGACY_CERT_STORAGE_KEY)
        if (registered == null) {
            registry.clear()
        } else {
            registeredAliases.filterValues { it !in failed }.keys.forEach { registry.remove(it) }
        }
        if (failed.isEmpty()) Napier.i("HolderKeyManager: Deleted all holder keys")
        else Napier.w("HolderKeyManager: Deleted all holder keys but those under $failed")
    }

    private suspend fun register(alias: String, signer: Signer) {
        val thumbprint = signer.publicKey.holderKeyThumbprint
        if (registry.get(thumbprint) == null) {
            registry.put(HolderKeyHandle.Platform(alias, thumbprint, clock.now()))
            Napier.i("HolderKeyManager: Registered holder key $thumbprint under alias $alias")
        }
    }

    private fun keyMaterial(signer: Signer, alias: String): WalletKeyMaterial =
        WalletKeyMaterial(PersistentSelfSignedCertKey(signer, alias, dataStoreService), signingUi)
}

/** No usable holder key for a bound key. */
class HolderKeyNotFoundException(message: String) : IllegalStateException(message)

/** The JWK thumbprint, which identifies a key in [HolderKeyRegistry]. */
internal val CryptoPublicKey.holderKeyThumbprint: String get() = toJsonWebKey().jwkThumbprint
