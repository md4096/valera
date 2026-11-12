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
import at.asitplus.wallet.lib.agent.HolderKeyResolver
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.oidvci.ProofKeyRequest
import at.asitplus.wallet.lib.oidvci.ProofKeySupplier
import data.storage.DataStoreService
import io.github.aakira.napier.Napier
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * The holder keys of the wallet: VC-K's [ProofKeySupplier], creating a new key for every credential request, and its
 * [HolderKeyResolver], finding the key a credential is bound to. Only the main app creates, deletes and registers keys;
 * the iOS extension only resolves them ([resolveOnly]).
 */
class HolderKeyManager(
    private val registry: HolderKeyRegistry,
    private val factory: HolderKeyFactory,
    private val signingUi: SigningUiCallbacks,
    private val dataStoreService: DataStoreService,
    private val clock: Clock = Clock.System,
    /** Only resolve keys, as in the iOS extension. */
    private val resolveOnly: Boolean = false,
) : HolderKeyResolver, ProofKeySupplier {
    /**
     * Key material by JWK thumbprint, so a key keeps its certificate between signatures. [resolve] still checks the
     * keystore every time, as the other process may have deleted the key.
     */
    private val keyMaterials = mutableMapOf<String, WalletKeyMaterial>()
    private val keyMaterialsMutex = Mutex()

    /** Aliases that may hold a key not registered yet, see [newKey]. */
    private val pendingKeys = PendingHolderKeys(dataStoreService)

    /**
     * A new key for a credential to be issued (ARF ISSU_12b). A key is never reused, as it may be in only one key
     * attestation (TS3, 2.2.2.1).
     */
    internal suspend fun allocateForIssuance(): KeyMaterial {
        requireWritable()
        return newKey()
    }

    /** A new key for the credential request of [request], see [allocateForIssuance]. */
    override suspend fun key(request: ProofKeyRequest): KmmResult<KeyMaterial> =
        catching { allocateForIssuance() }

    /**
     * The key material of [boundKey]. Fails if the key is gone or its alias now holds another key. Falls back to the
     * legacy key, for a process that hasn't migrated it yet.
     */
    override suspend fun resolve(boundKey: CryptoPublicKey): KmmResult<KeyMaterial> = catching {
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
        keyMaterialsMutex.withLock { keyMaterials[thumbprint] } ?: keyMaterial(signer, alias)
    }

    /**
     * A new, registered key under `holder-<uuid>`. The alias is recorded in [pendingKeys] before the key is created, as
     * the keystore can't list its keys: a key that is never registered, e.g. as the process ends in between, is still
     * deleted by [collectUnreferenced] and [deleteAll]. If creating or registering fails, the key is deleted again.
     */
    @OptIn(ExperimentalUuidApi::class)
    internal suspend fun newKey(): WalletKeyMaterial {
        requireWritable()
        val alias = "$HOLDER_KEY_ALIAS_PREFIX${Uuid.random()}"
        pendingKeys.add(listOf(alias), clock.now())
        val created = catchingUnwrapped {
            val signer = factory.create(alias)
            register(alias, signer)
            keyMaterial(signer, alias)
        }.onFailure {
            // Also a key the keystore created before failing; if deleting fails, the record stays for a later attempt
            catchingUnwrapped {
                factory.delete(alias)
                pendingKeys.remove(listOf(alias))
            }.onFailure { Napier.w("HolderKeyManager: Deleting the unregistered key under alias $alias failed", it) }
        }.getOrThrow()
        // Registered: a record left behind if this fails is dropped by collectUnreferenced
        catchingUnwrapped { pendingKeys.remove(listOf(alias)) }
            .onFailure { Napier.w("HolderKeyManager: Removing the record of alias $alias failed", it) }
        return created
    }

    /** The legacy holder key, created if there is none, and registered. Fails if it can't be created. */
    suspend fun legacyKey(): WalletKeyMaterial {
        val signer = factory.load(Configuration.KS_ALIAS)
            ?: if (resolveOnly) throw HolderKeyNotFoundException("No legacy holder key, and keys are only resolved here")
            else factory.create(Configuration.KS_ALIAS)
        if (!resolveOnly) register(Configuration.KS_ALIAS, signer)
        return keyMaterial(signer, Configuration.KS_ALIAS)
    }

    /** Registers the legacy key, if any, and moves its certificate to its alias. Idempotent. */
    suspend fun migrateLegacyKey() {
        requireWritable()
        factory.load(Configuration.KS_ALIAS)?.let { register(Configuration.KS_ALIAS, it) }
        dataStoreService.getPreference(LEGACY_CERT_STORAGE_KEY).first()?.let { legacy ->
            val target = certificateStorageKey(Configuration.KS_ALIAS)
            dataStoreService.updatePreference(target) { it ?: legacy }
            dataStoreService.deletePreference(LEGACY_CERT_STORAGE_KEY)
            Napier.i("HolderKeyManager: Moved the certificate of the legacy key to $target")
        }
    }

    /**
     * Deletes the keys, with their certificates, that aren't in [referenced] and were registered before [olderThan],
     * including the legacy key, and the keys recorded in [pendingKeys] before [olderThan] that were never registered.
     * Returns how many aliases were cleaned up. See [HolderKeyCleanup].
     */
    suspend fun collectUnreferenced(referenced: Set<String>, olderThan: Instant): Int {
        requireWritable()
        val registered = registry.all()
        return deleteUnreferenced(registered, referenced, olderThan) + deleteUnregistered(registered, olderThan)
    }

    /**
     * Whether [collectUnreferenced] would delete a key or drop a record with the same arguments, without deleting
     * anything, so [HolderKeyCleanup] can skip reading the stored credentials again.
     */
    suspend fun hasCollectable(referenced: Set<String>, olderThan: Instant): Boolean {
        if (registry.all().any { it.isCollectable(referenced, olderThan) }) return true
        // Records that can't be read are dropped by the next record written, see PendingHolderKeys
        val pending = catchingUnwrapped { pendingKeys.all() }.getOrElse { return false }
        return pending.values.any { it < olderThan }
    }

    private fun HolderKeyHandle.isCollectable(referenced: Set<String>, olderThan: Instant) =
        thumbprint !in referenced && createdAt < olderThan

    private suspend fun deleteUnreferenced(
        registered: List<HolderKeyHandle>,
        referenced: Set<String>,
        olderThan: Instant,
    ): Int = registered
        .filter { it.isCollectable(referenced, olderThan) }
        .onEach { handle ->
            when (handle) {
                is HolderKeyHandle.Platform -> {
                    factory.delete(handle.alias)
                    dataStoreService.deletePreference(certificateStorageKey(handle.alias))
                }
            }
            registry.remove(handle.thumbprint)
            keyMaterialsMutex.withLock { keyMaterials -= handle.thumbprint }
            Napier.i("HolderKeyManager: Deleted unused holder key ${handle.thumbprint}")
        }.size

    /**
     * Deletes the keys under the aliases recorded in [pendingKeys] before [olderThan] that aren't [registered], and
     * drops the records of registered ones. Such a key never got a certificate, nor was it in a proof. A younger record
     * may be a key another session is creating right now. Returns how many unregistered aliases were cleaned up.
     */
    private suspend fun deleteUnregistered(registered: List<HolderKeyHandle>, olderThan: Instant): Int {
        val registeredAliases = registered.aliases()
        val pending = catchingUnwrapped { pendingKeys.all() }.getOrElse {
            // The next record written drops them, see PendingHolderKeys
            Napier.w("HolderKeyManager: The records of unregistered keys can't be read", it)
            return 0
        }
        return pending.filterValues { it < olderThan }.keys.count { alias ->
            val unregistered = alias !in registeredAliases
            if (unregistered) factory.delete(alias)
            pendingKeys.remove(listOf(alias))
            if (unregistered) Napier.i("HolderKeyManager: Cleaned up the unregistered holder key alias $alias")
            unregistered
        }
    }

    /** Whether no keys of older app versions are present; otherwise the app has to be reset. */
    suspend fun isValid(): Boolean =
        Configuration.KS_ALIASES_OLDER_THAN_THE_HILLS.none { factory.load(it) != null }

    /**
     * Deletes all keys and their certificates as far as it can, so that a reset always finishes: the registered ones,
     * the ones under the fixed aliases, and the ones recorded in [pendingKeys]. A key that can't be deleted stays
     * registered or recorded, so a later reset or [collectUnreferenced] deletes it. If the registry can't be read,
     * deletes the keys under the fixed and recorded aliases only and clears it.
     *
     * Deletes nothing in a process that only resolves keys ([resolveOnly]): the main app's [HolderKeyCleanup] deletes
     * them once no credential is bound to them.
     */
    suspend fun deleteAll() {
        if (resolveOnly) {
            Napier.i("HolderKeyManager: Holder keys are only resolved in this process, the main app deletes them")
            return
        }
        val registered = catchingUnwrapped { registry.all() }
            .onFailure { Napier.w("HolderKeyManager: The registry can't be read, deleting known aliases only", it) }
            .getOrNull()
        val registeredAliases = registered.orEmpty().associate {
            when (it) {
                is HolderKeyHandle.Platform -> it.thumbprint to it.alias
            }
        }
        val pendingAliases = catchingUnwrapped { pendingKeys.all().keys }
            .onFailure { Napier.w("HolderKeyManager: The records of unregistered keys can't be read", it) }
            .getOrDefault(emptySet())
        val aliases = registeredAliases.values + pendingAliases +
            Configuration.KS_ALIASES_OLDER_THAN_THE_HILLS + Configuration.KS_ALIAS
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
        catchingUnwrapped { pendingKeys.remove(pendingAliases - failed) }
            .onFailure { Napier.w("HolderKeyManager: Removing the records of deleted keys failed", it) }
        keyMaterialsMutex.withLock { keyMaterials.clear() }
        if (failed.isEmpty()) Napier.i("HolderKeyManager: Deleted all holder keys")
        else Napier.w("HolderKeyManager: Deleted all holder keys but those under $failed")
    }

    private fun requireWritable() = check(!resolveOnly) { "Holder keys are only resolved in this process" }

    private suspend fun register(alias: String, signer: Signer) {
        val thumbprint = signer.publicKey.holderKeyThumbprint
        if (registry.get(thumbprint) == null) {
            registry.put(HolderKeyHandle.Platform(alias, thumbprint, clock.now()))
            Napier.i("HolderKeyManager: Registered holder key $thumbprint under alias $alias")
        }
    }

    private fun List<HolderKeyHandle>.aliases(): Set<String> = mapTo(mutableSetOf()) {
        when (it) {
            is HolderKeyHandle.Platform -> it.alias
        }
    }

    private suspend fun keyMaterial(signer: Signer, alias: String): WalletKeyMaterial =
        WalletKeyMaterial(PersistentSelfSignedCertKey(signer, alias, dataStoreService), signingUi).also { created ->
            keyMaterialsMutex.withLock { keyMaterials[signer.publicKey.holderKeyThumbprint] = created }
        }
}

/** No usable holder key for a bound key. */
class HolderKeyNotFoundException(message: String) : IllegalStateException(message)

internal const val HOLDER_KEY_ALIAS_PREFIX = "holder-"

/** The JWK thumbprint, which identifies a key in [HolderKeyRegistry]. */
internal val CryptoPublicKey.holderKeyThumbprint: String get() = toJsonWebKey().jwkThumbprint
