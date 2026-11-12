package at.asitplus.wallet.app.common.keys

import at.asitplus.wallet.app.common.Configuration
import data.storage.DataStoreService
import kotlin.time.Instant

/**
 * Aliases of holder keys that may exist but aren't registered, with the time they were recorded. The keystore can't
 * list its keys, so [HolderKeyManager] records an alias before creating its key, and removes the record once the key
 * is registered or deleted; a record left behind lets cleanup and reset find the key.
 */
internal class PendingHolderKeys(
    dataStoreService: DataStoreService,
    preferenceKey: String = Configuration.DATASTORE_KEY_HOLDER_KEY_PENDING,
) {
    private val records = PersistentTimestamps(dataStoreService, preferenceKey)

    suspend fun add(aliases: Collection<String>, recordedAt: Instant) {
        if (aliases.isEmpty()) return
        records.update { pending -> pending + aliases.associateWith { recordedAt.epochSeconds } }
    }

    suspend fun remove(aliases: Collection<String>) {
        if (aliases.isEmpty()) return
        records.update { pending -> pending - aliases.toSet() }
    }

    /** The recorded aliases with the time they were recorded. Fails for content that can't be decoded. */
    suspend fun all(): Map<String, Instant> = records.read().mapValues { Instant.fromEpochSeconds(it.value) }
}
