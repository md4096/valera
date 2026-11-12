package at.asitplus.wallet.app.common.keys

import at.asitplus.wallet.app.common.Configuration
import data.storage.DataStoreService
import kotlinx.coroutines.flow.first
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

/** Persistent map from JWK thumbprint to [HolderKeyHandle]. Entries never expire. */
interface HolderKeyRegistry {
    /** Adds [handle], replacing an entry with the same thumbprint. */
    suspend fun put(handle: HolderKeyHandle)

    suspend fun get(thumbprint: String): HolderKeyHandle?

    suspend fun all(): List<HolderKeyHandle>

    suspend fun remove(thumbprint: String)

    suspend fun clear()
}

/**
 * [HolderKeyRegistry] in one preference, so every write is one atomic edit, also across the iOS processes. No cache.
 * Content that can't be decoded fails every call instead of being dropped, as reset needs the list of keys to delete.
 */
class PersistentHolderKeyRegistry(
    private val dataStoreService: DataStoreService,
    private val preferenceKey: String = Configuration.DATASTORE_KEY_HOLDER_KEYS,
) : HolderKeyRegistry {

    override suspend fun put(handle: HolderKeyHandle) = update { it + (handle.thumbprint to handle) }

    override suspend fun get(thumbprint: String): HolderKeyHandle? = read()[thumbprint]

    override suspend fun all(): List<HolderKeyHandle> = read().values.toList()

    override suspend fun remove(thumbprint: String) = update { it - thumbprint }

    override suspend fun clear() {
        dataStoreService.deletePreference(preferenceKey)
    }

    private suspend fun read(): Map<String, HolderKeyHandle> =
        decode(dataStoreService.getPreference(preferenceKey).first())

    private suspend fun update(transform: (Map<String, HolderKeyHandle>) -> Map<String, HolderKeyHandle>) {
        dataStoreService.updatePreference(preferenceKey) { current ->
            transform(decode(current)).takeIf { it.isNotEmpty() }?.let { json.encodeToString(serializer, it) }
        }
    }

    private fun decode(value: String?): Map<String, HolderKeyHandle> =
        value?.let { json.decodeFromString(serializer, it) } ?: emptyMap()

    private companion object {
        val json = Json { ignoreUnknownKeys = true }
        val serializer = MapSerializer(String.serializer(), HolderKeyHandle.serializer())
    }
}
