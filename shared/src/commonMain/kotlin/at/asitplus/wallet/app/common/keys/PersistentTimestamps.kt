package at.asitplus.wallet.app.common.keys

import at.asitplus.catchingUnwrapped
import data.storage.DataStoreService
import io.github.aakira.napier.Napier
import kotlinx.coroutines.flow.first
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

/**
 * Names, each with an epoch second, in one preference, so every write is one atomic edit, also across the iOS
 * processes. Content that can't be decoded fails [read] and is dropped by the next [update].
 */
internal class PersistentTimestamps(
    private val dataStoreService: DataStoreService,
    private val preferenceKey: String,
) {
    suspend fun read(): Map<String, Long> = decode(dataStoreService.getPreference(preferenceKey).first())

    /** Applies [transform] in one atomic edit. */
    suspend fun update(transform: (Map<String, Long>) -> Map<String, Long>) {
        dataStoreService.updatePreference(preferenceKey) { current ->
            val entries = catchingUnwrapped { decode(current) }.getOrElse {
                Napier.w("PersistentTimestamps: Dropping $preferenceKey, which can't be decoded", it)
                emptyMap()
            }
            transform(entries).takeIf { it.isNotEmpty() }?.let { json.encodeToString(serializer, it) }
        }
    }

    suspend fun clear() = dataStoreService.deletePreference(preferenceKey)

    private fun decode(value: String?): Map<String, Long> =
        value?.let { json.decodeFromString(serializer, it) } ?: emptyMap()

    private companion object {
        val json = Json { ignoreUnknownKeys = true }
        val serializer = MapSerializer(String.serializer(), Long.serializer())
    }
}
