package at.asitplus.wallet.app.common.keys

import at.asitplus.wallet.app.common.Configuration
import data.storage.DataStoreService
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

/**
 * Persisted JWK thumbprints of keys whose credentials are under review, which [HolderKeyCleanup] must keep. Reviews
 * live in memory of their own session, so the main session's cleanup only sees other sessions' reviews through these.
 *
 * A hold ends when released, or after [duration], in case the process ends before its review does.
 */
class HolderKeyHolds(
    dataStoreService: DataStoreService,
    private val clock: Clock = Clock.System,
    private val duration: Duration = DEFAULT_DURATION,
    preferenceKey: String = Configuration.DATASTORE_KEY_HOLDER_KEY_HOLDS,
) {
    private val holds = PersistentTimestamps(dataStoreService, preferenceKey)

    suspend fun hold(thumbprints: Collection<String>) {
        if (thumbprints.isEmpty()) return
        val until = (clock.now() + duration).epochSeconds
        update { current -> current + thumbprints.associateWith { until } }
    }

    suspend fun release(thumbprints: Collection<String>) {
        if (thumbprints.isEmpty()) return
        update { current -> current - thumbprints.toSet() }
    }

    /** The keys held now. Fails for content that can't be decoded, so the cleanup deletes nothing. */
    suspend fun held(): Set<String> {
        val now = clock.now()
        return holds.read().filterValues { Instant.fromEpochSeconds(it) > now }.keys
    }

    /** Drops every hold, e.g. on reset. */
    suspend fun clear() = holds.clear()

    /** Applies [transform] in one atomic edit, dropping the expired holds. */
    private suspend fun update(transform: (Map<String, Long>) -> Map<String, Long>) {
        val now = clock.now().epochSeconds
        holds.update { current -> transform(current.filterValues { it > now }) }
    }

    companion object {
        /** Longer than any review, short enough that a lost one doesn't keep its keys for long. */
        val DEFAULT_DURATION = 24.hours
    }
}
