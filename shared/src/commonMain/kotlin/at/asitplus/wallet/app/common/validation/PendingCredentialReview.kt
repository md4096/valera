package at.asitplus.wallet.app.common.validation

import at.asitplus.wallet.app.common.keys.HolderKeyHolds
import at.asitplus.wallet.app.common.keys.holderKeyThumbprint
import at.asitplus.wallet.lib.agent.PreparedCredentialStorage
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.CredentialScheme
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.getAndUpdate
import kotlinx.coroutines.flow.update

/**
 * Issued credentials that have been rejected under [ValidationPolicies.issuance] for reasons the user may tolerate,
 * e.g. an untrusted issuer or claims the issuer left out, which are kept in memory, never persisted, until the user
 * decides to store or discard them. Session-scoped, so that they do not outlive the session they have been issued in.
 * The credentials of an issuance are reviewed only once each of them has been validated, so that one failing its
 * integrity leaves none of the others in a later review, and replace those of an earlier review the user left
 * without deciding.
 *
 * Their keys are held in [holds] until they are stored or discarded, see [HolderKeyHolds].
 */
class PendingCredentialReview(private val holds: HolderKeyHolds) {
    /**
     * A [prepared] credential with its validation and renewal info, to store it after the user's consent, the [scheme]
     * the wallet requested it as, and the [outcome] of its validation to show.
     */
    data class Entry(
        val prepared: PreparedCredentialStorage,
        val scheme: CredentialScheme,
        val outcome: ValidationOutcomeUi,
    )

    private val _entries = MutableStateFlow<List<Entry>>(emptyList())
    val entries: StateFlow<List<Entry>> = _entries.asStateFlow()

    /**
     * Replaces every entry with [entries], i.e. the credentials of the latest issuance to review, holding their keys
     * before releasing those of the replaced ones.
     */
    suspend fun replace(entries: List<Entry>) {
        holds.hold(entries.holderKeyThumbprints())
        val replaced = _entries.getAndUpdate { entries.toList() }
        holds.release(replaced.holderKeyThumbprints() - entries.holderKeyThumbprints())
    }

    /**
     * Stores each entry with [store], then removes it and releases its key. If [store] fails, that entry and the
     * following ones stay under review, so a retry doesn't store any twice. Returns how many were stored.
     */
    suspend fun keep(store: suspend (Entry) -> Unit): Int {
        val entries = _entries.value
        entries.forEach { entry ->
            store(entry)
            _entries.update { current -> current - entry }
            holds.release(listOf(entry).holderKeyThumbprints())
        }
        return entries.size
    }

    /** Discards all entries and releases their keys. */
    suspend fun discard() {
        holds.release(_entries.getAndUpdate { emptyList() }.holderKeyThumbprints())
    }

    /** Drops all entries when the session closes; their holds expire on their own. */
    fun clear() = _entries.update { emptyList() }

    private fun List<Entry>.holderKeyThumbprints(): Set<String> = mapNotNullTo(mutableSetOf()) {
        SubjectCredentialStore.StoreEntry.fromPreparedCredential(it.prepared).getOrNull()?.holderKey()
            ?.holderKeyThumbprint
    }
}
