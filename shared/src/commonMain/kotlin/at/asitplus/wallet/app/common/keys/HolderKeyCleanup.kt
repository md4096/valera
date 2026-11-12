package at.asitplus.wallet.app.common.keys

import at.asitplus.catchingUnwrapped
import at.asitplus.wallet.app.common.validation.PendingCredentialReview
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import data.storage.PersistentSubjectCredentialStore
import data.storage.StoreContainer
import data.storage.WalletSubjectCredentialStore
import io.github.aakira.napier.Napier
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours

/**
 * Deletes holder keys no credential is bound to, at startup and whenever the stored credentials change; main app session
 * only, see [HolderKeyManager]. Keeps keys younger than [gracePeriod] and keys of credentials under review in any
 * session ([pendingCredentialReview], [holderKeyHolds]).
 *
 * Reads holds, then reviews, then stored credentials, so every credential is seen at least once. The hot
 * [subjectCredentialStore] only rules out that anything can be deleted; before deleting, the credentials are read from
 * [persistentSubjectCredentialStore]. Deletes nothing while a credential is bound to a key that can't be read, e.g. by
 * `kid`, as any unused key could be that one.
 */
class HolderKeyCleanup(
    private val holderKeyManager: HolderKeyManager,
    private val subjectCredentialStore: WalletSubjectCredentialStore,
    private val persistentSubjectCredentialStore: PersistentSubjectCredentialStore,
    private val pendingCredentialReview: PendingCredentialReview,
    private val holderKeyHolds: HolderKeyHolds,
    private val clock: Clock = Clock.System,
    private val gracePeriod: Duration = DEFAULT_GRACE_PERIOD,
) {
    private val mutex = Mutex()

    /** Runs [collect] now and on every change of the stored credentials, until [scope] is cancelled. */
    fun start(scope: CoroutineScope): Job = subjectCredentialStore.observeStoreContainer()
        .onEach { collect(hot = it) }
        .launchIn(scope)

    /**
     * Deletes the unused keys and returns how many aliases were cleaned up. Deletes nothing if any credential
     * can't be read, as a key in use could then look unused.
     *
     * With the [hot] container of [subjectCredentialStore], nothing more is read if it leaves no key to delete, so the
     * stored credentials are decoded a second time only when a key may be deleted, e.g. after a credential was removed.
     */
    suspend fun collect(hot: StoreContainer? = null): Int = mutex.withLock {
        catchingUnwrapped {
            val olderThan = clock.now() - gracePeriod
            val mayDelete = hot == null || referencedHolderKeys { hot }
                ?.let { holderKeyManager.hasCollectable(it, olderThan) } == true
            if (!mayDelete) 0
            else referencedHolderKeys { persistentSubjectCredentialStore.observeStoreContainer().first() }
                ?.let { holderKeyManager.collectUnreferenced(it, olderThan) } ?: 0
        }.onFailure { Napier.w("HolderKeyCleanup: Collecting unused holder keys failed", it) }.getOrDefault(0)
    }

    /**
     * The JWK thumbprints of the keys credentials are bound to, with the stored credentials of [stored], `null` if they
     * can't all be read.
     */
    private suspend fun referencedHolderKeys(stored: suspend () -> StoreContainer): Set<String>? {
        // Holds, reviews, then stored credentials: see the class
        val held = holderKeyHolds.held()
        val underReview = pendingCredentialReview.entries.value.map {
            SubjectCredentialStore.StoreEntry.fromPreparedCredential(it.prepared).getOrNull() ?: run {
                Napier.w("HolderKeyCleanup: A credential under review can't be read, no holder key is deleted")
                return null
            }
        }
        val container = stored()
        if (container.unreadable) {
            Napier.w("HolderKeyCleanup: The stored credentials can't be decoded, no holder key is deleted")
            return null
        }
        val credentials = container.credentials.map { it.second } + underReview
        if (credentials.any { it.hasUnreadableHolderKey() }) {
            Napier.w("HolderKeyCleanup: A credential names a holder key that can't be read, no holder key is deleted")
            return null
        }
        return credentials.mapNotNullTo(mutableSetOf()) { it.holderKey()?.holderKeyThumbprint } + held
    }

    companion object {
        /** Longer than an issuance takes from creating its key to storing the credential. */
        val DEFAULT_GRACE_PERIOD = 1.hours
    }
}

/**
 * Whether [this] is holder-bound, but [SubjectCredentialStore.StoreEntry.holderKey] can't read the key, e.g. a `cnf`
 * with only a `kid`, by VC-K's definition ([SubjectCredentialStore.StoreEntry.isHolderBound]).
 */
internal fun SubjectCredentialStore.StoreEntry.hasUnreadableHolderKey(): Boolean = isHolderBound() && holderKey() == null
