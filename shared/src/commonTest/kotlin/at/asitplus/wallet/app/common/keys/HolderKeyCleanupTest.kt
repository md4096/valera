package at.asitplus.wallet.app.common.keys

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.app.common.Configuration
import at.asitplus.wallet.app.common.SigningUiCallbacks
import at.asitplus.wallet.app.common.validation.PendingCredentialReview
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import data.storage.DummyDataStoreService
import data.storage.PersistentSubjectCredentialStore
import data.storage.StoreContainer
import data.storage.WalletSubjectCredentialStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

class HolderKeyCleanupTest {
    private val now = Clock.System.now()

    /** [hotStore] wraps [store] as the session's hot store; by default it is [store], which never lags. */
    private class Fixture(
        now: Instant,
        hotStore: ((WalletSubjectCredentialStore) -> WalletSubjectCredentialStore)? = null,
    ) {
        val dataStore = DummyDataStoreService()
        val registry = PersistentHolderKeyRegistry(dataStore)
        val factory = InMemoryHolderKeyFactory()
        val manager = HolderKeyManager(registry, factory, SigningUiCallbacks(), dataStore)
        val store = PersistentSubjectCredentialStore(dataStore)
        val holds = HolderKeyHolds(dataStore, clock = fixedClock(now))
        val cleanup = HolderKeyCleanup(
            holderKeyManager = manager,
            subjectCredentialStore = hotStore?.invoke(store) ?: store,
            persistentSubjectCredentialStore = store,
            pendingCredentialReview = PendingCredentialReview(holds),
            holderKeyHolds = holds,
            clock = object : Clock {
                override fun now() = now
            },
            gracePeriod = 1.hours,
        )

        /** A key under [alias], registered at [createdAt], with a certificate. */
        suspend fun key(alias: String, createdAt: Instant): CryptoPublicKey {
            val key = factory.create(alias).publicKey
            registry.put(HolderKeyHandle.Platform(alias, key.holderKeyThumbprint, createdAt))
            dataStore.setPreference("certificate", certificateStorageKey(alias))
            return key
        }

        /** Stores an SD-JWT VC bound to [key]; its content is irrelevant for the cleanup. */
        suspend fun storeCredentialBoundTo(key: CryptoPublicKey) = store.storeCredential(
            SubjectCredentialStore.StoreEntry.SdJwt(
                vcSerialized = "",
                sdJwt = VerifiableCredentialSdJwt(
                    verifiableCredentialType = "urn:example",
                    confirmationClaim = ConfirmationClaim(jsonWebKey = key.toJsonWebKey()),
                ),
                disclosures = emptyMap(),
                schemeIdentifier = "urn:example",
            )
        ).getOrThrow()

        suspend fun certificate(alias: String) = dataStore.getPreference(certificateStorageKey(alias)).first()
    }

    @Test
    fun deletesOnlyOldKeysNoCredentialIsBoundTo() = runTest {
        val fixture = Fixture(now)
        val bound = fixture.key("bound", now - 2.hours)
        fixture.key("unused", now - 2.hours)
        fixture.key("recent", now - 30.minutes)
        fixture.storeCredentialBoundTo(bound)

        assertEquals(1, fixture.cleanup.collect())

        assertEquals(setOf("bound", "recent"), fixture.factory.aliases)
        assertEquals(
            setOf("bound", "recent"),
            fixture.registry.all().map { (it as HolderKeyHandle.Platform).alias }.toSet()
        )
        assertNull(fixture.certificate("unused"))
        assertNotNull(fixture.certificate("bound"))
    }

    @Test
    fun keepsAKeyStoredByAnotherSessionThatTheHotStoreDoesNotShowYet() = runTest {
        val fixture = Fixture(now) { store ->
            object : WalletSubjectCredentialStore by store {
                override fun observeStoreContainer() = flowOf(StoreContainer(credentials = emptyList()))
            }
        }
        val bound = fixture.key("bound", now - 2.hours)
        fixture.storeCredentialBoundTo(bound)

        assertEquals(0, fixture.cleanup.collect())

        assertEquals(setOf("bound"), fixture.factory.aliases)
    }

    @Test
    fun deletesNothingIfTheStoredCredentialsCanNotBeDecoded() = runTest {
        val fixture = Fixture(now)
        fixture.key("legacy", now - 2.hours)
        fixture.dataStore.setPreference("not a credential store", Configuration.DATASTORE_KEY_VCS)
        assertTrue(fixture.store.observeStoreContainer().first().unreadable)

        assertEquals(0, fixture.cleanup.collect())

        assertEquals(setOf("legacy"), fixture.factory.aliases)
        assertNotNull(fixture.certificate("legacy"))
    }

    @Test
    fun deletesNothingIfACredentialNamesAKeyThatCanNotBeRead() = runTest {
        val fixture = Fixture(now)
        fixture.key("unknown", now - 2.hours)
        fixture.store.storeCredential(
            SubjectCredentialStore.StoreEntry.SdJwt(
                vcSerialized = "",
                sdJwt = VerifiableCredentialSdJwt(
                    verifiableCredentialType = "urn:example",
                    confirmationClaim = ConfirmationClaim(keyId = "key-1"),
                ),
                disclosures = emptyMap(),
                schemeIdentifier = "urn:example",
            )
        ).getOrThrow()

        assertEquals(0, fixture.cleanup.collect())

        assertEquals(setOf("unknown"), fixture.factory.aliases)
    }

    @Test
    fun keepsTheKeysHeldByAReviewOfAnotherSession() = runTest {
        val fixture = Fixture(now)
        val held = fixture.key("held", now - 2.hours)
        val expired = fixture.key("expired", now - 2.hours)
        fixture.holds.hold(listOf(held.holderKeyThumbprint))
        // A hold of a review the session never released, from long ago
        HolderKeyHolds(fixture.dataStore, clock = fixedClock(now - 25.hours)).hold(listOf(expired.holderKeyThumbprint))

        assertEquals(1, fixture.cleanup.collect())
        assertEquals(setOf("held"), fixture.factory.aliases)

        fixture.holds.release(listOf(held.holderKeyThumbprint))
        assertEquals(1, fixture.cleanup.collect())
        assertEquals(emptySet(), fixture.factory.aliases)
    }

    @Test
    fun deletesNothingIfTheHoldsCanNotBeDecoded() = runTest {
        val fixture = Fixture(now)
        fixture.key("unused", now - 2.hours)
        fixture.dataStore.setPreference("not holds", Configuration.DATASTORE_KEY_HOLDER_KEY_HOLDS)

        assertEquals(0, fixture.cleanup.collect())
        assertEquals(setOf("unused"), fixture.factory.aliases)
    }

    @Test
    fun deletesTheKeyOfARemovedCredential() = runTest {
        val fixture = Fixture(now)
        val bound = fixture.key("bound", now - 2.hours)
        fixture.storeCredentialBoundTo(bound)
        assertEquals(0, fixture.cleanup.collect())

        val id = fixture.store.observeStoreContainer().first().credentials.single().first
        fixture.store.removeStoreEntryById(id)

        assertEquals(1, fixture.cleanup.collect())
        assertEquals(emptySet(), fixture.factory.aliases)
    }

    @Test
    fun trustsTheHotContainerToShowNothingToDelete() = runTest {
        val fixture = Fixture(now)
        val bound = fixture.key("bound", now - 2.hours)
        fixture.storeCredentialBoundTo(bound)
        val hot = fixture.store.observeStoreContainer().first()
        val id = hot.credentials.single().first
        fixture.store.removeStoreEntryById(id)

        // The stored credentials aren't read again, the next hot container triggers the deletion
        assertEquals(0, fixture.cleanup.collect(hot))
        assertEquals(setOf("bound"), fixture.factory.aliases)

        assertEquals(1, fixture.cleanup.collect(fixture.store.observeStoreContainer().first()))
        assertEquals(emptySet(), fixture.factory.aliases)
    }

    @Test
    fun confirmsWithTheStoredCredentialsBeforeDeleting() = runTest {
        val fixture = Fixture(now)
        val bound = fixture.key("bound", now - 2.hours)
        val hot = fixture.store.observeStoreContainer().first()
        // Stored after the hot container was decoded
        fixture.storeCredentialBoundTo(bound)

        assertEquals(0, fixture.cleanup.collect(hot))
        assertEquals(setOf("bound"), fixture.factory.aliases)
    }

    @Test
    fun deletesNothingIfTheHotContainerCanNotBeDecoded() = runTest {
        val fixture = Fixture(now)
        fixture.key("unused", now - 2.hours)

        assertEquals(0, fixture.cleanup.collect(StoreContainer(credentials = emptyList(), unreadable = true)))
        assertEquals(setOf("unused"), fixture.factory.aliases)
    }

}

private fun fixedClock(at: Instant) = object : Clock {
    override fun now() = at
}
