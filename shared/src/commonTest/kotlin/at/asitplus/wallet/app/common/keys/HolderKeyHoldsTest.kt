package at.asitplus.wallet.app.common.keys

import at.asitplus.wallet.app.common.Configuration
import data.storage.DummyDataStoreService
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNull
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

class HolderKeyHoldsTest {
    private val now = Clock.System.now()

    private fun holds(dataStore: DummyDataStoreService, at: Instant = now) = HolderKeyHolds(
        dataStore,
        clock = object : Clock {
            override fun now() = at
        },
    )

    @Test
    fun holdsUntilReleased() = runTest {
        val holds = holds(DummyDataStoreService())

        holds.hold(listOf("a", "b"))
        assertEquals(setOf("a", "b"), holds.held())

        holds.release(listOf("a"))
        assertEquals(setOf("b"), holds.held())
    }

    @Test
    fun holdsExpire() = runTest {
        val dataStore = DummyDataStoreService()
        holds(dataStore, at = now - 25.hours).hold(listOf("old"))
        holds(dataStore).hold(listOf("new"))

        assertEquals(setOf("new"), holds(dataStore).held())
        assertEquals(emptySet(), holds(dataStore, at = now + 25.hours).held())
    }

    @Test
    fun releasingEveryHoldRemovesThePreference() = runTest {
        val dataStore = DummyDataStoreService()
        val holds = holds(dataStore)
        holds.hold(listOf("a"))

        holds.release(listOf("a"))

        assertNull(dataStore.getPreference(Configuration.DATASTORE_KEY_HOLDER_KEY_HOLDS).first())
    }

    @Test
    fun holdsThatCanNotBeDecodedFailToBeRead() = runTest {
        val dataStore = DummyDataStoreService()
        dataStore.setPreference("not holds", Configuration.DATASTORE_KEY_HOLDER_KEY_HOLDS)

        assertFails { holds(dataStore).held() }
    }
}
