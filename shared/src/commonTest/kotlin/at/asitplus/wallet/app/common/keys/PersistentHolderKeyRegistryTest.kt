package at.asitplus.wallet.app.common.keys

import data.storage.DummyDataStoreService
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.SerializationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.time.Instant

class PersistentHolderKeyRegistryTest {
    private val first = HolderKeyHandle.Platform("holder-1", "thumbprint-1", Instant.fromEpochSeconds(1))
    private val second = HolderKeyHandle.Platform("holder-2", "thumbprint-2", Instant.fromEpochSeconds(2))

    @Test
    fun putAndGet() = runTest {
        val registry = PersistentHolderKeyRegistry(DummyDataStoreService())

        registry.put(first)
        registry.put(second)

        assertEquals(first, registry.get(first.thumbprint))
        assertEquals(second, registry.get(second.thumbprint))
        assertNull(registry.get("unknown"))
        assertEquals(listOf(first, second), registry.all())
    }

    @Test
    fun putReplacesTheEntryOfTheSameThumbprint() = runTest {
        val registry = PersistentHolderKeyRegistry(DummyDataStoreService())
        val replacement = first.copy(alias = "holder-3")

        registry.put(first)
        registry.put(replacement)

        assertEquals(listOf(replacement), registry.all())
    }

    @Test
    fun removeAndClear() = runTest {
        val dataStore = DummyDataStoreService()
        val registry = PersistentHolderKeyRegistry(dataStore, "registry")
        registry.put(first)
        registry.put(second)

        registry.remove(first.thumbprint)
        registry.remove("unknown")
        assertEquals(listOf(second), registry.all())

        registry.remove(second.thumbprint)
        assertNull(dataStore.getPreference("registry").first())

        registry.put(first)
        registry.clear()
        assertEquals(emptyList(), registry.all())
        assertNull(dataStore.getPreference("registry").first())
    }

    @Test
    fun entriesAreReadFromTheStore() = runTest {
        val dataStore = DummyDataStoreService()
        PersistentHolderKeyRegistry(dataStore).put(first)
        val other = PersistentHolderKeyRegistry(dataStore)

        assertEquals(first, other.get(first.thumbprint))

        other.put(second)
        PersistentHolderKeyRegistry(dataStore).remove(first.thumbprint)
        assertEquals(listOf(second), other.all())
    }

    @Test
    fun undecodableContentFailsInsteadOfBeingDropped() = runTest {
        val dataStore = DummyDataStoreService()
        dataStore.setPreference("not json", "registry")
        val registry = PersistentHolderKeyRegistry(dataStore, "registry")

        assertFailsWith<SerializationException> { registry.all() }
        assertFailsWith<SerializationException> { registry.put(first) }
        assertEquals("not json", dataStore.getPreference("registry").first())
    }
}
