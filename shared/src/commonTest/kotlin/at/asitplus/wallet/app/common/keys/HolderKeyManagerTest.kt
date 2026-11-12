package at.asitplus.wallet.app.common.keys

import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.app.common.Configuration
import at.asitplus.wallet.app.common.FallBackKeyMaterial
import at.asitplus.wallet.app.common.SigningUiCallbacks
import at.asitplus.wallet.lib.agent.HolderKeyResolver
import data.storage.DummyDataStoreService
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HolderKeyManagerTest {
    private class Fixture {
        val dataStore = DummyDataStoreService()
        val registry = PersistentHolderKeyRegistry(dataStore)
        val factory = InMemoryHolderKeyFactory()
        val manager = HolderKeyManager(registry, factory, SigningUiCallbacks(), dataStore)
    }

    @Test
    fun theLegacyKeyIsCreatedOnceAndRegistered() = runTest {
        val fixture = Fixture()

        val first = fixture.manager.legacyKey()
        val second = fixture.manager.legacyKey()

        assertTrue(first.publicKey.equalsCryptographically(second.publicKey))
        assertEquals(setOf(Configuration.KS_ALIAS), fixture.factory.aliases)
        val handle = assertIs<HolderKeyHandle.Platform>(fixture.registry.all().single())
        assertEquals(Configuration.KS_ALIAS, handle.alias)
        assertEquals(first.publicKey.holderKeyThumbprint, handle.thumbprint)
    }

    @Test
    fun resolveFindsARegisteredKey() = runTest {
        val fixture = Fixture()
        val signer = fixture.factory.create("holder-1")
        fixture.registry.put(HolderKeyHandle.Platform("holder-1", signer.publicKey.holderKeyThumbprint, now()))

        val resolved = fixture.manager.resolve(signer.publicKey).getOrThrow()

        assertTrue(resolved.publicKey.equalsCryptographically(signer.publicKey))
    }

    @Test
    fun resolvesAsTheHolderKeyResolverOfVcK() = runTest {
        val fixture = Fixture()
        val legacy = fixture.manager.legacyKey()
        val resolver: HolderKeyResolver = fixture.manager

        val resolved = resolver.resolve(legacy.publicKey).getOrThrow()

        assertTrue(resolved.publicKey.equalsCryptographically(legacy.publicKey))
        assertIs<HolderKeyNotFoundException>(resolver.resolve(otherKey()).exceptionOrNull())
    }

    @Test
    fun resolveFallsBackToTheUnregisteredLegacyKey() = runTest {
        val fixture = Fixture()
        val legacy = fixture.factory.create(Configuration.KS_ALIAS)

        val resolved = fixture.manager.resolve(legacy.publicKey).getOrThrow()

        assertTrue(resolved.publicKey.equalsCryptographically(legacy.publicKey))
        assertEquals(emptyList(), fixture.registry.all())
    }

    @Test
    fun resolveFailsForAnUnknownKey() = runTest {
        val fixture = Fixture()
        fixture.factory.create(Configuration.KS_ALIAS)

        val result = fixture.manager.resolve(otherKey())

        assertIs<HolderKeyNotFoundException>(result.exceptionOrNull())
    }

    @Test
    fun resolveFailsForAStaleKey() = runTest {
        val fixture = Fixture()
        val bound = fixture.factory.create("holder-1")
        fixture.registry.put(HolderKeyHandle.Platform("holder-1", bound.publicKey.holderKeyThumbprint, now()))
        // The key under the alias is invalidated and created again
        fixture.factory.delete("holder-1")
        fixture.factory.create("holder-1")

        val result = fixture.manager.resolve(bound.publicKey)

        assertIs<HolderKeyNotFoundException>(result.exceptionOrNull())
    }

    @Test
    fun migrationRegistersTheLegacyKeyAndMovesItsCertificate() = runTest {
        val fixture = Fixture()
        val legacy = fixture.factory.create(Configuration.KS_ALIAS)
        fixture.dataStore.setPreference("legacy certificate", LEGACY_CERT_STORAGE_KEY)

        fixture.manager.migrateLegacyKey()
        fixture.manager.migrateLegacyKey()

        val handle = assertIs<HolderKeyHandle.Platform>(fixture.registry.all().single())
        assertEquals(Configuration.KS_ALIAS, handle.alias)
        assertEquals(legacy.publicKey.holderKeyThumbprint, handle.thumbprint)
        assertNull(fixture.dataStore.getPreference(LEGACY_CERT_STORAGE_KEY).first())
        assertEquals(
            "legacy certificate",
            fixture.dataStore.getPreference(certificateStorageKey(Configuration.KS_ALIAS)).first()
        )
    }

    @Test
    fun migrationKeepsACertificateAlreadyStoredPerAlias() = runTest {
        val fixture = Fixture()
        fixture.dataStore.setPreference("legacy certificate", LEGACY_CERT_STORAGE_KEY)
        fixture.dataStore.setPreference("current certificate", certificateStorageKey(Configuration.KS_ALIAS))

        fixture.manager.migrateLegacyKey()

        assertNull(fixture.dataStore.getPreference(LEGACY_CERT_STORAGE_KEY).first())
        assertEquals(
            "current certificate",
            fixture.dataStore.getPreference(certificateStorageKey(Configuration.KS_ALIAS)).first()
        )
    }

    @Test
    fun migrationWithoutALegacyKeyRegistersNothing() = runTest {
        val fixture = Fixture()

        fixture.manager.migrateLegacyKey()

        assertEquals(emptyList(), fixture.registry.all())
    }

    @Test
    fun deleteAllDeletesRegisteredAndLegacyKeysWithTheirCertificates() = runTest {
        val fixture = Fixture()
        fixture.manager.legacyKey()
        val signer = fixture.factory.create("holder-1")
        fixture.registry.put(HolderKeyHandle.Platform("holder-1", signer.publicKey.holderKeyThumbprint, now()))
        Configuration.KS_ALIASES_OLDER_THAN_THE_HILLS.forEach { fixture.factory.create(it) }
        val aliases = listOf("holder-1", Configuration.KS_ALIAS)
        aliases.forEach { fixture.dataStore.setPreference("certificate", certificateStorageKey(it)) }
        fixture.dataStore.setPreference("legacy certificate", LEGACY_CERT_STORAGE_KEY)

        fixture.manager.deleteAll()

        assertEquals(emptySet(), fixture.factory.aliases)
        assertEquals(emptyList(), fixture.registry.all())
        aliases.forEach { assertNull(fixture.dataStore.getPreference(certificateStorageKey(it)).first()) }
        assertNull(fixture.dataStore.getPreference(LEGACY_CERT_STORAGE_KEY).first())
    }

    @Test
    fun deleteAllKeepsGoingAndKeepsRegisteredAKeyThatCantBeDeleted() = runTest {
        val fixture = Fixture()
        val stuck = fixture.factory.create("holder-1")
        val other = fixture.factory.create("holder-2")
        fixture.registry.put(HolderKeyHandle.Platform("holder-1", stuck.publicKey.holderKeyThumbprint, now()))
        fixture.registry.put(HolderKeyHandle.Platform("holder-2", other.publicKey.holderKeyThumbprint, now()))
        fixture.factory.create(Configuration.KS_ALIAS)
        listOf("holder-1", "holder-2").forEach {
            fixture.dataStore.setPreference("certificate", certificateStorageKey(it))
        }
        fixture.factory.undeletable = setOf("holder-1")

        fixture.manager.deleteAll()

        assertEquals(setOf("holder-1"), fixture.factory.aliases)
        val kept = assertIs<HolderKeyHandle.Platform>(fixture.registry.all().single())
        assertEquals("holder-1", kept.alias)
        assertEquals("certificate", fixture.dataStore.getPreference(certificateStorageKey("holder-1")).first())
        assertNull(fixture.dataStore.getPreference(certificateStorageKey("holder-2")).first())

        fixture.factory.undeletable = emptySet()
        fixture.manager.deleteAll()
        assertEquals(emptySet(), fixture.factory.aliases)
        assertEquals(emptyList(), fixture.registry.all())
    }

    @Test
    fun deleteAllWithAnUnreadableRegistryDeletesTheFixedAliasesAndClearsIt() = runTest {
        val fixture = Fixture()
        fixture.factory.create(Configuration.KS_ALIAS)
        Configuration.KS_ALIASES_OLDER_THAN_THE_HILLS.forEach { fixture.factory.create(it) }
        fixture.dataStore.setPreference("not a registry", Configuration.DATASTORE_KEY_HOLDER_KEYS)

        fixture.manager.deleteAll()

        assertEquals(emptySet(), fixture.factory.aliases)
        assertNull(fixture.dataStore.getPreference(Configuration.DATASTORE_KEY_HOLDER_KEYS).first())
        assertEquals(emptyList(), fixture.registry.all())
    }

    @Test
    fun isValidUnlessKeysOfOlderVersionsArePresent() = runTest {
        val fixture = Fixture()
        fixture.manager.legacyKey()
        assertTrue(fixture.manager.isValid())

        fixture.factory.create(Configuration.KS_ALIASES_OLDER_THAN_THE_HILLS.first())

        assertFalse(fixture.manager.isValid())
    }

    @Test
    @Suppress("DEPRECATION")
    fun fallbackKeyIsNeverRegistered() = runTest {
        val dataStore = DummyDataStoreService()
        val registry = PersistentHolderKeyRegistry(dataStore)
        val failingFactory = object : HolderKeyFactory by InMemoryHolderKeyFactory() {
            override suspend fun create(alias: String): Signer = throw IllegalStateException("No secure hardware")
        }
        val manager = HolderKeyManager(registry, failingFactory, SigningUiCallbacks(), dataStore)

        val keyMaterial = manager.legacyKeyOrFallback()

        assertIs<FallBackKeyMaterial>(keyMaterial.keyMaterial)
        assertFailsWith<IllegalStateException> { manager.legacyKey() }
        assertEquals(emptyList(), registry.all())
    }

    private fun otherKey() = Signer.Ephemeral { ec {} }.getOrThrow().publicKey

    private fun now() = kotlin.time.Clock.System.now()
}
