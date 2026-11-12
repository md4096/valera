package at.asitplus.wallet.app.common

import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.wallet.app.common.keys.InMemoryHolderKeyFactory
import data.storage.DummyDataStoreService
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class KeystoreServiceTest {

    @Test
    fun getSignerCreatesTheKeyOnceAndLoadsItAfterwards() = runTest {
        val factory = InMemoryHolderKeyFactory()
        val service = KeystoreService(DummyDataStoreService(), holderKeyFactory = factory)
        assertNull(service.liveSigningPublicKey())

        val first = service.getSigner()
        val second = service.getSigner()

        assertEquals(setOf(Configuration.KS_ALIAS), factory.aliases)
        assertTrue(first.publicKey.equalsCryptographically(second.publicKey))
        assertTrue(first.publicKey.equalsCryptographically(assertNotNull(service.liveSigningPublicKey())))
    }

    @Test
    fun certificateIsStoredPerAlias() = runTest {
        val dataStore = DummyDataStoreService()
        val service = KeystoreService(dataStore, holderKeyFactory = InMemoryHolderKeyFactory())

        val certificate = assertNotNull(service.getSigner().getCertificate())

        assertNotNull(dataStore.getPreference(certificateStorageKey(Configuration.KS_ALIAS)).first())
        assertNull(dataStore.getPreference("MB64_CERT_SELF_SIGNED").first())
        val reloaded = assertNotNull(service.getSigner().getCertificate())
        assertTrue(certificate.encodeToDer().contentEquals(reloaded.encodeToDer()))
    }
}
