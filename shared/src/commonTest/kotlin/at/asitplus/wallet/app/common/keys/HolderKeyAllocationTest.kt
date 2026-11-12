package at.asitplus.wallet.app.common.keys

import at.asitplus.openid.CredentialRequestProofSupported
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.KeyAttestationRequired
import at.asitplus.openid.OpenIdConstants.ProofTypes
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.UnlockFailed
import at.asitplus.signum.supreme.UserInitiatedCancellationReason
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.app.common.SigningUiCallbacks
import at.asitplus.wallet.lib.oidvci.AttestationProofCreator
import at.asitplus.wallet.lib.oidvci.JwtProofCreator
import at.asitplus.wallet.lib.oidvci.OpenId4VciClient
import data.storage.DummyDataStoreService
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

class HolderKeyAllocationTest {
    private class Fixture(
        val factory: HolderKeyFactory = InMemoryHolderKeyFactory(),
        val dataStore: DummyDataStoreService = DummyDataStoreService(),
        val registry: HolderKeyRegistry = PersistentHolderKeyRegistry(dataStore),
    ) {
        val manager = HolderKeyManager(registry, factory, SigningUiCallbacks(), dataStore)
        val aliases get() = (factory as InMemoryHolderKeyFactory).aliases
        val pending = PendingHolderKeys(dataStore)
    }

    @Test
    fun everyAllocationGetsANewRegisteredKey() = runTest {
        val fixture = Fixture()

        val first = fixture.manager.allocateForIssuance()
        val second = fixture.manager.allocateForIssuance()

        assertFalse(first.publicKey.equalsCryptographically(second.publicKey))
        assertEquals(2, fixture.aliases.size)
        assertTrue(fixture.aliases.all { it.startsWith(HOLDER_KEY_ALIAS_PREFIX) })
        assertEquals(
            setOf(first.publicKey.holderKeyThumbprint, second.publicKey.holderKeyThumbprint),
            fixture.registry.all().map { it.thumbprint }.toSet(),
        )
        listOf(first, second).forEach {
            assertTrue(fixture.manager.resolve(it.publicKey).getOrThrow().publicKey.equalsCryptographically(it.publicKey))
        }
        assertEquals(emptyMap(), fixture.pending.all())
    }

    @Test
    fun withoutSecureHardwareAllocationFailsAndNothingIsRegistered() = runTest {
        val failingFactory = object : HolderKeyFactory by InMemoryHolderKeyFactory() {
            override suspend fun create(alias: String): Signer = throw IllegalStateException("No secure hardware")
        }
        val dataStore = DummyDataStoreService()
        val registry = PersistentHolderKeyRegistry(dataStore)
        val manager = HolderKeyManager(registry, failingFactory, SigningUiCallbacks(), dataStore)

        assertFailsWith<IllegalStateException> { manager.allocateForIssuance() }

        assertEquals(emptyList(), registry.all())
    }

    @Test
    fun aKeyThatCanNotBeRegisteredIsDeleted() = runTest {
        val dataStore = DummyDataStoreService()
        val failingRegistry = object : HolderKeyRegistry by PersistentHolderKeyRegistry(dataStore) {
            override suspend fun put(handle: HolderKeyHandle) = throw IllegalStateException("Write failed")
        }
        val fixture = Fixture(dataStore = dataStore, registry = failingRegistry)

        assertFailsWith<IllegalStateException> { fixture.manager.allocateForIssuance() }

        assertEquals(emptySet(), fixture.aliases)
        assertEquals(emptyMap(), fixture.pending.all())
    }

    @Test
    fun aKeyTheKeystoreCreatedBeforeFailingIsDeleted() = runTest {
        val keys = InMemoryHolderKeyFactory()
        val failingFactory = object : HolderKeyFactory by keys {
            override suspend fun create(alias: String): Signer {
                keys.create(alias)
                throw IllegalStateException("Reading the attestation failed")
            }
        }
        val fixture = Fixture(factory = failingFactory)

        assertFailsWith<IllegalStateException> { fixture.manager.allocateForIssuance() }

        assertEquals(emptySet(), keys.aliases)
        assertEquals(emptyMap(), fixture.pending.all())
    }

    @Test
    fun aKeyThatCanBeNeitherRegisteredNorDeletedIsDeletedLaterOnceItsRecordIsOld() = runTest {
        val keys = InMemoryHolderKeyFactory()
        var deletable = false
        val factory = object : HolderKeyFactory by keys {
            override suspend fun delete(alias: String) =
                if (deletable) keys.delete(alias) else throw IllegalStateException("Keystore error")
        }
        val dataStore = DummyDataStoreService()
        var writable = false
        val registry = object : HolderKeyRegistry by PersistentHolderKeyRegistry(dataStore) {
            override suspend fun put(handle: HolderKeyHandle) =
                if (writable) PersistentHolderKeyRegistry(dataStore).put(handle) else throw IllegalStateException()
        }
        val fixture = Fixture(factory = factory, dataStore = dataStore, registry = registry)

        assertFailsWith<IllegalStateException> { fixture.manager.allocateForIssuance() }
        val alias = keys.aliases.single()
        assertEquals(setOf(alias), fixture.pending.all().keys)
        deletable = true
        writable = true

        // Young: it may be a key another session is creating right now
        assertEquals(0, fixture.manager.collectUnreferenced(emptySet(), olderThan = Clock.System.now() - 1.hours))
        assertEquals(setOf(alias), keys.aliases)

        assertEquals(1, fixture.manager.collectUnreferenced(emptySet(), olderThan = Clock.System.now() + 1.minutes))
        assertEquals(emptySet(), keys.aliases)
        assertEquals(emptyMap(), fixture.pending.all())
    }

    @Test
    fun anAbsentUnregisteredAliasIsCleanedUpOnlyOnce() = runTest {
        val fixture = Fixture()
        fixture.pending.add(listOf("holder-absent"), Clock.System.now() - 2.hours)

        assertEquals(1, fixture.manager.collectUnreferenced(emptySet(), olderThan = Clock.System.now()))
        assertEquals(emptyMap(), fixture.pending.all())
        assertEquals(0, fixture.manager.collectUnreferenced(emptySet(), olderThan = Clock.System.now()))
    }

    @Test
    fun theRecordOfARegisteredKeyIsDroppedButTheKeyKept() = runTest {
        val fixture = Fixture()
        val key = fixture.manager.newKey()
        val alias = fixture.aliases.single()
        // As if the process ended after registering the key, before removing its record
        fixture.pending.add(listOf(alias), Clock.System.now())

        val deleted = fixture.manager.collectUnreferenced(
            referenced = setOf(key.publicKey.holderKeyThumbprint),
            olderThan = Clock.System.now() + 1.minutes,
        )

        assertEquals(0, deleted)
        assertEquals(setOf(alias), fixture.aliases)
        assertEquals(emptyMap(), fixture.pending.all())
    }

    @Test
    fun asProofKeySupplierAKeyIsAllocatedForTheRequirementsOfTheProofType() = runTest {
        val fixture = Fixture()
        val creator = JwtProofCreator(keySupplier = fixture.manager)

        val created = assertNotNull(
            creator.createProof(ISSUER, credentialFormat(keyAttestationRequired = null), "client", "nonce").getOrThrow()
        )

        val proofKey = assertNotNull(created.key)
        assertEquals(proofKey.holderKeyThumbprint, fixture.registry.all().single().thumbprint)
        assertEquals(1, created.proofs.jwt?.size)
    }

    @Test
    fun aCancelledUnlockEndsTheRequestInsteadOfProvingAnotherKeyWithAnAttestation() = runTest {
        val keys = InMemoryHolderKeyFactory()
        val cancellingFactory = object : HolderKeyFactory by keys {
            override suspend fun create(alias: String): Signer = keys.create(alias).cancellingUnlock()
        }
        val fixture = Fixture(factory = cancellingFactory)
        var keyAttestations = 0
        val client = OpenId4VciClient(
            proofCreators = listOf(
                JwtProofCreator(keySupplier = fixture.manager),
                AttestationProofCreator(
                    loadKeyAttestation = { keyAttestations++; error("No key attestation expected") },
                    keySupplier = fixture.manager,
                ),
            ),
        )
        val metadata = IssuerMetadata(
            credentialIssuer = ISSUER,
            credentialEndpointUrl = "$ISSUER/credential",
            supportedCredentialConfigurations = mapOf(
                CONFIGURATION_ID to credentialFormat(
                    keyAttestationRequired = null,
                    proofTypes = listOf(ProofTypes.JWT, ProofTypes.ATTESTATION),
                ),
            ),
        )

        val failure = client.createCredential(metadata, CONFIGURATION_ID, clientNonce = "nonce").exceptionOrNull()

        assertNotNull(generateSequence(failure) { it.cause }.firstOrNull { it is UserInitiatedCancellationReason })
        assertEquals(1, keys.aliases.size)
        assertEquals(0, keyAttestations)
    }

    /** A signer whose every signature fails as the user cancelled unlocking the key. */
    private fun Signer.cancellingUnlock(): Signer {
        val signer = this
        return object : Signer by signer {
            // Delegation forwards the overloads with a default body as well, so override each one in use
            override suspend fun sign(data: SignatureInput) = SignatureResult.Failure(UnlockFailed("Cancelled"))
            override suspend fun sign(data: ByteArray) = SignatureResult.Failure(UnlockFailed("Cancelled"))
        }
    }

    private fun credentialFormat(
        keyAttestationRequired: KeyAttestationRequired?,
        proofTypes: List<String> = listOf(ProofTypes.JWT),
    ) = SupportedCredentialFormat.forSdJwt(
        scope = "example",
        supportedBindingMethods = setOf("jwk"),
        supportedProofTypes = proofTypes.associateWith {
            CredentialRequestProofSupported(
                supportedSigningAlgorithms = setOf("ES256"),
                keyAttestationRequired = keyAttestationRequired,
            )
        },
        sdJwtVcType = "urn:example",
        sdJwtClaims = emptySet(),
    )

    private companion object {
        const val ISSUER = "https://issuer.example.com"
        const val CONFIGURATION_ID = "example"
    }
}
