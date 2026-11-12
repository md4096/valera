package at.asitplus.wallet.app.common.attestation

import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.app.common.ErrorService
import at.asitplus.wallet.app.common.WalletConfig
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import data.storage.DummyDataStoreService
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull

class KeyAttestationHelperTest {
    @Test
    fun theKeysAreRequestedInTheirOrder() = runTest {
        var body: String? = null
        val client = HttpClient(MockEngine { request ->
            body = request.body.toByteArray().decodeToString()
            respond("", HttpStatusCode.InternalServerError)
        }) { install(ContentNegotiation) { json(joseCompliantSerializer) } }
        val keys = List(3) { EphemeralKeyWithoutCert().publicKey }
        val jwt = SignJwt<JsonWebToken>(EphemeralKeyWithoutCert(), JwsHeaderNone())(
            null, JsonWebToken(), JsonWebToken.serializer(),
        ).getOrThrow()
        val helper = KeyAttestationHelper(WalletConfig(DummyDataStoreService(), ErrorService(this)), client)

        assertFails { helper.requestKeyAttestation(keys, jwt, jwt, "nonce", null, null) }

        // The first key signs a jwt proof (TS3, 2.2.2.1)
        val requested = joseCompliantSerializer.parseToJsonElement(assertNotNull(body)).jsonObject["keys"]!!.jsonArray
            .map { joseCompliantSerializer.decodeFromJsonElement(JsonWebKey.serializer(), it).toCryptoPublicKey().getOrThrow() }
        assertEquals(keys, requested)
    }
}
