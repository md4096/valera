package at.asitplus.wallet.app.common.validation

import at.asitplus.wallet.app.common.keys.HolderKeyHolds
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import data.storage.DummyDataStoreService
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PendingCredentialReviewTest {
    private val holder = HolderAgent(EphemeralKeyWithoutCert())

    private fun entry(name: String): PendingCredentialReview.Entry {
        val prepared = holder.rejectUndecodable(IllegalArgumentException(name), ValidationPolicies.issuance)
        return PendingCredentialReview.Entry(
            prepared = prepared,
            scheme = ConstantIndex.AtomicAttribute2023,
            outcome = prepared.validation.report.toUi(),
        )
    }

    @Test
    fun keepingAgainAfterAFailureStoresOnlyTheEntriesNotStoredYet() = runTest {
        val review = PendingCredentialReview(HolderKeyHolds(DummyDataStoreService()))
        val (first, second, third) = listOf(entry("first"), entry("second"), entry("third"))
        review.replace(listOf(first, second, third))
        val stored = mutableListOf<PendingCredentialReview.Entry>()

        assertFailsWith<IllegalStateException> {
            review.keep {
                check(it != second) { "Storing failed" }
                stored.add(it)
            }
        }

        assertEquals(listOf(first), stored)
        assertEquals(listOf(second, third), review.entries.value)

        assertEquals(2, review.keep { stored.add(it) })

        assertEquals(listOf(first, second, third), stored)
        assertEquals(emptyList(), review.entries.value)
    }
}
