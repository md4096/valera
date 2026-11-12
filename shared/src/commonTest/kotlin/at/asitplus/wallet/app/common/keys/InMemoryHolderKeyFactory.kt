package at.asitplus.wallet.app.common.keys

import at.asitplus.signum.supreme.sign.Signer

/**
 * [HolderKeyFactory] for tests: ephemeral software keys by alias, so tests don't need the platform keystore, which CI's
 * emulators and simulators don't provide with secure hardware.
 */
class InMemoryHolderKeyFactory : HolderKeyFactory {
    private val keys = mutableMapOf<String, Signer>()

    /** Aliases of the keys that currently exist. */
    val aliases: Set<String> get() = keys.keys.toSet()

    override suspend fun create(alias: String): Signer =
        Signer.Ephemeral { ec {} }.getOrThrow().also { keys[alias] = it }

    override suspend fun load(alias: String): Signer? = keys[alias]

    override suspend fun delete(alias: String) {
        keys.remove(alias)
    }
}
