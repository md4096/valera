package at.asitplus.wallet.app.common.domain.platform.di

import at.asitplus.wallet.app.common.IntentState
import at.asitplus.wallet.app.common.PlatformAdapter
import at.asitplus.wallet.app.common.SESSION_NAME
import at.asitplus.wallet.app.common.SessionService
import at.asitplus.wallet.app.common.SigningUiCallbacks
import at.asitplus.wallet.app.common.WalletKeyMaterial
import at.asitplus.wallet.app.common.WalletSessionBindings
import at.asitplus.wallet.app.common.decodeImage
import at.asitplus.wallet.app.common.domain.platform.ImageDecoder
import at.asitplus.wallet.app.common.domain.platform.UrlOpener
import at.asitplus.wallet.app.common.keys.HolderKeyCleanup
import at.asitplus.wallet.app.common.keys.HolderKeyFactory
import at.asitplus.wallet.app.common.keys.HolderKeyHolds
import at.asitplus.wallet.app.common.keys.HolderKeyManager
import at.asitplus.wallet.app.common.keys.HolderKeyRegistry
import at.asitplus.wallet.app.common.keys.PersistentHolderKeyRegistry
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import data.storage.DataStoreService
import data.storage.HotWalletSubjectCredentialStore
import data.storage.PersistentSubjectCredentialStore
import data.storage.PersistentTrustListStore
import data.storage.WalletSubjectCredentialStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.runBlocking
import org.koin.core.module.dsl.scopedOf
import org.koin.core.qualifier.named
import org.koin.dsl.binds
import org.koin.dsl.module
import org.multipaz.prompt.PromptModel

/**
 * Bridges the imperative session setup in [WalletSessionScopeFactory] with Koin's declarative DI
 * by unwrapping each field of [WalletSessionBindings] into its own session-scoped binding.
 */
fun platformModule() = module {
    scope(named(SESSION_NAME)) {
        scoped<IntentState> { get<WalletSessionBindings>().intentState }
        scoped<SessionService> { get<WalletSessionBindings>().sessionService }
        scoped<PromptModel> { get<WalletSessionBindings>().promptModel }
        scoped<PlatformAdapter> { get<WalletSessionBindings>().platformAdapter }
        scoped<DataStoreService> { get<WalletSessionBindings>().dataStoreService }
        scoped<at.asitplus.wallet.app.common.KeystoreService> { get<WalletSessionBindings>().keystoreService }
        scoped<CoroutineScope> { get<WalletSessionBindings>().sessionCoroutineScope }
        scopedOf(::PersistentSubjectCredentialStore)
        scopedOf(::PersistentTrustListStore)

        scopedOf(::SigningUiCallbacks)
        scoped<HolderKeyFactory> { get<at.asitplus.wallet.app.common.KeystoreService>().holderKeyFactory }
        scoped<HolderKeyRegistry> { PersistentHolderKeyRegistry(get()) }
        scoped {
            HolderKeyManager(
                registry = get(),
                factory = get(),
                signingUi = get(),
                dataStoreService = get(),
                resolveOnly = get<WalletSessionBindings>().resolveHolderKeysOnly,
            )
        }
        scoped { HolderKeyHolds(get()) }
        scoped {
            HolderKeyCleanup(
                holderKeyManager = get(),
                subjectCredentialStore = get(),
                persistentSubjectCredentialStore = get(),
                pendingCredentialReview = get(),
                holderKeyHolds = get(),
            )
        }
        scoped<WalletKeyMaterial> {
            @Suppress("DEPRECATION")
            runBlocking { get<HolderKeyManager>().legacyKeyOrFallback() }
        } binds arrayOf(KeyMaterial::class)

        scoped<HotWalletSubjectCredentialStore> {
            HotWalletSubjectCredentialStore(
                delegate = get(),
                coroutineScope = CoroutineScope(get<CoroutineScope>().coroutineContext + Dispatchers.IO)
            )
        } binds arrayOf(
            SubjectCredentialStore::class,
            WalletSubjectCredentialStore::class,
        )

        scoped<UrlOpener> {
            UrlOpener {
                get<PlatformAdapter>().openUrl(it)
            }
        }

        scoped<ImageDecoder> {
            ImageDecoder {
                get<PlatformAdapter>().decodeImage(it)
            }
        }
    }
}
