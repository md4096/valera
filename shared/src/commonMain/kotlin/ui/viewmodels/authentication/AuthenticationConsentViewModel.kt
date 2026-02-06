package ui.viewmodels.authentication

import androidx.compose.ui.graphics.ImageBitmap
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.wallet.app.common.WalletMain
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import ui.composables.PresentationRequestPreviewData
import ui.composables.toPreviewData

class AuthenticationConsentViewModel(
    val spName: String?,
    val spLocation: String,
    val spImage: ImageBitmap?,
    val transactionData: TransactionDataBase64Url?,
    val navigateUp: () -> Unit,
    val buttonConsent: () -> Unit,
    val walletMain: WalletMain,
    val presentationRequest: CredentialPresentationRequest,
    val onClickLogo: () -> Unit,
    val onClickSettings: () -> Unit
) {
    val scope = CoroutineScope(Dispatchers.IO)
    val onError = MutableSharedFlow<Throwable>()
    val requestPreviewData = MutableStateFlow<List<PresentationRequestPreviewData>?>(null)

    val consentToDataTransmission: () -> Unit = {
        buttonConsent()
    }

    init {
        scope.launch {
            runCatching {
                presentationRequest.toPreviewData()
            }.onSuccess {
                requestPreviewData.emit(it)
            }.onFailure {
                onError.emit(it)
            }
        }
    }
}
