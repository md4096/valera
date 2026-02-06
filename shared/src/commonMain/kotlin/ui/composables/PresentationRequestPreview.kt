package ui.composables

import androidx.compose.runtime.Composable
import at.asitplus.catchingUnwrapped
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.valera.resources.Res
import at.asitplus.valera.resources.error_complex_dcql_query
import at.asitplus.valera.resources.error_invalid_dcql_query
import at.asitplus.wallet.app.common.extractConsentData
import at.asitplus.wallet.app.common.thirdParty.at.asitplus.wallet.lib.data.getLocalization
import at.asitplus.wallet.app.common.thirdParty.at.asitplus.wallet.lib.data.uiLabel
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.PresentationExchangeRequest
import data.credentials.JsonClaimReference
import data.credentials.JwtClaimDefinition
import data.credentials.JwtClaimDefinitionTranslator
import data.credentials.MdocClaimReference
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.getString
import org.jetbrains.compose.resources.stringResource

@Composable
fun PresentationRequestPreview(
    data: PresentationRequestPreviewData
) {
    val scheme = data.scheme
    val schemeName = scheme.uiLabel()
    val format = data.representation.name
    val localizations = data.attributes?.let { claimReferences ->
        val otherClaims = claimReferences.count {
            it.key == null
        }
        val singleClaimReferences = claimReferences.filter {
            it.key != null
        }.mapKeys {
            it.key!!
        }
        otherClaims to singleClaimReferences.mapKeys { (path, _) ->
            catchingUnwrapped {
                (scheme.getLocalization(path) ?: getMetadataLocalization(path))
                    ?.let { stringResource(it) }
                    ?: path.toString()
            }.getOrElse { path.toString() }
        }
    }
    ConsentAttributesSection(
        title = "$schemeName (${format})",
        attributes = localizations
    )
}
private fun getMetadataLocalization(path: NormalizedJsonPath): StringResource? {
    val firstSegment = path.segments.firstOrNull()?.let {
        it as? NormalizedJsonPathSegment.NameSegment
    } ?: return null
    val jwtClaimDefinition = JwtClaimDefinition.valueOfClaimNameOrNull(firstSegment.memberName) ?: return null
    return JwtClaimDefinitionTranslator().translate(jwtClaimDefinition)
}

data class PresentationRequestPreviewData(val scheme: ConstantIndex.CredentialScheme,
                                          val representation: ConstantIndex.CredentialRepresentation,
                                          val attributes: Map<NormalizedJsonPath?, Boolean>?)

suspend fun CredentialPresentationRequest.toPreviewData(): List<PresentationRequestPreviewData>? = when (this) {
    is DCQLRequest -> {
        if (this.dcqlQuery.requestedCredentialSetQueries.size != 1) {
            throw(UnsupportedOperationException(getString(Res.string.error_complex_dcql_query)))
        }
        val credentialSetQuery = this.dcqlQuery.requestedCredentialSetQueries.first()

        if (credentialSetQuery.options.size != 1) {
            throw(UnsupportedOperationException(getString(Res.string.error_complex_dcql_query)))
        }
        val requestedCredentialCombination = credentialSetQuery.options.first()

        requestedCredentialCombination.map { credentialQueryIdentifier ->
            val credentialQuery = this.dcqlQuery.credentials.find {
                it.id == credentialQueryIdentifier
            }
            if (credentialQuery == null) {
                throw (IllegalArgumentException(getString(Res.string.error_invalid_dcql_query)))
            }

            val (representation, scheme, attributePaths) = try {
                credentialQuery.extractConsentData()
            } catch (e: Throwable) {
                throw e
            }

            PresentationRequestPreviewData(scheme, representation, attributePaths?.map {
                when (it) {
                    is MdocClaimReference -> NormalizedJsonPath() + it.namespace + it.claimName
                    is JsonClaimReference -> it.normalizedJsonPath
                    null -> null
                }
            }?.associateWith { false })
        }
    }
    is PresentationExchangeRequest -> {
        this.presentationDefinition.inputDescriptors.map { inputDescriptor ->
            inputDescriptor.extractConsentData().let { (representation, scheme, attributes) ->
                PresentationRequestPreviewData(
                    scheme = scheme,
                    representation = representation,
                    attributes = attributes.mapKeys { it.key }
                )
            }
        }
    }
}