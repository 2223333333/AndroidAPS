package app.aaps.plugins.sync.tidepool.auth

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.util.Base64
import androidx.core.net.toUri
import app.aaps.core.interfaces.logging.AAPSLogger
import app.aaps.core.interfaces.logging.LTag
import app.aaps.core.interfaces.rx.bus.RxBus
import app.aaps.core.keys.interfaces.Preferences
import app.aaps.core.objects.crypto.CryptoUtil
import app.aaps.plugins.sync.tidepool.events.EventTidepoolStatus
import app.aaps.plugins.sync.tidepool.events.EventTidepoolUpdateGUI
import app.aaps.plugins.sync.tidepool.keys.TidepoolBooleanKey
import app.aaps.plugins.sync.tidepool.keys.TidepoolStringNonKey
import net.openid.appauth.AppAuthConfiguration
import net.openid.appauth.AuthState
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.ResponseTypeValues
import net.openid.appauth.browser.BrowserDescriptor
import net.openid.appauth.browser.BrowserMatcher
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/**
 * JamOrHam
 *
 * Handler for new style Tidepool openid auth
 */
@Singleton
class AuthFlowOut @Inject constructor(
    private val aapsLogger: AAPSLogger,
    private val preferences: Preferences,
    private val context: Context,
    private val cryptoUtil: CryptoUtil,
    private val rxBus: RxBus
) {

    companion object {
        private const val CLIENT_ID = "aaps"
        private const val REDIRECT_URI = "aaps://callback/tidepool"
        private const val INTEGRATION_BASE_URL = "https://auth.integration.tidepool.org/realms/integration"
        private const val PRODUCTION_BASE_URL = "https://auth.tidepool.org/realms/tidepool"
        private const val CUSTOM_BROWSER_PACKAGE = "com.tidbrowser"
    }

    /*
     * Match TidBrowser by package name only.
     *
     * Requiring descriptor.useCustomTab was the problem: AppAuth sets it to
     * true only when it can resolve a CustomTabsService in the browser
     * package, and that detection is unreliable for the minimal
     * TidCustomTabsService. When the flag is false the matcher never matches,
     * AppAuth finds "no suitable browser" and the login is never handed over
     * to TidBrowser.
     *
     * Matching on the package alone makes AppAuth route the auth request to
     * TidBrowser via Custom Tabs when available and via plain ACTION_VIEW
     * otherwise - both open the login screen inside TidBrowser.
     */
    private class PackageNameBrowserMatcher(
        private val requiredPackage: String
    ) : BrowserMatcher {
        override fun matches(descriptor: BrowserDescriptor): Boolean =
            descriptor.packageName == requiredPackage
    }

    private fun buildAppAuthConfig(): AppAuthConfiguration =
        AppAuthConfiguration.Builder()
            .setBrowserMatcher(PackageNameBrowserMatcher(CUSTOM_BROWSER_PACKAGE))
            .build()

    val authService: AuthorizationService =
        AuthorizationService(context, buildAppAuthConfig())

    enum class ConnectionStatus {
        NONE, BLOCKED, NOT_LOGGED_IN, NO_SESSION, FETCHING_TOKEN, SESSION_ESTABLISHED, FAILED
    }

    var connectionStatus: ConnectionStatus = ConnectionStatus.NONE
        private set
        get() =
            if (field == ConnectionStatus.NONE) {
                if (authState.lastTokenResponse != null) ConnectionStatus.NO_SESSION
                else ConnectionStatus.NOT_LOGGED_IN
            } else field

    var authState = AuthState()

    fun updateConnectionStatus(newStatus: ConnectionStatus? = null, message: String? = null) {
        aapsLogger.debug(LTag.TIDEPOOL, "updateConnectionStatus: $newStatus $message")
        newStatus?.let { connectionStatus = it }
        message?.let { rxBus.send(EventTidepoolStatus(it)) }
        rxBus.send(EventTidepoolUpdateGUI())
    }

    fun saveAuthState() {
        preferences.put(TidepoolStringNonKey.AuthState, authState.jsonSerializeString())
    }

    fun eraseAuthState(message: String?) {
        preferences.put(TidepoolStringNonKey.AuthState, "")
        initAuthState()
        updateConnectionStatus(ConnectionStatus.NONE, message)
    }

    @Synchronized fun initAuthState() {
        authState = AuthState()
        try {
            val serviceConfig = preferences.get(TidepoolStringNonKey.ServiceConfiguration)
            if (serviceConfig.isNotEmpty())
                authState = AuthState(AuthorizationServiceConfiguration.fromJson(serviceConfig))
            val savedAuthState = preferences.get(TidepoolStringNonKey.AuthState)
            if (savedAuthState.isNotEmpty()) {
                authState = AuthState.jsonDeserialize(savedAuthState)
            }
        } catch (e: Exception) {
            aapsLogger.error(LTag.TIDEPOOL, "Failed to restore auth state, resetting", e)
            authState = AuthState()
            preferences.put(TidepoolStringNonKey.AuthState, "")
            preferences.put(TidepoolStringNonKey.ServiceConfiguration, "")
        }
        aapsLogger.debug(LTag.TIDEPOOL, "Using auth state : ${authState.jsonSerializeString()}")
    }

    @Synchronized
    fun clearAllSavedData() {
        preferences.put(TidepoolStringNonKey.ServiceConfiguration, "")
        eraseAuthState("Credentials cleared")
    }

    fun doTidePoolInitialLogin(@Suppress("unused") from: String) {
        rxBus.send(EventTidepoolStatus(("Opening login screen")))
        AuthorizationServiceConfiguration.fetchFromIssuer(
            if (preferences.get(TidepoolBooleanKey.UseTestServers)) INTEGRATION_BASE_URL.toUri()
            else PRODUCTION_BASE_URL.toUri(),
            AuthorizationServiceConfiguration.RetrieveConfigurationCallback { serviceConfiguration, exception ->
                if (exception != null || serviceConfiguration == null) {
                    rxBus.send(EventTidepoolStatus(("Failed to fetch configuration $exception")))
                    return@RetrieveConfigurationCallback
                }
                preferences.put(TidepoolStringNonKey.ServiceConfiguration, serviceConfiguration.toJsonString())
                initAuthState()

                val codeVerifierChallengeMethod = "S256"
                val encoding = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                val challenge = cryptoUtil.getRandomKey(64)
                val codeVerifier = Base64.encodeToString(challenge, encoding)
                val digest = MessageDigest.getInstance("SHA-256")
                val hash = digest.digest(codeVerifier.toByteArray(StandardCharsets.UTF_8))
                val codeChallenge = Base64.encodeToString(hash, encoding)

                val authRequest =
                    AuthorizationRequest.Builder(
                        serviceConfiguration,
                        CLIENT_ID,
                        ResponseTypeValues.CODE,
                        REDIRECT_URI.toUri()
                    )
                        .setScopes("openid")
                        .setCodeVerifier(codeVerifier, codeChallenge, codeVerifierChallengeMethod)
                        .setPrompt("login")
                        .build()

                authService.performAuthorizationRequest(
                    authRequest,
                    PendingIntent.getActivity(context, 0, Intent(context, AuthFlowIn::class.java), PendingIntent.FLAG_MUTABLE),
                    PendingIntent.getActivity(context, 0, Intent(context, AuthFlowIn::class.java), PendingIntent.FLAG_MUTABLE)
                )
            })
    }
}
