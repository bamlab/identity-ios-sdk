import Foundation
import SafariServices
import IdentitySdkCore
import BrightFutures
import AuthenticationServices

public class WebViewProvider: ProviderCreator {
    public static let NAME = "webview"
    
    public var name: String = NAME
    
    public init() {}
    
    public func create(
        sdkConfig: SdkConfig,
        providerConfig: ProviderConfig,
        reachFiveApi: ReachFiveApi,
        clientConfigResponse: ClientConfigResponse
    ) -> Provider {
        ConfiguredWebViewProvider(
            sdkConfig: sdkConfig,
            providerConfig: providerConfig,
            reachFiveApi: reachFiveApi,
            clientConfigResponse: clientConfigResponse
        )
    }
}

class ConfiguredWebViewProvider: NSObject, Provider {
    var name: String = WebViewProvider.NAME
    
    let sdkConfig: SdkConfig
    let providerConfig: ProviderConfig
    let reachFiveApi: ReachFiveApi
    let clientConfigResponse: ClientConfigResponse
    var session: ASWebAuthenticationSession?
    
    public init(
        sdkConfig: SdkConfig,
        providerConfig: ProviderConfig,
        reachFiveApi: ReachFiveApi,
        clientConfigResponse: ClientConfigResponse
    ) {
        self.sdkConfig = sdkConfig
        self.providerConfig = providerConfig
        self.reachFiveApi = reachFiveApi
        self.name = providerConfig.provider
        self.clientConfigResponse = clientConfigResponse
    }
    
    public func login(
        scope: [String]?,
        origin: String,
        viewController: UIViewController?
    ) -> Future<AuthToken, ReachFiveError> {
        let promise = Promise<AuthToken, ReachFiveError>()
        
        guard let viewController = viewController else {
            promise.failure(.TechnicalError(reason: "No presenting viewController"))
            return promise.future
        }
        
        let pkce = Pkce.generate()
        let url = buildUrl(
            sdkConfig: sdkConfig,
            providerConfig: providerConfig,
            scope: scope != nil ? scope!.joined(separator: " ") : clientConfigResponse.scope,
            pkce: pkce
        )
        
        guard let authURL = URL(string: url) else {
            promise.failure(.TechnicalError(reason: "Cannot build authorize URL"))
            return promise.future
        }
        
        session = ASWebAuthenticationSession(url: authURL, callbackURLScheme: "reachfive-\(sdkConfig.clientId)") { callbackURL, error in
            guard error == nil else {
                let r5Error: ReachFiveError
                switch error!._code {
                case 1: r5Error = .AuthCanceled
                case 2: r5Error = .TechnicalError(reason: "Presentation Context Not Provided")
                case 3: r5Error = .TechnicalError(reason: "Presentation Context Invalid")
                default:
                    r5Error = .TechnicalError(reason: "Unknown Error")
                }
                promise.failure(r5Error)
                return
            }
            
            guard let callbackURL = callbackURL else {
                promise.failure(.TechnicalError(reason: "No callback URL"))
                return
            }
            
            let queryItems = URLComponents(string: callbackURL.absoluteString)?.queryItems
            let code = queryItems?.first(where: { $0.name == "code" })?.value
            guard let code = code else {
                promise.failure(.TechnicalError(reason: "No authorization code"))
                return
            }
            
            promise.completeWith(self.handleAuthCode(code: code, pkce: pkce))
        }
        
        // Set an appropriate context provider instance that determines the window that acts as a presentation anchor for the session
        session?.presentationContextProvider = (viewController as! ASWebAuthenticationPresentationContextProviding)
        
        // Start the Authentication Flow
        session?.start()
        return promise.future
    }
    
    private func handleAuthCode(code: String, pkce: Pkce) -> Future<AuthToken, ReachFiveError> {
        let authCodeRequest = AuthCodeRequest(
            clientId: sdkConfig.clientId,
            code: code,
            redirectUri: sdkConfig.scheme,
            pkce: pkce
        )
        return reachFiveApi.authWithCode(authCodeRequest: authCodeRequest)
            .flatMap({ AuthToken.fromOpenIdTokenResponseFuture($0) })
    }
    
    public func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
        true
    }
    
    func application(_ application: UIApplication, open url: URL, sourceApplication: String?, annotation: Any) -> Bool {
        true
    }
    
    public func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        true
    }
    
    public func applicationDidBecomeActive(_ application: UIApplication) {
    }
    
    public func logout() -> Future<(), ReachFiveError> {
        Future(value: ())
    }
    
    func buildUrl(sdkConfig: SdkConfig, providerConfig: ProviderConfig, scope: String, pkce: Pkce) -> String {
        let params = [
            "provider": providerConfig.provider,
            "client_id": sdkConfig.clientId,
            "response_type": "code",
            "redirect_uri": sdkConfig.scheme,
            "scope": scope,
            "platform": "ios",
            "code_challenge": pkce.codeChallenge,
            "code_challenge_method": pkce.codeChallengeMethod,
        ]
        let queryStrings = params
            .map { "\($0)=\($1)" }
            .map { $0.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) }
            .filter { $0 != nil }
            .map { $0! }
            .joined(separator: "&")
        return "https://\(sdkConfig.domain)/oauth/authorize?\(queryStrings)"
    }
    
    override var description: String {
        "Provider: \(name)"
    }
}
