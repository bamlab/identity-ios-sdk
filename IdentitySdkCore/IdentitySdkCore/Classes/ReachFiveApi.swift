import Alamofire
import BrightFutures

public class ReachFiveApi {
    let decoder = JSONDecoder()
    let sdkConfig: SdkConfig
    
    private let profile_fields = [
        "birthdate",
        "bio",
        "middle_name",
        "addresses",
        "auth_types",
        "consents",
        "created_at",
        "custom_fields",
        "devices",
        "company",
        "email",
        "emails",
        "email_verified",
        "external_id",
        "family_name",
        "first_login",
        "first_name",
        "full_name",
        "gender",
        "given_name",
        "has_managed_profile",
        "has_password",
        "id",
        "identities",
        "last_login",
        "last_login_provider",
        "last_login_type",
        "last_name",
        "likes_friends_ratio",
        "lite_only",
        "locale",
        "local_friends_count",
        "login_summary",
        "logins_count",
        "name",
        "nickname",
        "origins",
        "picture",
        "phone_number",
        "phone_number_verified",
        "custom_identifier",
        "provider_details",
        "providers",
        "social_identities",
        "sub",
        "uid",
        "updated_at"
    ]
    
    let deviceInfo: String = "\(UIDevice.current.modelName) \(UIDevice.current.systemName) \(UIDevice.current.systemVersion)"
        .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
    
    //TODO read from the version.rb. Either directly or indirectly from IdentitySdkCore.h, Info.plist...
    let sdk = "5.8.0"
    
    public init(sdkConfig: SdkConfig) {
        self.sdkConfig = sdkConfig
        decoder.keyDecodingStrategy = .convertFromSnakeCase
    }
    
    public func clientConfig() -> Future<ClientConfigResponse, ReachFiveError> {
        AF
            .request(createUrl(path: "/identity/v1/config?platform=ios&sdk=\(sdk)&device=\(deviceInfo)&client_id=\(sdkConfig.clientId)"))
            .validate(statusCode: 200..<300)
            .validate(contentType: ["application/json"])
            .responseJson(type: ClientConfigResponse.self, decoder: decoder)
    }
    
    public func providersConfigs() -> Future<ProvidersConfigsResult, ReachFiveError> {
        AF
            .request(createUrl(path: "/api/v1/providers?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"))
            .validate(statusCode: 200..<300)
            .validate(contentType: ["application/json"])
            .responseJson(type: ProvidersConfigsResult.self, decoder: decoder)
    }
    
    public func loginWithProvider(
        loginProviderRequest: LoginProviderRequest
    ) -> Future<AccessTokenResponse, ReachFiveError> {
        let origin: String = loginProviderRequest.origin ?? ""
        AF
            .request(createUrl(path: "/identity/v1/oauth/provider/token?platform=ios?origin=\(origin)&sdk=\(sdk)&device=\(deviceInfo)"), method: .post, parameters: loginProviderRequest.dictionary(), encoding: JSONEncoding.default)
            .validate(statusCode: 200..<300)
            .validate(contentType: ["application/json"])
            .responseJson(type: AccessTokenResponse.self, decoder: decoder)
    }
    
    public func signupWithPassword(signupRequest: SignupRequest) -> Future<AccessTokenResponse, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/signup-token?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: signupRequest.dictionary(),
                encoding: JSONEncoding.default
            )
            .validate(contentType: ["application/json"])
            .responseJson(type: AccessTokenResponse.self, decoder: decoder)
    }
    
    public func loginWithPassword(loginRequest: LoginRequest) -> Future<AuthenticationToken, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/password/login?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: loginRequest.dictionary(),
                encoding: JSONEncoding.default
            )
            .validate(contentType: ["application/json"])
            .responseJson(type: AuthenticationToken.self, decoder: decoder)
    }
    
    public func loginCallback(loginCallback: LoginCallback) -> Future<String, ReachFiveError> {
        let promise = Promise<String, ReachFiveError>()
        
        AF
            .request(
                createUrl(path: "/oauth/authorize?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .get,
                parameters: loginCallback.dictionary()
            )
            .redirect(using: Redirector.doNotFollow)
            .validate(statusCode: 300...308) //TODO pas de 305/306
            .response { responseData in
                let callbackURL = responseData.response?.allHeaderFields["Location"] as? String
                guard let callbackURL else {
                    promise.failure(.TechnicalError(reason: "No location"))
                    return
                }
                let queryItems = URLComponents(string: callbackURL)?.queryItems
                let code = queryItems?.first(where: { $0.name == "code" })?.value
                guard let code else {
                    promise.failure(.TechnicalError(reason: "No authorization code"))
                    return
                }
                promise.success(code)
            }
        return promise.future
    }
    
    public func authWithCode(authCodeRequest: AuthCodeRequest) -> Future<AccessTokenResponse, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/oauth/token?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: authCodeRequest.dictionary(),
                encoding: JSONEncoding.default
            )
            .validate(statusCode: 200..<300)
            .validate(contentType: ["application/json"])
            .responseJson(type: AccessTokenResponse.self, decoder: decoder)
    }
    
    public func refreshAccessToken(_ refreshRequest: RefreshRequest) -> Future<AccessTokenResponse, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/oauth/token?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: refreshRequest.dictionary(),
                encoding: JSONEncoding.default
            )
            .validate(statusCode: 200..<300)
            .validate(contentType: ["application/json"])
            .responseJson(type: AccessTokenResponse.self, decoder: decoder)
    }
    
    public func getProfile(authToken: AuthToken) -> Future<Profile, ReachFiveError> {
        AF
            .request(
                createUrl(
                    path: "/identity/v1/userinfo?platform=ios&sdk=\(sdk)&device=\(deviceInfo)&fields=\(profile_fields.joined(separator: ","))"
                ),
                method: .get,
                headers: tokenHeader(authToken)
            )
            .validate(statusCode: 200..<300)
            .validate(contentType: ["application/json"])
            .responseJson(type: Profile.self, decoder: decoder)
    }
    
    public func verifyPhoneNumber(
        authToken: AuthToken,
        verifyPhoneNumberRequest: VerifyPhoneNumberRequest
    ) -> Future<(), ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/verify-phone-number?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: verifyPhoneNumberRequest.dictionary(),
                encoding: JSONEncoding.default,
                headers: tokenHeader(authToken)
            )
            .validate(contentType: ["application/json"])
            .responseJson(decoder: decoder)
    }
    
    public func updateEmail(
        authToken: AuthToken,
        updateEmailRequest: UpdateEmailRequest
    ) -> Future<Profile, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/update-email?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: updateEmailRequest.dictionary(),
                encoding: JSONEncoding.default,
                headers: tokenHeader(authToken)
            )
            .validate(statusCode: 200..<300)
            .validate(contentType: ["application/json"])
            .responseJson(type: Profile.self, decoder: decoder)
    }
    
    public func updateProfile(
        authToken: AuthToken,
        profile: Profile
    ) -> Future<Profile, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/update-profile?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: profile.dictionary(),
                encoding: JSONEncoding.default,
                headers: tokenHeader(authToken)
            )
            .validate(statusCode: 200..<300)
            .validate(contentType: ["application/json"])
            .responseJson(type: Profile.self, decoder: decoder)
    }
    
    public func updatePassword(
        authToken: AuthToken?,
        updatePasswordRequest: UpdatePasswordRequest
    ) -> Future<(), ReachFiveError> {
        let headers: HTTPHeaders = authToken != nil ? tokenHeader(authToken!) : [:]
        return AF
            .request(
                createUrl(path: "/identity/v1/update-password?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: updatePasswordRequest.dictionary(),
                encoding: JSONEncoding.default,
                headers: headers
            )
            .validate(contentType: ["application/json"])
            .responseJson(decoder: decoder)
    }
    
    public func updatePhoneNumber(
        authToken: AuthToken,
        updatePhoneNumberRequest: UpdatePhoneNumberRequest
    ) -> Future<Profile, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/update-phone-number?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: updatePhoneNumberRequest.dictionary(),
                encoding: JSONEncoding.default,
                headers: tokenHeader(authToken)
            )
            .validate(contentType: ["application/json"])
            .responseJson(type: Profile.self, decoder: decoder)
    }
    
    public func requestPasswordReset(
        requestPasswordResetRequest: RequestPasswordResetRequest
    ) -> Future<(), ReachFiveError> {
        AF
            .request(createUrl(
                path: "/identity/v1/forgot-password?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: requestPasswordResetRequest.dictionary(),
                encoding: JSONEncoding.default
            )
            .validate(contentType: ["application/json"])
            .responseJson(decoder: decoder)
    }
    
    public func startPasswordless(_ startPasswordlessRequest: StartPasswordlessRequest) -> Future<(), ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/passwordless/start?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: startPasswordlessRequest.dictionary(),
                encoding: JSONEncoding.default
            )
            .validate(statusCode: 200..<300)
            .responseJson(decoder: decoder)
    }
    
    public func verifyPasswordless(verifyPasswordlessRequest: VerifyPasswordlessRequest) -> Future<PasswordlessVerifyResponse, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/passwordless/verify?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: verifyPasswordlessRequest.dictionary()
            )
            .validate(statusCode: 200..<300)
            .responseJson(type: PasswordlessVerifyResponse.self, decoder: decoder)
    }
    
    public func verifyAuthCode(verifyAuthCodeRequest: VerifyAuthCodeRequest) -> Future<(), ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/verify-auth-code?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: verifyAuthCodeRequest.dictionary(),
                encoding: JSONEncoding.default
            )
            .validate(statusCode: 200..<300)
            .responseJson(decoder: decoder)
    }
    
    public func logout() -> Future<(), ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/logout?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .get
            )
            .validate(statusCode: 200..<300)
            .responseJson(decoder: decoder)
    }
    
    func tokenHeader(_ authToken: AuthToken) -> HTTPHeaders {
        ["Authorization": "\(authToken.tokenType ?? "Bearer") \(authToken.accessToken)"]
    }
    
    func createUrl(path: String) -> String {
        "https://\(sdkConfig.domain)\(path)"
    }
    
    public func buildAuthorizeURL(queryParams: [String: String]) -> URL {
        let request = try! URLRequest.init(url: createUrl(path: "/oauth/authorize?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"), method: .get, headers: nil)
        let encodedURLRequest = try! URLEncoding.queryString.encode(request, with: queryParams)
        return encodedURLRequest.url!
    }
    
    public func createWebAuthnSignupOptions(webAuthnSignupOptions: SignupOptions) -> Future<RegistrationOptions, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/webauthn/signup-options?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: webAuthnSignupOptions.dictionary(),
                encoding: JSONEncoding.default
            )
            .validate(contentType: ["application/json"])
            .responseJson(type: RegistrationOptions.self, decoder: decoder)
    }
    
    public func signupWithWebAuthn(webauthnSignupCredential: WebauthnSignupCredential) -> Future<AuthenticationToken, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/webauthn/signup?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: webauthnSignupCredential.dictionary(),
                encoding: JSONEncoding.default
            )
            .validate(contentType: ["application/json"])
            .responseJson(type: AuthenticationToken.self, decoder: decoder)
    }
    
    public func createWebAuthnAuthenticationOptions(webAuthnLoginRequest: WebAuthnLoginRequest) -> Future<AuthenticationOptions, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/webauthn/authentication-options?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: webAuthnLoginRequest.dictionary(),
                encoding: JSONEncoding.default
            )
            .validate(contentType: ["application/json"])
            .responseJson(type: AuthenticationOptions.self, decoder: decoder)
    }
    
    public func authenticateWithWebAuthn(authenticationPublicKeyCredential: AuthenticationPublicKeyCredential) -> Future<AuthenticationToken, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/webauthn/authentication?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: authenticationPublicKeyCredential.dictionary(),
                encoding: JSONEncoding.default
            )
            .validate(contentType: ["application/json"])
            .responseJson(type: AuthenticationToken.self, decoder: decoder)
    }
    
    public func createWebAuthnRegistrationOptions(authToken: AuthToken, registrationRequest: RegistrationRequest) -> Future<RegistrationOptions, ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/webauthn/registration-options?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: registrationRequest.dictionary(),
                encoding: JSONEncoding.default,
                headers: tokenHeader(authToken)
            )
            .validate(contentType: ["application/json"])
            .responseJson(type: RegistrationOptions.self, decoder: decoder)
    }
    
    public func registerWithWebAuthn(authToken: AuthToken, publicKeyCredential: RegistrationPublicKeyCredential) -> Future<(), ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/webauthn/registration?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .post,
                parameters: publicKeyCredential.dictionary(),
                encoding: JSONEncoding.default,
                headers: tokenHeader(authToken)
            )
            .validate(contentType: ["application/json"])
            .responseJson(decoder: decoder)
    }
    
    public func getWebAuthnRegistrations(authToken: AuthToken) -> Future<[DeviceCredential], ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/webauthn/registration?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .get,
                encoding: JSONEncoding.default,
                headers: tokenHeader(authToken)
            )
            .validate(contentType: ["application/json"])
            .responseJson(type: [DeviceCredential].self, decoder: decoder)
    }
    
    public func deleteWebAuthnRegistration(id: String, authToken: AuthToken) -> Future<(), ReachFiveError> {
        AF
            .request(
                createUrl(path: "/identity/v1/webauthn/registration/\(id)?platform=ios&sdk=\(sdk)&device=\(deviceInfo)"),
                method: .delete,
                encoding: JSONEncoding.default,
                headers: tokenHeader(authToken)
            )
            .validate(contentType: ["application/json"])
            .responseJson(decoder: decoder)
    }
}
