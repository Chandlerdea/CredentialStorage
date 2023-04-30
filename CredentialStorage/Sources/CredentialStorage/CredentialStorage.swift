import Foundation

/// A protocol witness for storing credentials from APIs using the HTTP protocol
public struct CredentialStore {
    /// Stores an auth token for a `URL`
    /// - Parameters:
    ///     - token: The auth token to store
    ///     - user: The user owning the auth token
    ///     - url: The `URL` associated with the auth token
    ///     - persistence: How long the token should be persisted. When this is `nil`, the default store will use `.permanent`
    ///     - isSecure: Whether the URL is secured via SSL (https) or not (http). When this is `nil`, the url is assumed ot be using https.
    var storeToken: (_ token: String, _ user: String, _ url: URL, _ persistence: URLCredential.Persistence?, _ isSecure: Bool?) -> Void

    /// Removes a token for a `URL`
    /// - Parameters
    ///     - url: THe `URL` of the associated auth token
    ///     - isSecure: Whether the URL is secured via SSL (https) or not (http). When this is `nil`, the url is assumed ot be using https.
    var removeToken: (_ url: URL, _ isSecure: Bool?) -> Void

    /// Retrieves an auth token for a `URL`
    /// - Parameters
    ///     - url: The `URL` associated with the auth token
    ///     - isSecure: Whether the URL is secured via SSL (https) or not (http). When this is `nil`, the url is assumed ot be using https.
    var token: (_ url: URL, _ isSecure: Bool?) -> String?
}

private extension CredentialStore {
    static func protectionSpace(for host: String, isSecure: Bool?) -> URLProtectionSpace {
        let isUsingHTTP = isSecure == false
        return URLProtectionSpace(
            host: host,
            port: isUsingHTTP ? 80 : 443,
            protocol: isUsingHTTP ? NSURLProtectionSpaceHTTP : NSURLProtectionSpaceHTTPS,
            realm: nil,
            authenticationMethod: NSURLAuthenticationMethodHTTPBasic
        )
    }
}

extension CredentialStore {

    /// Uses Apple's `URLCredentialStorage` to store and retreive `URLCredential` instances. This assumes the urls are using SSL (https).
    static var `default`: Self {
        .init(
            storeToken: { token, user, url, _, isSecure in
                precondition(url.host(percentEncoded: false) != nil, "Expected host for credential for url: \(url.absoluteString)")
                guard let host = url.host else {
                    return
                }
                let protectionSpace = Self.protectionSpace(for: host, isSecure: isSecure)
                let credential = URLCredential(user: user, password: token, persistence: .permanent)
                URLCredentialStorage.shared.setDefaultCredential(credential, for: protectionSpace)
                NotificationCenter.default.post(name: .NSURLCredentialStorageChanged, object: URLCredentialStorage.shared)
            },
            removeToken: { url, isSecure in
                precondition(url.host(percentEncoded: false) != nil, "Expected host for credential for url: \(url.absoluteString)")
                guard let host = url.host else {
                    return
                }
                let protectionSpace = Self.protectionSpace(for: host, isSecure: isSecure)
                guard let credential = URLCredentialStorage.shared.defaultCredential(for: protectionSpace) else {
                    return
                }
                URLCredentialStorage.shared.remove(credential, for: protectionSpace)
                NotificationCenter.default.post(name: .NSURLCredentialStorageChanged, object: URLCredentialStorage.shared)
            },
            token: { url, isSecure in
                precondition(url.host(percentEncoded: false) != nil, "Expected host for credential for url: \(url.absoluteString)")
                guard let host = url.host else {
                    return nil
                }
                let protectionSpace = Self.protectionSpace(for: host, isSecure: isSecure)
                let credential = URLCredentialStorage.shared.defaultCredential(for: protectionSpace)
                return credential?.password
            }
        )
    }
}

