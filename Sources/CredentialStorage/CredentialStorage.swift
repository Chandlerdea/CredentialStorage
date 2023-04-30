import Foundation

/// A protocol witness for storing credentials from APIs using the HTTP protocol.
/// Only urls using the HTTP protocol are supported currently.
public struct CredentialStore {
    enum Error: Swift.Error {
        case unsupportedURLScheme(String?)
        case noURLHost(URL)
    }

    /// Stores an auth token for a `URL`
    /// - Parameters:
    ///     - token: The auth token to store
    ///     - user: The user owning the auth token. This is usually the username or email belonging to the password. For auth tokens, you can use whatever description you want.
    ///     - url: The `URL` associated with the auth token
    ///     - persistence: How long the token should be persisted. When this is `nil`, the default store will use `.permanent`
    var storeToken: (_ token: String, _ user: String, _ url: URL, _ persistence: URLCredential.Persistence?) throws -> Void

    /// Removes a token for a `URL`
    /// - Parameters
    ///     - url: THe `URL` of the associated auth token
    var removeToken: (_ url: URL) throws -> Void

    /// Retrieves an auth token for a `URL`
    /// - Parameters
    ///     - url: The `URL` associated with the auth token
    var token: (_ url: URL) throws -> String?
}

private extension CredentialStore {
    static func protectionSpace(for host: String, url: URL) throws -> URLProtectionSpace {
        guard let scheme = url.supportedScheme, url.isSchemeSupported else {
            throw Error.unsupportedURLScheme(url.scheme)
        }
        return URLProtectionSpace(
            host: host,
            port: scheme.isSecure ? 443 : 80,
            protocol: scheme.isSecure ? NSURLProtectionSpaceHTTPS : NSURLProtectionSpaceHTTP,
            realm: nil,
            authenticationMethod: NSURLAuthenticationMethodHTTPBasic
        )
    }
}

extension CredentialStore {

    /// Uses Apple's `URLCredentialStorage` to store and retreive `URLCredential` instances. This assumes the urls are using SSL (https).
    static var `default`: Self {
        .init(
            storeToken: { token, user, url, _ in
                guard let host = url.host else {
                    throw Error.noURLHost(url)
                }
                let protectionSpace = try Self.protectionSpace(for: host, url: url)
                let credential = URLCredential(user: user, password: token, persistence: .permanent)
                URLCredentialStorage.shared.setDefaultCredential(credential, for: protectionSpace)
                NotificationCenter.default.post(name: .NSURLCredentialStorageChanged, object: URLCredentialStorage.shared)
            },
            removeToken: { url in
                guard let host = url.host else {
                    throw Error.noURLHost(url)
                }
                let protectionSpace = try Self.protectionSpace(for: host, url: url)
                guard let credential = URLCredentialStorage.shared.defaultCredential(for: protectionSpace) else {
                    return
                }
                URLCredentialStorage.shared.remove(credential, for: protectionSpace)
                NotificationCenter.default.post(name: .NSURLCredentialStorageChanged, object: URLCredentialStorage.shared)
            },
            token: { url in
                guard let host = url.host else {
                    throw Error.noURLHost(url)
                }
                let protectionSpace = try Self.protectionSpace(for: host, url: url)
                let credential = URLCredentialStorage.shared.defaultCredential(for: protectionSpace)
                return credential?.password
            }
        )
    }
}

