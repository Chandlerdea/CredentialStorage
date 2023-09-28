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
    ///     - isDefault: Whether the token is the default credentail for the URL's protection space
    ///     - persistence: How long the token should be persisted. When this is `nil`, the default store will use `.permanent`
    public var storeToken: (_ token: String, _ user: String, _ url: URL, _ isDefault: Bool, _ persistence: URLCredential.Persistence?) throws -> Void

    /// Removes a token for a `URL`
    /// - Parameters
    ///     - url: THe `URL` of the associated auth token
    public var removeTokens: (_ url: URL) throws -> Void

    /// Retrieves an auth token for a `URL`
    /// - Returns: A dictionary where the keys are the users and the values are the tokens
    /// - Parameters
    ///     - url: The `URL` associated with the auth token
    public var tokens: (_ url: URL) throws -> [String: String]
}

extension CredentialStore {
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

public extension CredentialStore {

    /// Uses Apple's `URLCredentialStorage` to store and retreive `URLCredential` instances. This assumes the urls are using SSL (https).
    static var `default`: Self {
        let storage = URLCredentialStorage.shared
        return .init(
            storeToken: { token, user, url, isDefault, persistence in
                guard let host = url.host else {
                    throw Error.noURLHost(url)
                }
                let protectionSpace = try Self.protectionSpace(for: host, url: url)
                let credential = URLCredential(user: user, password: token, persistence: persistence ?? .permanent)
                if isDefault {
                    storage.setDefaultCredential(credential, for: protectionSpace)
                } else {
                    storage.set(credential, for: protectionSpace)
                }
                NotificationCenter.default.post(name: .NSURLCredentialStorageChanged, object: storage)
            },
            removeTokens: { url in
                guard let host = url.host else {
                    throw Error.noURLHost(url)
                }
                let protectionSpace = try Self.protectionSpace(for: host, url: url)
                guard let credentials = storage.credentials(for: protectionSpace) else {
                    return
                }
                for (_, credential) in credentials {
                    storage.remove(credential, for: protectionSpace)
                }
                NotificationCenter.default.post(name: .NSURLCredentialStorageChanged, object: storage)
            },
            tokens: { url in
                guard let host = url.host else {
                    throw Error.noURLHost(url)
                }
                let protectionSpace = try Self.protectionSpace(for: host, url: url)
                guard let credentials = storage.credentials(for: protectionSpace) else {
                    return [:]
                }
                return credentials.compactMapValues(\.password)
            }
        )
    }
}

