import XCTest
@testable import CredentialStorage

final class CredentialStorageTests: XCTestCase {
    let store: CredentialStore = .default
    let supportedURL = URL(string: "https://www.google.com")!
    let unsupportedSchemeURL = URL(string: "facetime://www.google.com")!
    let fileURL = URL(string: "file:///usr/bin")!

    var protectionSpace: URLProtectionSpace {
        try! CredentialStore.protectionSpace(for: supportedURL.host()!, url: supportedURL)
    }

    var storage: URLCredentialStorage {
        URLCredentialStorage.shared
    }

    func createAndAddToken(
        for url: URL,
        isDefault: Bool = false
    ) throws {
        try store.storeToken(
            "1234",
            "me@gmail.com",
            url,
            isDefault,
            .forSession
        )
    }

    override class func tearDown() {
        super.tearDown()
        let supportedURL = URL(string: "https://www.google.com")!
        let protectionSpace = try! CredentialStore.protectionSpace(for: supportedURL.host()!, url: supportedURL)
        if let allCredentials = URLCredentialStorage.shared.credentials(for: protectionSpace) {
            for (_, credential) in allCredentials {
                URLCredentialStorage.shared.remove(credential, for: protectionSpace)
            }
        }
    }

    func testStoreAddsDefaultCredential() throws {
        try createAndAddToken(for: supportedURL, isDefault: true)
        let credential = storage.defaultCredential(for: protectionSpace)
        XCTAssertTrue(credential?.password == "1234")
    }

    func testStoreAddsCredential() throws {
        try createAndAddToken(for: supportedURL)
        let credentials = storage.credentials(for: protectionSpace)
        XCTAssertEqual(credentials?.count, 1)
        XCTAssertEqual(credentials?["me@gmail.com"]?.password, "1234")
    }

    func testStoreRemovesCredential() throws {
        try createAndAddToken(for: supportedURL)
        try CredentialStore.default.removeTokens(supportedURL)
        let credentials = storage.credentials(for: protectionSpace)
        XCTAssertNil(credentials)
    }

    func testStoreReturnsAllTokens() throws {
        let credential1 = URLCredential(user: "user1", password: "1", persistence: .forSession)
        let credential2 = URLCredential(user: "user2", password: "2", persistence: .forSession)
        storage.set(credential1, for: protectionSpace)
        storage.set(credential2, for: protectionSpace)
        let tokens = try CredentialStore.default.tokens(supportedURL)
        XCTAssertEqual(tokens["user1"], "1")
        XCTAssertEqual(tokens["user2"], "2")
    }

    func testUnsupportedURLCannotAddCredential() throws {
        do {
            try createAndAddToken(for: unsupportedSchemeURL)
        } catch CredentialStore.Error.unsupportedURLScheme(let scheme) {
            XCTAssertEqual(scheme, "facetime")
        }
    }

    func testUnsupportedURLCannotRemoveCredential() throws {
        try createAndAddToken(for: supportedURL)
        do {
            try store.removeTokens(unsupportedSchemeURL)
        } catch CredentialStore.Error.unsupportedURLScheme(let scheme) {
            XCTAssertEqual(scheme, "facetime")
        }
    }

    func testFileURLCannotAddCredential() throws {
        do {
            try createAndAddToken(for: fileURL)
        } catch CredentialStore.Error.noURLHost(let url) {
            XCTAssertEqual(url, fileURL)
        }
    }

    func testFileURLCannotRemoveCredential() throws {
        try createAndAddToken(for: supportedURL)
        do {
            try store.removeTokens(fileURL)
        } catch CredentialStore.Error.noURLHost(let url) {
            XCTAssertEqual(url, fileURL)
        }
    }
}
