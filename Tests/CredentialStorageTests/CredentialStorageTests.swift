import XCTest
@testable import CredentialStorage

final class CredentialStorageTests: XCTestCase {
    let store: CredentialStore = .default
    let supportedURL = URL(string: "https://www.google.com")!
    let unsupportedSchemeURL = URL(string: "facetime://www.google.com")!
    let fileURL = URL(string: "file:///usr/bin")!

    func createAndAddToken(for url: URL) throws {
        try store.storeToken(
            "1234",
            "me@gmail.com",
            url,
            .forSession
        )
    }

    func testStoreAddsCredential() throws {
        try createAndAddToken(for: supportedURL)
        let token = try store.token(supportedURL)
        XCTAssertTrue(token == "1234")
    }

    func testStoreRemovesCredential() throws {
        try createAndAddToken(for: supportedURL)
        try store.removeToken(supportedURL)
        let token = try store.token(supportedURL)
        XCTAssertNil(token)
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
            try store.removeToken(unsupportedSchemeURL)
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
            try store.removeToken(fileURL)
        } catch CredentialStore.Error.noURLHost(let url) {
            XCTAssertEqual(url, fileURL)
        }
    }
}
