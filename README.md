# CredentialStorage

`CredentialStorage` is a package that uses Apple's `URLCredentialStorage` APIs to store tokens and passwords in the user's keychain without the boilerplate associated with creating `URLCredential`s and `URLProtectionSpace`s.

As of now, the package only supports basic HTTP authentication with passwords.

## How to use

### Saving credentials

```swift
let loginURL = ...
let someToken...
let store = CredentialStore.default
try store.storeToken(someToken, userEmail, loginURL, nil)
```
Passing `nil` as the last parameter will use `URLCredential.Persistence.permanent` and store the token in the user's keychain.

### Using credentials

```swift
let credentialURL = ...
let store = CredentialStore.default
if let token = try store.token(credentialURL) {
    ...
}
```

### Removing credentials

```swift
let credentialURL = ...
let store = CredentialStore.default
try store.removeToken(credentialURL)
```
