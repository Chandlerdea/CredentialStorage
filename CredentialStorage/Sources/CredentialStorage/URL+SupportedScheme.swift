import Foundation

extension URL {
    enum SupportedScheme: String, CaseIterable {
        case http
        case https

        var isSecure: Bool {
            switch self {
            case .http:
                return false
            case .https:
                return true
            }
        }
    }

    var isSchemeSupported: Bool {
        guard let supportedScheme else {
            return false
        }
        return SupportedScheme.allCases.contains(supportedScheme)
    }

    var supportedScheme: SupportedScheme? {
        scheme.flatMap(SupportedScheme.init(rawValue:))
    }
}
