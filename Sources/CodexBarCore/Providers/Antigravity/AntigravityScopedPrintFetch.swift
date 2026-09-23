#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif
import Foundation

// MARK: - agy file token storage payload

/// JSON payload of the `fileTokenStorage` fallback file that `agy` maintains at
/// `<home>/.gemini/antigravity-cli/antigravity-oauth-token`. `agy`'s composite token
/// storage reads this file whenever the OS keyring is unavailable, so a staged `HOME`
/// scopes the account without touching the user's Keychain item.
struct AntigravityAgyFileTokenPayload: Codable, Equatable, Sendable {
    struct Token: Codable, Equatable, Sendable {
        let accessToken: String
        let tokenType: String
        let refreshToken: String
        let expiry: String

        enum CodingKeys: String, CodingKey {
            case accessToken = "access_token"
            case tokenType = "token_type"
            case refreshToken = "refresh_token"
            case expiry
        }
    }

    let token: Token
    let authMethod: String
    let idToken: String?

    enum CodingKeys: String, CodingKey {
        case token
        case authMethod = "auth_method"
        case idToken = "id_token"
    }
}

enum AntigravityAgyFileTokenEncoder {
    static func encode(credentials: AntigravityOAuthCredentials) -> Data? {
        guard let accessToken = credentials.accessToken?.trimmingCharacters(in: .whitespacesAndNewlines),
              !accessToken.isEmpty,
              let refreshToken = credentials.refreshToken?.trimmingCharacters(in: .whitespacesAndNewlines),
              !refreshToken.isEmpty,
              let expiryDate = credentials.expiryDate
        else {
            return nil
        }

        let payload = AntigravityAgyFileTokenPayload(
            token: .init(
                accessToken: accessToken,
                tokenType: "Bearer",
                refreshToken: refreshToken,
                expiry: expiryString(for: expiryDate)),
            authMethod: "consumer",
            idToken: credentials.idToken)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try? encoder.encode(payload)
    }

    static func decode(data: Data) -> AntigravityAgyFileTokenPayload? {
        try? JSONDecoder().decode(AntigravityAgyFileTokenPayload.self, from: data)
    }

    private static func expiryString(for date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }
}

// MARK: - Scoped staging

enum AntigravityScopedStagingError: LocalizedError, Sendable, Equatable {
    case credentialsMissingRequiredFields
    case identityUnverifiable

    var errorDescription: String? {
        switch self {
        case .credentialsMissingRequiredFields:
            "Antigravity account credentials lack required token or expiry fields."
        case .identityUnverifiable:
            "Antigravity scoped credentials could not be verified against the selected account."
        }
    }
}

/// Stages the selected account's credentials into a fresh private `HOME` for a
/// single `agy` print invocation. The directory is deleted by the caller's `defer`,
/// so no account lifecycle tracking, locking, or persistent credential copies exist.
enum AntigravityScopedAgyStaging {
    // Provider-specific by design: agy's file token storage path is a fixed external contract.
    static let tokenRelativePath = [".gemini", "antigravity-cli", "antigravity-oauth-token"]

    /// Allowlist environment for the scoped child. Nothing else is inherited:
    /// injected credentials, other providers' tokens, and ambient tool settings
    /// cannot leak into the `agy` process. A non-empty `SSH_TTY` makes `agy`
    /// select file-based token storage outright, so it never consults the OS keyring.
    static func childEnvironment(
        from environment: [String: String],
        home: URL) -> [String: String]
    {
        var child: [String: String] = [:]
        for key in [
            "PATH",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ] {
            if let value = environment[key]?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty {
                child[key] = value
            }
        }
        child["PATH"] = PathBuilder.effectivePATH(
            purposes: [.tty], env: child, loginPATH: LoginShellPathCache.shared.current)
        child["HOME"] = home.path
        child["PWD"] = home.path
        child["SSH_TTY"] = "codexbar-scoped"
        return child
    }

    /// Creates a fresh 0700 staging directory, writes the token file, then
    /// re-reads and verifies that the staged `id_token` claim belongs to the
    /// expected account — the identity `agy` will act as is proven from the
    /// bytes it will read, not from the caller's label.
    static func stage(
        credentials: AntigravityOAuthCredentials,
        expectedAccountEmail: String,
        fileManager: FileManager = .default) throws -> (stagingRoot: URL, home: URL)
    {
        guard let tokenData = AntigravityAgyFileTokenEncoder.encode(credentials: credentials) else {
            throw AntigravityScopedStagingError.credentialsMissingRequiredFields
        }
        let root = fileManager.temporaryDirectory
            .appendingPathComponent("codexbar-agy-scoped-" + UUID().uuidString, isDirectory: true)
        let home = root.appendingPathComponent("home", isDirectory: true)
        do {
            try fileManager.createDirectory(
                at: home, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            var tokenURL = home
            for component in Self.tokenRelativePath.dropLast() {
                tokenURL.appendPathComponent(component, isDirectory: true)
            }
            try fileManager.createDirectory(
                at: tokenURL, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            tokenURL.appendPathComponent(Self.tokenRelativePath.last!)
            try tokenData.write(to: tokenURL, options: [.atomic])
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenURL.path)

            guard let staged = try? Data(contentsOf: tokenURL),
                  let payload = AntigravityAgyFileTokenEncoder.decode(data: staged),
                  Self.normalizedEmail(
                      AntigravityOAuthCredentials.email(fromIDToken: payload.idToken)) ==
                  Self.normalizedEmail(expectedAccountEmail)
            else {
                throw AntigravityScopedStagingError.identityUnverifiable
            }
            return (root, home)
        } catch {
            try? fileManager.removeItem(at: root)
            throw error
        }
    }

    static func normalizedEmail(_ email: String?) -> String? {
        guard let trimmed = email?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else {
            return nil
        }
        return trimmed.lowercased()
    }
}

// MARK: - Scoped print fetch

#if os(macOS)
extension AntigravityCLIHTTPSFetchStrategy {
    /// Runs `agy -p /usage` scoped to the injected token account's credentials:
    /// the account's OAuth tokens are staged into a private per-run `HOME`, the
    /// child receives an allowlist environment, and the staged token's `id_token`
    /// claim is verified against the selected account before launch, so the
    /// identity-free report can be attributed to that account. Fails closed:
    /// any error propagates so the pipeline falls through to the account-scoped
    /// OAuth strategy; ambient reports are never substituted for a selected
    /// account.
    func fetchScopedPrintUsage(
        binary: String,
        environment: [String: String],
        timeout: TimeInterval = 90) async throws -> ProviderFetchResult
    {
        guard let value = environment[AntigravityOAuthCredentialsStore.environmentCredentialsKey],
              let credentials = AntigravityOAuthCredentialsStore.credentials(fromTokenAccountValue: value),
              let expectedAccountEmail = credentials.resolvedAccountEmail
        else {
            throw AntigravityScopedStagingError.credentialsMissingRequiredFields
        }

        let staged = try AntigravityScopedAgyStaging.stage(
            credentials: credentials,
            expectedAccountEmail: expectedAccountEmail)
        defer { try? FileManager.default.removeItem(at: staged.stagingRoot) }
        let scopedEnvironment = AntigravityScopedAgyStaging.childEnvironment(
            from: environment, home: staged.home)

        let result: SubprocessResult
        do {
            let version = try await Self.agyVersion(binary: binary, environment: scopedEnvironment)
            guard let version, version >= (1, 1, 11)
            else { throw AntigravityStatusProbeError.parseFailed("CLI usage reports require agy 1.1.11 or later") }
            result = try await SubprocessRunner.run(
                binary: binary,
                arguments: ["-p", "/usage", "--output-format", "json", "--print-timeout", "90s"],
                environment: scopedEnvironment,
                timeout: timeout,
                maxOutputBytes: 1_048_576,
                standardInput: FileHandle.nullDevice,
                currentDirectoryURL: staged.home,
                label: "antigravity-cli-scoped-usage")
        } catch let error as SubprocessRunnerError {
            try Task.checkCancellation()
            // Subprocess errors may contain raw stderr; classify them into safe,
            // fixed diagnostics instead of surfacing the process output.
            throw AntigravityCLIPrintFailure.error(for: error)
        }

        let parsed = try AntigravityStatusProbe.parseCLIUsageReport(Data(result.stdout.utf8))
        if let reportedEmail = AntigravityScopedAgyStaging.normalizedEmail(parsed.accountEmail),
           reportedEmail != AntigravityScopedAgyStaging.normalizedEmail(expectedAccountEmail)
        {
            throw AntigravityStatusProbeError.accountMismatch(
                expected: expectedAccountEmail, found: parsed.accountEmail)
        }
        let snapshot = parsed.withIdentity(from: AntigravityStatusSnapshot(
            modelQuotas: [], accountEmail: expectedAccountEmail, accountPlan: nil, source: parsed.source))
        return try self.makeResult(usage: snapshot.toUsageSnapshot(), sourceLabel: Self.sourceLabel)
    }
}
#endif
