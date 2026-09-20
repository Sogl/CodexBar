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
/// storage reads this file whenever the OS keyring is unavailable, and writes refreshed
/// tokens back to it, so a per-account staging `HOME` fully isolates account scope
/// without touching the user's Keychain item (and therefore without Keychain prompts).
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

    static func expiryDate(from payload: AntigravityAgyFileTokenPayload) -> Date? {
        let text = payload.token.expiry
        let withFraction = ISO8601DateFormatter()
        withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = withFraction.date(from: text) {
            return date
        }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        if let date = plain.date(from: text) {
            return date
        }
        // agy writes RFC3339 with nanosecond precision; trim to microseconds for parsing.
        guard let dotIndex = text.firstIndex(of: "."),
              let zoneIndex = text[dotIndex...].firstIndex(where: { $0 == "Z" || $0 == "+" })
        else {
            return nil
        }
        let trimmed = String(text[..<zoneIndex]) + "Z"
        return plain.date(from: trimmed)
    }

    private static func expiryString(for date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }
}

// MARK: - Scoped environment

/// The environment `agy` must run with to stay scoped to one saved Google account.
struct AntigravityAgyScopedEnvironment: Equatable, Sendable {
    static let unscoped = AntigravityAgyScopedEnvironment(homeURL: nil, environment: [:])

    let homeURL: URL?
    let environment: [String: String]
}

enum AntigravityAgyHomeScopeError: LocalizedError, Sendable, Equatable {
    case credentialsMissingRequiredFields
    case unavailable(String)

    var errorDescription: String? {
        switch self {
        case .credentialsMissingRequiredFields:
            "Antigravity account credentials lack required token or expiry fields."
        case let .unavailable(message):
            "Antigravity account scope is unavailable: \(message)"
        }
    }
}

// MARK: - Mutation Lock

protocol AntigravityAgyCredentialMutationLocking: Sendable {
    func withLock<T: Sendable>(_ operation: @Sendable () async throws -> T) async throws -> T
}

final class AntigravityAgyCredentialMutationLock: AntigravityAgyCredentialMutationLocking, @unchecked Sendable {
    private let fileURL: URL
    private let fileManager: FileManager

    init(
        fileURL: URL = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
            .appendingPathComponent(".codexbar", isDirectory: true)
            .appendingPathComponent("antigravity", isDirectory: true)
            .appendingPathComponent("agy-credential.lock"),
        fileManager: FileManager = .default)
    {
        self.fileURL = fileURL
        self.fileManager = fileManager
    }

    func withLock<T: Sendable>(_ operation: @Sendable () async throws -> T) async throws -> T {
        let directory = self.fileURL.deletingLastPathComponent()
        try self.fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        let fd = open(self.fileURL.path, O_CREAT | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR)
        guard fd >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer {
            _ = flock(fd, LOCK_UN)
            close(fd)
        }

        // Nonblocking acquisition: waiters suspend instead of occupying a cooperative
        // worker while the holder awaits subprocesses, and Task.sleep makes the wait
        // cancellation-aware so a cancelled refresh can abandon the queue.
        while flock(fd, LOCK_EX | LOCK_NB) != 0 {
            let lockError = errno
            guard lockError == EWOULDBLOCK || lockError == EINTR else {
                throw POSIXError(POSIXErrorCode(rawValue: lockError) ?? .EIO)
            }
            try await Task.sleep(for: .milliseconds(25))
        }
        return try await operation()
    }
}

// MARK: - Home Scope Coordinator

/// `FileManager` is safe for the simple directory operations performed inside the lock;
/// the box lets it travel inside the `@Sendable` lock operation.
private struct UncheckedSendableFileManager: @unchecked Sendable {
    let value: FileManager
}

/// Prepares a per-account staging `HOME` for `agy` and serializes scoped CLI sessions.
///
/// Instead of mutating the shared Keychain credential (which `agy` would refuse to read
/// without a Keychain ACL prompt, because CodexBar is not in its ACL), the coordinator
/// writes the selected account's OAuth tokens into `agy`'s own file token storage inside
/// an isolated `HOME`, and marks the child environment as an SSH session. `agy` detects
/// the SSH session and selects file-based token storage outright, so it neither reads
/// nor writes the OS keyring: no Keychain prompt can appear, and refreshed tokens stay
/// in the per-account staging directory.
actor AntigravityAgyHomeCoordinator {
    static let shared = AntigravityAgyHomeCoordinator()

    private static let log = CodexBarLog.logger(LogCategories.provider(.antigravity, scope: "agy-scope"))

    /// Provider-specific by design: agy stores its file token under ~/.gemini because the
    /// Antigravity CLI shares the Gemini CLI toolchain directory layout.
    static let tokenRelativePath = [".gemini", "antigravity-cli", "antigravity-oauth-token"]
    /// Any non-empty value triggers `agy`'s "SSH session detected" file-storage path.
    static let sshSessionMarkerValue = "/dev/ttys001"

    private let fileManager: FileManager
    private let mutationLock: any AntigravityAgyCredentialMutationLocking
    private let resetSession: @Sendable () async -> Void
    private let accountsDirectory: URL
    /// Account keys tombstoned by `removeScope(accountKey:)`. Tombstoned scopes can
    /// never be restaged in this process, so a queued fan-out refresh cannot
    /// recreate credentials after the saved account was deleted.
    private var retiredAccountKeys: Set<String> = []

    init(
        fileManager: FileManager = .default,
        mutationLock: any AntigravityAgyCredentialMutationLocking = AntigravityAgyCredentialMutationLock(),
        resetSession: @escaping @Sendable () async -> Void = { await AntigravityCLISession.shared.reset() },
        accountsDirectory: URL? = nil)
    {
        self.fileManager = fileManager
        self.mutationLock = mutationLock
        self.resetSession = resetSession
        if let accountsDirectory {
            self.accountsDirectory = accountsDirectory
        } else {
            self.accountsDirectory = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
                .appendingPathComponent(".codexbar", isDirectory: true)
                .appendingPathComponent("antigravity", isDirectory: true)
                .appendingPathComponent("accounts", isDirectory: true)
        }
    }

    /// Runs `operation` with an environment scoped to `credentials`, serializing scoped
    /// sessions so a warm managed `agy` for one account is never observed by another.
    func withPreparedScope<T: Sendable>(
        credentials: AntigravityOAuthCredentials,
        accountKey: String,
        operation: @Sendable (AntigravityAgyScopedEnvironment) async throws -> T) async throws -> T
    {
        guard !self.retiredAccountKeys.contains(accountKey) else {
            Self.log.info("agy scope: staging skipped, account scope removed", metadata: [
                "accountKey": accountKey,
            ])
            throw AntigravityAgyHomeScopeError.unavailable("account scope was removed")
        }
        let fileManager = UncheckedSendableFileManager(value: self.fileManager)
        let accountsDirectory = self.accountsDirectory
        let resetSession = self.resetSession
        Self.log.debug("agy scope: waiting for mutation lock", metadata: ["accountKey": accountKey])
        return try await self.mutationLock.withLock {
            // Re-check under the lock: the account may have been removed while this
            // fetch was queued behind another scoped session.
            if await self.isScopeRetired(accountKey) {
                Self.log.info("agy scope: staging blocked for removed account", metadata: [
                    "accountKey": accountKey,
                ])
                throw AntigravityAgyHomeScopeError.unavailable("account scope was removed")
            }
            // Ensure a previous CodexBar-managed agy session (possibly for another account)
            // is gone before the scoped spawn, and again after it completes.
            await resetSession()
            let scoped = try Self.prepare(
                credentials: credentials,
                accountKey: accountKey,
                fileManager: fileManager.value,
                accountsDirectory: accountsDirectory)
            Self.log.debug("agy scope: prepared", metadata: [
                "accountKey": accountKey,
                "home": scoped.homeURL?.path ?? "none",
            ])
            do {
                let value = try await operation(scoped)
                await resetSession()
                Self.log.debug("agy scope: finished", metadata: ["accountKey": accountKey])
                return value
            } catch {
                await resetSession()
                Self.log.debug("agy scope: operation failed", metadata: [
                    "accountKey": accountKey,
                    "error": error.localizedDescription,
                ])
                throw error
            }
        }
    }

    /// Deletes the staged home for `accountKey` and tombstones the scope so queued or
    /// in-flight staging cannot recreate credentials for a removed saved account.
    /// Deletion is serialized with staging behind the mutation lock: a scoped fetch
    /// already running finishes first, then its staged home is removed.
    func removeScope(accountKey: String) async {
        self.retiredAccountKeys.insert(accountKey)
        let fileManager = UncheckedSendableFileManager(value: self.fileManager)
        let directory = Self.accountDirectory(
            accountKey: accountKey,
            accountsDirectory: self.accountsDirectory)
        do {
            try await self.mutationLock.withLock {
                if fileManager.value.fileExists(atPath: directory.path) {
                    try fileManager.value.removeItem(at: directory)
                }
            }
            Self.log.info("agy scope: staged home removed", metadata: ["accountKey": accountKey])
        } catch {
            Self.log.warning("agy scope: could not remove staged home", metadata: [
                "accountKey": accountKey,
                "error": error.localizedDescription,
            ])
        }
    }

    private func isScopeRetired(_ accountKey: String) -> Bool {
        self.retiredAccountKeys.contains(accountKey)
    }

    func prepare(
        credentials: AntigravityOAuthCredentials,
        accountKey: String) throws -> AntigravityAgyScopedEnvironment
    {
        guard !self.retiredAccountKeys.contains(accountKey) else {
            throw AntigravityAgyHomeScopeError.unavailable("account scope was removed")
        }
        return try Self.prepare(
            credentials: credentials,
            accountKey: accountKey,
            fileManager: self.fileManager,
            accountsDirectory: self.accountsDirectory)
    }

    static func accountDirectory(accountKey: String, accountsDirectory: URL) -> URL {
        accountsDirectory
            .appendingPathComponent(self.sanitizedDirectoryComponent(accountKey), isDirectory: true)
    }

    static func prepare(
        credentials: AntigravityOAuthCredentials,
        accountKey: String,
        fileManager: FileManager,
        accountsDirectory: URL) throws -> AntigravityAgyScopedEnvironment
    {
        guard let tokenData = AntigravityAgyFileTokenEncoder.encode(credentials: credentials) else {
            self.log.warning("agy scope: credentials missing required fields", metadata: [
                "accountKey": accountKey,
                "hasAccessToken": credentials.accessToken.map { !$0.isEmpty } == true ? "yes" : "no",
                "hasRefreshToken": credentials.refreshToken.map { !$0.isEmpty } == true ? "yes" : "no",
                "hasExpiry": credentials.expiryDate == nil ? "no" : "yes",
            ])
            throw AntigravityAgyHomeScopeError.credentialsMissingRequiredFields
        }

        let homeURL = Self.accountDirectory(
            accountKey: accountKey,
            accountsDirectory: accountsDirectory)
            .appendingPathComponent("home", isDirectory: true)
        do {
            try fileManager.createDirectory(
                at: homeURL.appendingPathComponent(Self.tokenRelativePath[0], isDirectory: true)
                    .appendingPathComponent(Self.tokenRelativePath[1], isDirectory: true),
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
        } catch {
            Self.log.warning("agy scope: could not create staging home", metadata: [
                "accountKey": accountKey,
                "error": error.localizedDescription,
            ])
            throw AntigravityAgyHomeScopeError.unavailable(error.localizedDescription)
        }

        let tokenURL = Self.tokenURL(home: homeURL)
        // `agy` refreshes tokens itself and persists them into the staging file. Keep the
        // fresher token only when it is the same grant (matching refresh token): a staged
        // token from different credentials must always be replaced, regardless of expiry.
        let injectedRefreshToken = credentials.refreshToken?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        var shouldWrite = true
        if let existingData = fileManager.contents(atPath: tokenURL.path),
           let existingPayload = AntigravityAgyFileTokenEncoder.decode(data: existingData),
           existingPayload.token.refreshToken == injectedRefreshToken,
           let existingExpiry = AntigravityAgyFileTokenEncoder.expiryDate(from: existingPayload),
           let credentialsExpiry = credentials.expiryDate,
           existingExpiry > credentialsExpiry
        {
            shouldWrite = false
        }
        if shouldWrite {
            do {
                try tokenData.write(to: tokenURL, options: [.atomic])
                try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenURL.path)
            } catch {
                Self.log.warning("agy scope: could not stage token file", metadata: [
                    "accountKey": accountKey,
                    "error": error.localizedDescription,
                ])
                throw AntigravityAgyHomeScopeError.unavailable(error.localizedDescription)
            }
        }
        Self.log.debug("agy scope: token staged", metadata: [
            "accountKey": accountKey,
            "tokenFile": tokenURL.path,
            "action": shouldWrite ? "written" : "kept-fresher-staged",
            "credentialsExpiry": credentials.expiryDate.map { ISO8601DateFormatter().string(from: $0) }
                ?? "none",
        ])

        return AntigravityAgyScopedEnvironment(
            homeURL: homeURL,
            environment: [
                "HOME": homeURL.path,
                "PWD": homeURL.path,
                "SSH_TTY": Self.sshSessionMarkerValue,
            ])
    }

    static func tokenURL(home: URL) -> URL {
        self.tokenRelativePath.reduce(home) { $0.appendingPathComponent($1) }
    }

    private static func sanitizedDirectoryComponent(_ value: String) -> String {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        let sanitized = value.unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" }
        let trimmed = String(sanitized).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return trimmed.isEmpty ? "account" : String(trimmed.prefix(64))
    }
}

/// App-facing lifecycle hook for the internal scope coordinator. Kept deliberately
/// narrow: the saved-account removal path is the only supported caller.
public enum AntigravityAgyScopedHomeLifecycle {
    /// Deletes the staged credential home for `accountKey` (the saved account's UUID
    /// string) and blocks queued or in-flight staging from recreating it after the
    /// account was removed from settings.
    public static func removeScope(accountKey: String) async {
        await AntigravityAgyHomeCoordinator.shared.removeScope(accountKey: accountKey)
    }
}
