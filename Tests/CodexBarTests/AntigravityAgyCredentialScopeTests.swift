import Foundation
import Testing
@testable import CodexBarCore

// MARK: - Test Fakes

private actor FakeAntigravityAgyCredentialMutationLock: AntigravityAgyCredentialMutationLocking {
    private var isLocked = false
    private var waitingTasks: [CheckedContinuation<Void, Never>] = []
    var activeLocks = 0
    var maxConcurrentLocks = 0

    func withLock<T: Sendable>(_ operation: @Sendable () async throws -> T) async throws -> T {
        await self.acquire()
        self.activeLocks += 1
        if self.activeLocks > self.maxConcurrentLocks {
            self.maxConcurrentLocks = self.activeLocks
        }

        do {
            let value = try await operation()
            self.activeLocks -= 1
            self.release()
            return value
        } catch {
            self.activeLocks -= 1
            self.release()
            throw error
        }
    }

    func maximumConcurrentLocks() -> Int {
        self.maxConcurrentLocks
    }

    private func acquire() async {
        guard self.isLocked else {
            self.isLocked = true
            return
        }
        await withCheckedContinuation { continuation in
            self.waitingTasks.append(continuation)
        }
    }

    private func release() {
        if let continuation = self.waitingTasks.first {
            self.waitingTasks.removeFirst()
            continuation.resume()
        } else {
            self.isLocked = false
        }
    }
}

private final class AntigravitySessionResetRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var resetCount = 0

    func recordReset() {
        self.lock.lock()
        self.resetCount += 1
        self.lock.unlock()
    }

    var count: Int {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.resetCount
    }
}

private actor AntigravityAsyncGate {
    private var isOpen = false
    private var waiter: CheckedContinuation<Void, Never>?

    func wait() async {
        guard !self.isOpen else { return }
        await withCheckedContinuation { self.waiter = $0 }
    }

    func open() {
        self.isOpen = true
        self.waiter?.resume()
        self.waiter = nil
    }
}

private final class AntigravityScopeCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    @discardableResult
    func increment() -> Int {
        self.lock.lock()
        self.count += 1
        let value = self.count
        self.lock.unlock()
        return value
    }

    var value: Int {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.count
    }
}

// MARK: - Test Suite

struct AntigravityAgyCredentialScopeTests {
    private static let sampleExpiry = Date(timeIntervalSince1970: 1_789_562_096)

    private static func validCredentials(email: String = "user@example.com") -> AntigravityOAuthCredentials {
        AntigravityOAuthCredentials(
            accessToken: "test-access-token",
            refreshToken: "test-refresh-token",
            expiryDate: self.sampleExpiry,
            idToken: nil,
            email: email)
    }

    private static func makeUsage(email: String?) -> UsageSnapshot {
        UsageSnapshot(
            primary: RateWindow(usedPercent: 20, windowMinutes: 300, resetsAt: nil, resetDescription: nil),
            secondary: RateWindow(usedPercent: 10, windowMinutes: 10080, resetsAt: nil, resetDescription: nil),
            tertiary: nil,
            updatedAt: Date(),
            identity: ProviderIdentitySnapshot(
                providerID: .antigravity,
                accountEmail: email,
                accountOrganization: nil,
                loginMethod: "Pro"))
    }

    private static func makeWarmDependencies(
        processInfos: @escaping @Sendable (TimeInterval) async throws
            -> [AntigravityStatusProbe.ProcessInfoResult] = { _ in [] },
        listeningPorts: @escaping @Sendable (Int, TimeInterval) async throws -> [Int] = { _, _ in [] },
        fetchSnapshot: @escaping @Sendable ([Int], TimeInterval) async throws -> AntigravityStatusSnapshot = { _, _ in
            throw AntigravityStatusProbeError.notRunning
        }) -> AntigravityCLIHTTPSFetchStrategy.WarmAgyDependencies
    {
        AntigravityCLIHTTPSFetchStrategy.WarmAgyDependencies(
            processInfos: processInfos,
            listeningPorts: listeningPorts,
            fetchSnapshot: fetchSnapshot,
            processOwnerUserID: { _ in 501 },
            currentUserID: { 501 },
            ownedPID: { nil },
            now: Date.init)
    }

    private static func makeAccountsDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("agy-scope-tests-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// DirectoryEnumerator is unavailable from async contexts; kept synchronous.
    private static func stagedFilePaths(under directory: URL) throws -> [String] {
        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isDirectoryKey])
        else { return [] }
        var files: [String] = []
        for case let url as URL in enumerator {
            let isDirectory = try url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory ?? false
            if !isDirectory {
                files.append(url.path)
            }
        }
        return files.sorted()
    }

    /// OAuth credentials encode into the `fileTokenStorage` payload `agy` reads.
    @Test
    func `oauth credentials encode to agy file token payload`() throws {
        let credentials = AntigravityOAuthCredentials(
            accessToken: "test-access-token",
            refreshToken: "test-refresh-token",
            expiryDate: Self.sampleExpiry,
            idToken: "test-id-token",
            email: "user@example.com")

        let data = try #require(AntigravityAgyFileTokenEncoder.encode(credentials: credentials))
        let payload = try #require(AntigravityAgyFileTokenEncoder.decode(data: data))

        #expect(payload.authMethod == "consumer")
        #expect(payload.idToken == "test-id-token")
        #expect(payload.token.accessToken == "test-access-token")
        #expect(payload.token.tokenType == "Bearer")
        #expect(payload.token.refreshToken == "test-refresh-token")
        #expect(payload.token.expiry == "2026-09-16T12:34:56Z")
        #expect(AntigravityAgyFileTokenEncoder.expiryDate(from: payload) == Self.sampleExpiry)
    }

    /// Credentials without an access token, refresh token, or expiry cannot build a payload.
    @Test
    func `encoder rejects credentials missing required fields`() {
        #expect(AntigravityAgyFileTokenEncoder.encode(credentials: AntigravityOAuthCredentials(
            accessToken: nil,
            refreshToken: "refresh",
            expiryDate: Self.sampleExpiry)) == nil)
        #expect(AntigravityAgyFileTokenEncoder.encode(credentials: AntigravityOAuthCredentials(
            accessToken: "access",
            refreshToken: nil,
            expiryDate: Self.sampleExpiry)) == nil)
        #expect(AntigravityAgyFileTokenEncoder.encode(credentials: AntigravityOAuthCredentials(
            accessToken: "access",
            refreshToken: "refresh",
            expiryDate: nil)) == nil)
    }

    /// `agy` may persist RFC3339 expiries with nanosecond precision; both forms must parse.
    @Test
    func `expiry parser handles plain fractional and nanosecond rfc3339`() {
        func payload(expiry: String) -> AntigravityAgyFileTokenPayload {
            AntigravityAgyFileTokenPayload(
                token: .init(
                    accessToken: "a",
                    tokenType: "Bearer",
                    refreshToken: "r",
                    expiry: expiry),
                authMethod: "consumer",
                idToken: nil)
        }

        let plain = AntigravityAgyFileTokenEncoder.expiryDate(from: payload(expiry: "2026-09-16T12:34:56Z"))
        let fractional = AntigravityAgyFileTokenEncoder.expiryDate(
            from: payload(expiry: "2026-09-16T12:34:56.789Z"))
        let nanos = AntigravityAgyFileTokenEncoder.expiryDate(
            from: payload(expiry: "2026-09-16T12:34:56.123456789Z"))

        #expect(plain == Self.sampleExpiry)
        #expect(fractional != nil)
        #expect(abs((nanos?.timeIntervalSince1970 ?? 0) - 1_789_562_096.123456) < 1)
    }

    /// `prepare` writes the token into an isolated staging HOME and returns the
    /// environment (`HOME`, `PWD`, `SSH_TTY`) that makes `agy` pick file token storage.
    @Test
    func `prepare stages token file and scoped environment`() async throws {
        let accountsDirectory = try Self.makeAccountsDirectory()
        defer { try? FileManager.default.removeItem(at: accountsDirectory) }
        let coordinator = AntigravityAgyHomeCoordinator(
            mutationLock: FakeAntigravityAgyCredentialMutationLock(),
            resetSession: {},
            accountsDirectory: accountsDirectory)

        let scope = try await coordinator.prepare(
            credentials: Self.validCredentials(),
            accountKey: "Account ID/with*unsafe?chars")

        let homeURL = try #require(scope.homeURL)
        #expect(homeURL.path.hasPrefix(accountsDirectory.path))
        #expect(!homeURL.lastPathComponent.contains("/"))
        #expect(scope.environment["HOME"] == homeURL.path)
        #expect(scope.environment["PWD"] == homeURL.path)
        #expect(scope.environment["SSH_TTY"]?.isEmpty == false)

        let tokenURL = AntigravityAgyHomeCoordinator.tokenURL(home: homeURL)
        #expect(tokenURL.path.hasPrefix(homeURL.path))
        #expect(tokenURL.path.contains(".gemini/antigravity-cli"))

        let data = try #require(FileManager.default.contents(atPath: tokenURL.path))
        let payload = try #require(AntigravityAgyFileTokenEncoder.decode(data: data))
        #expect(payload.token.accessToken == "test-access-token")

        let attributes = try FileManager.default.attributesOfItem(atPath: tokenURL.path)
        #expect((attributes[.posixPermissions] as? Int) == 0o600)
    }

    /// A fresher token already staged by `agy`'s own refresh is not overwritten by an
    /// older injected credential; an older staged token is replaced.
    @Test
    func `prepare keeps fresher staged token and replaces staler one`() async throws {
        let accountsDirectory = try Self.makeAccountsDirectory()
        defer { try? FileManager.default.removeItem(at: accountsDirectory) }
        let coordinator = AntigravityAgyHomeCoordinator(
            mutationLock: FakeAntigravityAgyCredentialMutationLock(),
            resetSession: {},
            accountsDirectory: accountsDirectory)
        let accountKey = "account-a"

        let scope = try await coordinator.prepare(
            credentials: Self.validCredentials(),
            accountKey: accountKey)
        let tokenURL = try AntigravityAgyHomeCoordinator.tokenURL(home: #require(scope.homeURL))

        // agy persisted a fresher token for the same grant: a stale injected credential
        // must not clobber it.
        let fresher = AntigravityOAuthCredentials(
            accessToken: "agy-refreshed-access",
            refreshToken: "test-refresh-token",
            expiryDate: Self.sampleExpiry.addingTimeInterval(3600))
        try #require(AntigravityAgyFileTokenEncoder.encode(credentials: fresher)).write(to: tokenURL)

        _ = try await coordinator.prepare(credentials: Self.validCredentials(), accountKey: accountKey)
        let kept = try AntigravityAgyFileTokenEncoder.decode(
            data: #require(FileManager.default.contents(atPath: tokenURL.path)))
        #expect(kept?.token.accessToken == "agy-refreshed-access")

        // A newer injected credential replaces the staged token again.
        let evenNewer = AntigravityOAuthCredentials(
            accessToken: "injected-newer-access",
            refreshToken: "test-refresh-token",
            expiryDate: Self.sampleExpiry.addingTimeInterval(7200))
        _ = try await coordinator.prepare(credentials: evenNewer, accountKey: accountKey)
        let replaced = try AntigravityAgyFileTokenEncoder.decode(
            data: #require(FileManager.default.contents(atPath: tokenURL.path)))
        #expect(replaced?.token.accessToken == "injected-newer-access")
    }

    /// A staged token from a different grant (another refresh token, e.g. credentials
    /// re-issued by a different OAuth client) is always replaced even when it is fresher.
    @Test
    func `prepare replaces staged token from a different grant`() async throws {
        let accountsDirectory = try Self.makeAccountsDirectory()
        defer { try? FileManager.default.removeItem(at: accountsDirectory) }
        let coordinator = AntigravityAgyHomeCoordinator(
            mutationLock: FakeAntigravityAgyCredentialMutationLock(),
            resetSession: {},
            accountsDirectory: accountsDirectory)
        let accountKey = "account-a"

        let scope = try await coordinator.prepare(
            credentials: Self.validCredentials(),
            accountKey: accountKey)
        let tokenURL = try AntigravityAgyHomeCoordinator.tokenURL(home: #require(scope.homeURL))

        let foreignGrant = AntigravityOAuthCredentials(
            accessToken: "foreign-access",
            refreshToken: "foreign-refresh-token",
            expiryDate: Self.sampleExpiry.addingTimeInterval(3600))
        try #require(AntigravityAgyFileTokenEncoder.encode(credentials: foreignGrant)).write(to: tokenURL)

        _ = try await coordinator.prepare(credentials: Self.validCredentials(), accountKey: accountKey)
        let replaced = try AntigravityAgyFileTokenEncoder.decode(
            data: #require(FileManager.default.contents(atPath: tokenURL.path)))
        #expect(replaced?.token.refreshToken == "test-refresh-token")
    }

    /// `withPreparedScope` serializes work under the mutation lock and resets the managed
    /// `agy` session before and after the operation, including on failure.
    @Test
    func `withPreparedScope resets managed session around operation`() async throws {
        let accountsDirectory = try Self.makeAccountsDirectory()
        defer { try? FileManager.default.removeItem(at: accountsDirectory) }
        let resetRecorder = AntigravitySessionResetRecorder()
        let coordinator = AntigravityAgyHomeCoordinator(
            mutationLock: FakeAntigravityAgyCredentialMutationLock(),
            resetSession: { resetRecorder.recordReset() },
            accountsDirectory: accountsDirectory)

        let result = try await coordinator.withPreparedScope(
            credentials: Self.validCredentials(),
            accountKey: "account-a")
        { scope in
            #expect(scope.environment["HOME"] == scope.homeURL?.path)
            return "done"
        }

        #expect(result == "done")
        #expect(resetRecorder.count == 2)

        await #expect(throws: AntigravityAgyHomeScopeError.self) {
            try await coordinator.withPreparedScope(
                credentials: AntigravityOAuthCredentials(
                    accessToken: nil,
                    refreshToken: "refresh",
                    expiryDate: Self.sampleExpiry),
                accountKey: "account-b")
            { _ in "never" }
        }
        // Failing before the operation still leaves the session reset on entry.
        #expect(resetRecorder.count == 3)
    }

    /// Concurrent scoped fetches serialize through the lock instead of mixing staging dirs.
    @Test
    func `concurrent account scoped fetches are serialized`() async throws {
        let accountsDirectory = try Self.makeAccountsDirectory()
        defer { try? FileManager.default.removeItem(at: accountsDirectory) }
        let lock = FakeAntigravityAgyCredentialMutationLock()
        let coordinator = AntigravityAgyHomeCoordinator(
            mutationLock: lock,
            resetSession: {},
            accountsDirectory: accountsDirectory)

        let credsA = Self.validCredentials(email: "a@example.com")
        let credsB = Self.validCredentials(email: "b@example.com")

        async let fetchA = coordinator.withPreparedScope(credentials: credsA, accountKey: "a") { scope in
            try await Task.sleep(nanoseconds: 50_000_000)
            return scope.environment["HOME"] ?? ""
        }
        async let fetchB = coordinator.withPreparedScope(credentials: credsB, accountKey: "b") { scope in
            try await Task.sleep(nanoseconds: 50_000_000)
            return scope.environment["HOME"] ?? ""
        }

        let (homeA, homeB) = try await (fetchA, fetchB)
        #expect(homeA != homeB)
        #expect(homeA.contains("/a/"))
        #expect(homeB.contains("/b/"))
        let maximumConcurrentLocks = await lock.maximumConcurrentLocks()
        #expect(maximumConcurrentLocks == 1)
    }

    /// The production flock-based lock must suspend waiters instead of blocking a
    /// cooperative worker, and a cancelled waiter must abandon the wait promptly.
    /// A second waiter acquires the lock once the holder is cancelled.
    @Test
    func `real mutation lock releases cancelled waiters and reacquires`() async throws {
        let lockFileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("agy-real-lock-" + UUID().uuidString, isDirectory: true)
            .appendingPathComponent("scope.lock")
        defer { try? FileManager.default.removeItem(at: lockFileURL.deletingLastPathComponent()) }
        let lock = AntigravityAgyCredentialMutationLock(fileURL: lockFileURL)
        let entered = AntigravityScopeCounter()

        let holder = Task {
            try await lock.withLock {
                entered.increment()
                try await Task.sleep(for: .seconds(60))
                return "held"
            }
        }
        while entered.value == 0 {
            try await Task.sleep(for: .milliseconds(5))
        }

        // A waiter blocked in a synchronous flock() could never observe cancellation;
        // with the suspending wait it must finish promptly once cancelled.
        let waiter = Task {
            try await lock.withLock { "acquired" }
        }
        try await Task.sleep(for: .milliseconds(150))
        waiter.cancel()
        let waiterFinished = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                _ = await waiter.result
                return true
            }
            group.addTask {
                try? await Task.sleep(for: .seconds(5))
                return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
        #expect(waiterFinished)

        // The lock stays usable: a later waiter acquires it after the holder releases.
        let latecomer = Task {
            try await lock.withLock { "latecomer" }
        }
        holder.cancel()
        #expect(try await latecomer.value == "latecomer")
        _ = await holder.result
    }

    /// Removing an account deletes its staged home and tombstones the scope so
    /// neither `prepare` nor `withPreparedScope` can restage credentials for it.
    @Test
    func `removeScope deletes staged home and blocks restaging`() async throws {
        let accountsDirectory = try Self.makeAccountsDirectory()
        defer { try? FileManager.default.removeItem(at: accountsDirectory) }
        let coordinator = AntigravityAgyHomeCoordinator(
            mutationLock: FakeAntigravityAgyCredentialMutationLock(),
            resetSession: {},
            accountsDirectory: accountsDirectory)
        let accountKey = "account-removed"

        let scope = try await coordinator.prepare(
            credentials: Self.validCredentials(),
            accountKey: accountKey)
        let homeURL = try #require(scope.homeURL)
        #expect(FileManager.default.fileExists(atPath: homeURL.path))

        await coordinator.removeScope(accountKey: accountKey)
        #expect(!FileManager.default.fileExists(atPath: homeURL.path))

        await #expect(throws: AntigravityAgyHomeScopeError.self) {
            try await coordinator.prepare(
                credentials: Self.validCredentials(),
                accountKey: accountKey)
        }
        await #expect(throws: AntigravityAgyHomeScopeError.self) {
            try await coordinator.withPreparedScope(
                credentials: Self.validCredentials(),
                accountKey: accountKey)
            { _ in "never" }
        }
        #expect(!FileManager.default.fileExists(atPath: homeURL.path))
    }

    /// A fetch queued behind another scoped session must not restage credentials
    /// once its account was removed while it waited on the lock.
    @Test
    func `queued staging cannot restage a removed account`() async throws {
        let accountsDirectory = try Self.makeAccountsDirectory()
        defer { try? FileManager.default.removeItem(at: accountsDirectory) }
        let coordinator = AntigravityAgyHomeCoordinator(
            mutationLock: FakeAntigravityAgyCredentialMutationLock(),
            resetSession: {},
            accountsDirectory: accountsDirectory)
        let removedKey = "account-queued"
        let gate = AntigravityAsyncGate()
        let firstEntered = AntigravityScopeCounter()

        let first = Task {
            try await coordinator.withPreparedScope(
                credentials: Self.validCredentials(),
                accountKey: "account-first")
            { _ in
                firstEntered.increment()
                await gate.wait()
                return "first"
            }
        }
        while firstEntered.value == 0 {
            try await Task.sleep(for: .milliseconds(5))
        }

        let queued = Task {
            try await coordinator.withPreparedScope(
                credentials: Self.validCredentials(),
                accountKey: removedKey)
            { _ in "restaged" }
        }
        // Let the queued fetch reach the lock wait, then remove the account. The
        // tombstone lands immediately even though the deletion queues on the lock.
        let removal = Task { await coordinator.removeScope(accountKey: removedKey) }
        try await Task.sleep(for: .milliseconds(100))
        await gate.open()

        await #expect(throws: AntigravityAgyHomeScopeError.self) {
            try await queued.value
        }
        #expect(try await first.value == "first")
        await removal.value
        let removedHome = AntigravityAgyHomeCoordinator.accountDirectory(
            accountKey: removedKey,
            accountsDirectory: accountsDirectory)
            .appendingPathComponent("home", isDirectory: true)
        #expect(!FileManager.default.fileExists(atPath: removedHome.path))
    }

    /// Retirement must reach every process sharing the accounts directory: a second
    /// coordinator (e.g. a `codexbar` CLI invocation) has an empty in-memory tombstone
    /// set, yet the persisted marker must still block restaging of the removed account.
    @Test
    func `removeScope blocks restaging from another coordinator sharing the directory`() async throws {
        let accountsDirectory = try Self.makeAccountsDirectory()
        defer { try? FileManager.default.removeItem(at: accountsDirectory) }
        let lockFileURL = accountsDirectory.appendingPathComponent("shared-scope.lock")
        let appCoordinator = AntigravityAgyHomeCoordinator(
            mutationLock: AntigravityAgyCredentialMutationLock(fileURL: lockFileURL),
            resetSession: {},
            accountsDirectory: accountsDirectory)
        let cliCoordinator = AntigravityAgyHomeCoordinator(
            mutationLock: AntigravityAgyCredentialMutationLock(fileURL: lockFileURL),
            resetSession: {},
            accountsDirectory: accountsDirectory)
        let accountKey = "account-removed-remotely"

        let scope = try await appCoordinator.prepare(
            credentials: Self.validCredentials(),
            accountKey: accountKey)
        let homeURL = try #require(scope.homeURL)
        await appCoordinator.removeScope(accountKey: accountKey)
        #expect(!FileManager.default.fileExists(atPath: homeURL.path))

        // The other coordinator never saw the removal, but the shared marker blocks it.
        await #expect(throws: AntigravityAgyHomeScopeError.self) {
            try await cliCoordinator.withPreparedScope(
                credentials: Self.validCredentials(),
                accountKey: accountKey)
            { _ in "never" }
        }
        await #expect(throws: AntigravityAgyHomeScopeError.self) {
            try await cliCoordinator.prepare(
                credentials: Self.validCredentials(),
                accountKey: accountKey)
        }
        #expect(!FileManager.default.fileExists(atPath: homeURL.path))

        // Retirement stays scoped to the removed key: unrelated accounts still stage.
        let otherScope = try await cliCoordinator.prepare(
            credentials: Self.validCredentials(),
            accountKey: "account-still-saved")
        #expect(otherScope.homeURL != nil)
    }

    /// The exact review scenario: a fetch in a second process captured the account,
    /// waited behind the app's scoped session on the shared lock, and acquired the
    /// lock only after the app removed the account. The persisted marker must reject
    /// it before any credential file is restaged.
    @Test
    func `queued staging in another coordinator cannot restage a removed account`() async throws {
        let accountsDirectory = try Self.makeAccountsDirectory()
        defer { try? FileManager.default.removeItem(at: accountsDirectory) }
        let lockFileURL = accountsDirectory.appendingPathComponent("shared-scope.lock")
        let appCoordinator = AntigravityAgyHomeCoordinator(
            mutationLock: AntigravityAgyCredentialMutationLock(fileURL: lockFileURL),
            resetSession: {},
            accountsDirectory: accountsDirectory)
        let cliCoordinator = AntigravityAgyHomeCoordinator(
            mutationLock: AntigravityAgyCredentialMutationLock(fileURL: lockFileURL),
            resetSession: {},
            accountsDirectory: accountsDirectory)
        let removedKey = "account-queued-remotely"
        let markerURL = AntigravityAgyHomeCoordinator.retiredMarkerURL(
            accountKey: removedKey,
            accountsDirectory: accountsDirectory)
        let gate = AntigravityAsyncGate()
        let holderEntered = AntigravityScopeCounter()

        // The app process holds the shared lock on an unrelated scoped fetch.
        let holder = Task {
            try await appCoordinator.withPreparedScope(
                credentials: Self.validCredentials(),
                accountKey: "account-holder")
            { _ in
                holderEntered.increment()
                await gate.wait()
                return "held"
            }
        }
        while holderEntered.value == 0 {
            try await Task.sleep(for: .milliseconds(5))
        }

        // The CLI process captured the account before removal and queues on the lock.
        #expect(!FileManager.default.fileExists(atPath: markerURL.path))
        let queued = Task {
            try await cliCoordinator.withPreparedScope(
                credentials: Self.validCredentials(),
                accountKey: removedKey)
            { _ in "restaged" }
        }
        try await Task.sleep(for: .milliseconds(100))

        // The app removes the account; the marker lands before the delete waits on the lock.
        let removal = Task { await appCoordinator.removeScope(accountKey: removedKey) }
        while !FileManager.default.fileExists(atPath: markerURL.path) {
            try await Task.sleep(for: .milliseconds(5))
        }
        await gate.open()

        await #expect(throws: AntigravityAgyHomeScopeError.self) {
            try await queued.value
        }
        #expect(try await holder.value == "held")
        await removal.value
        let removedHome = AntigravityAgyHomeCoordinator.accountDirectory(
            accountKey: removedKey,
            accountsDirectory: accountsDirectory)
            .appendingPathComponent("home", isDirectory: true)
        #expect(!FileManager.default.fileExists(atPath: removedHome.path))
    }

    /// If a removal crashes between writing the marker and deleting the directory,
    /// the next scoped operation in any process sweeps the leftover staged home
    /// instead of leaving reusable tokens behind.
    @Test
    func `first scoped operation sweeps staged home left by interrupted removal`() async throws {
        let accountsDirectory = try Self.makeAccountsDirectory()
        defer { try? FileManager.default.removeItem(at: accountsDirectory) }
        let lockFileURL = accountsDirectory.appendingPathComponent("shared-scope.lock")
        let crashedCoordinator = AntigravityAgyHomeCoordinator(
            mutationLock: AntigravityAgyCredentialMutationLock(fileURL: lockFileURL),
            resetSession: {},
            accountsDirectory: accountsDirectory)
        let otherCoordinator = AntigravityAgyHomeCoordinator(
            mutationLock: AntigravityAgyCredentialMutationLock(fileURL: lockFileURL),
            resetSession: {},
            accountsDirectory: accountsDirectory)
        let retiredKey = "account-crashed-removal"

        let scope = try await crashedCoordinator.prepare(
            credentials: Self.validCredentials(),
            accountKey: retiredKey)
        let staleHomeURL = try #require(scope.homeURL)

        // Simulate the crash window: marker persisted, directory deletion never ran.
        let markerURL = AntigravityAgyHomeCoordinator.retiredMarkerURL(
            accountKey: retiredKey,
            accountsDirectory: accountsDirectory)
        try FileManager.default.createDirectory(
            at: markerURL.deletingLastPathComponent(),
            withIntermediateDirectories: true)
        try Data("\(retiredKey)\n".utf8).write(to: markerURL)
        #expect(FileManager.default.fileExists(atPath: staleHomeURL.path))

        // The other process's first scoped fetch sweeps the retired home under the lock.
        let unrelated = try await otherCoordinator.withPreparedScope(
            credentials: Self.validCredentials(),
            accountKey: "account-alive")
        { scope in scope.homeURL?.path ?? "" }

        #expect(!unrelated.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: staleHomeURL.path))
        #expect(FileManager.default.fileExists(atPath: markerURL.path))
    }

    /// The staged home is the only credential source the scoped `agy` can see: a
    /// fresh scope contains exactly the file-token payload for the staged account,
    /// and the environment pins file-based storage so ambient credentials cannot
    /// leak into the scope.
    @Test
    func `staged home exposes only the scoped account token`() async throws {
        let accountsDirectory = try Self.makeAccountsDirectory()
        defer { try? FileManager.default.removeItem(at: accountsDirectory) }
        let coordinator = AntigravityAgyHomeCoordinator(
            mutationLock: FakeAntigravityAgyCredentialMutationLock(),
            resetSession: {},
            accountsDirectory: accountsDirectory)

        let scope = try await coordinator.prepare(
            credentials: Self.validCredentials(email: "selected@example.com"),
            accountKey: "account-isolated")
        let homeURL = try #require(scope.homeURL)
        let tokenURL = AntigravityAgyHomeCoordinator.tokenURL(home: homeURL)

        // Enumerated paths resolve the /var -> /private/var symlink, so compare by
        // suffix: exactly one file, inside the account's staged home, at the agy
        // file-token location.
        let stagedFiles = try Self.stagedFilePaths(under: homeURL)
        #expect(stagedFiles.count == 1)
        #expect(stagedFiles.first?.hasSuffix(
            "/" + AntigravityAgyHomeCoordinator.tokenRelativePath.joined(separator: "/")) == true)
        #expect(stagedFiles.first?.contains("/account-isolated/home/") == true)

        let tokenData = try #require(FileManager.default.contents(atPath: tokenURL.path))
        let payload = try #require(AntigravityAgyFileTokenEncoder.decode(data: tokenData))
        #expect(payload.token.refreshToken == "test-refresh-token")
        #expect(scope.environment["HOME"] == homeURL.path)
        #expect(scope.environment["SSH_TTY"]?.isEmpty == false)
    }

    /// A warm ambient `agy` that already matches the selected account is reused; neither the
    /// scoped fetch nor a fresh spawn runs.
    @Test
    func `matching external warm agy skips account scoped fetch and spawn`() async throws {
        let strategy = AntigravityCLIHTTPSFetchStrategy()
        let spawnCallCount = AntigravityScopeCounter()
        let scopedCallCount = AntigravityScopeCounter()

        let warmSnapshot = AntigravityStatusSnapshot(
            modelQuotas: [AntigravityModelQuota(
                label: "Gemini",
                modelId: "gemini-pro",
                remainingFraction: 0.9,
                resetTime: nil,
                resetDescription: nil)],
            accountEmail: "user@example.com",
            accountPlan: "Pro",
            source: .local)

        let result = try await strategy.fetchUsingWarmSession(
            binary: "/usr/local/bin/agy",
            idleWindow: 60,
            resetAfterFetch: false,
            expectedAccountEmail: "user@example.com",
            accountScopedFetch: {
                scopedCallCount.increment()
                return strategy.makeResult(
                    usage: Self.makeUsage(email: "user@example.com"),
                    sourceLabel: "cli")
            },
            warmDependencies: Self.makeWarmDependencies(
                processInfos: { _ in
                    [AntigravityStatusProbe.ProcessInfoResult(
                        pid: 7777,
                        extensionPort: nil,
                        extensionServerCSRFToken: nil,
                        csrfToken: "",
                        commandLine: "/usr/local/bin/agy")]
                },
                listeningPorts: { _, _ in [55000] },
                fetchSnapshot: { _, _ in warmSnapshot }),
            spawnFetch: { _, _, _ in
                spawnCallCount.increment()
                return strategy.makeResult(
                    usage: Self.makeUsage(email: "user@example.com"),
                    sourceLabel: "cli")
            })

        #expect(result.usage.identity?.accountEmail == "user@example.com")
        #expect(scopedCallCount.value == 0)
        #expect(spawnCallCount.value == 0)
    }

    /// When the ambient `agy` reports another account, the scoped fetch runs instead of the
    /// ambient spawn path.
    @Test
    func `warm mismatch falls through to account scoped fetch`() async throws {
        let strategy = AntigravityCLIHTTPSFetchStrategy()
        let spawnCallCount = AntigravityScopeCounter()
        let scopedCallCount = AntigravityScopeCounter()

        let otherAccountWarmSnapshot = AntigravityStatusSnapshot(
            modelQuotas: [AntigravityModelQuota(
                label: "Gemini",
                modelId: "gemini-pro",
                remainingFraction: 0.9,
                resetTime: nil,
                resetDescription: nil)],
            accountEmail: "other@example.com",
            accountPlan: "Free",
            source: .local)

        let result = try await strategy.fetchUsingWarmSession(
            binary: "/usr/local/bin/agy",
            idleWindow: 60,
            resetAfterFetch: false,
            expectedAccountEmail: "selected@example.com",
            accountScopedFetch: {
                scopedCallCount.increment()
                return strategy.makeResult(
                    usage: Self.makeUsage(email: "selected@example.com"),
                    sourceLabel: "cli")
            },
            warmDependencies: Self.makeWarmDependencies(
                processInfos: { _ in
                    [AntigravityStatusProbe.ProcessInfoResult(
                        pid: 8888,
                        extensionPort: nil,
                        extensionServerCSRFToken: nil,
                        csrfToken: "",
                        commandLine: "/usr/local/bin/agy")]
                },
                listeningPorts: { _, _ in [55000] },
                fetchSnapshot: { _, _ in otherAccountWarmSnapshot }),
            spawnFetch: { _, _, _ in
                spawnCallCount.increment()
                return strategy.makeResult(
                    usage: Self.makeUsage(email: "other@example.com"),
                    sourceLabel: "cli")
            })

        #expect(result.usage.identity?.accountEmail == "selected@example.com")
        #expect(scopedCallCount.value == 1)
        #expect(spawnCallCount.value == 0)
    }

    /// Without a selected account the ambient spawn path is unchanged.
    @Test
    func `no selected account keeps ambient spawn path`() async throws {
        let strategy = AntigravityCLIHTTPSFetchStrategy()
        let spawnCallCount = AntigravityScopeCounter()
        let scopedCallCount = AntigravityScopeCounter()

        let result = try await strategy.fetchUsingWarmSession(
            binary: "/usr/local/bin/agy",
            idleWindow: 60,
            resetAfterFetch: false,
            expectedAccountEmail: nil,
            accountScopedFetch: nil,
            warmDependencies: Self.makeWarmDependencies(),
            spawnFetch: { _, idleWindow, resetAfterFetch in
                spawnCallCount.increment()
                #expect(idleWindow == 60)
                #expect(!resetAfterFetch)
                return strategy.makeResult(
                    usage: Self.makeUsage(email: "ambient@example.com"),
                    sourceLabel: "cli")
            })

        #expect(result.usage.identity?.accountEmail == "ambient@example.com")
        #expect(scopedCallCount.value == 0)
        #expect(spawnCallCount.value == 1)
    }
}
