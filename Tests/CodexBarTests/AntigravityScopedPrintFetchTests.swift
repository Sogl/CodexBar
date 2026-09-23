import Foundation
import Testing
@testable import CodexBarCore

@Suite(.serialized)
struct AntigravityScopedPrintFetchTests {
    // MARK: - Token payload

    @Test
    func `file token payload encodes the agy storage format`() throws {
        let credentials = AntigravityOAuthCredentials(
            accessToken: "access",
            refreshToken: "refresh",
            expiryDate: Date(timeIntervalSince1970: 1_800_000_000),
            idToken: "header.payload.signature",
            email: "user@example.com")
        let data = try #require(AntigravityAgyFileTokenEncoder.encode(credentials: credentials))
        let payload = try #require(AntigravityAgyFileTokenEncoder.decode(data: data))
        #expect(payload.token.accessToken == "access")
        #expect(payload.token.tokenType == "Bearer")
        #expect(payload.token.refreshToken == "refresh")
        #expect(payload.token.expiry == "2027-01-15T08:00:00Z")
        #expect(payload.authMethod == "consumer")
        #expect(payload.idToken == "header.payload.signature")
    }

    @Test
    func `file token payload refuses credentials without refresh token or expiry`() {
        let noRefresh = AntigravityOAuthCredentials(
            accessToken: "access", refreshToken: nil, expiryDate: Date(), email: "a@b.c")
        let noExpiry = AntigravityOAuthCredentials(
            accessToken: "access", refreshToken: "refresh", expiryDate: nil, email: "a@b.c")
        #expect(AntigravityAgyFileTokenEncoder.encode(credentials: noRefresh) == nil)
        #expect(AntigravityAgyFileTokenEncoder.encode(credentials: noExpiry) == nil)
    }

    // MARK: - Child environment

    @Test
    func `scoped child environment inherits only allowlisted keys`() {
        let parent = [
            "HOME": "/users/ambient",
            "PATH": "/ambient/bin",
            "TMPDIR": "/tmp/ambient",
            "LANG": "en_US.UTF-8",
            "HTTPS_PROXY": "http://proxy:8080",
            "GEMINI_API_KEY": "ambient-secret",
            "ANTHROPIC_API_KEY": "ambient-secret",
            AntigravityOAuthCredentialsStore.environmentCredentialsKey: "injected-creds",
            "AWS_PROFILE": "ambient-profile",
        ]
        let home = URL(fileURLWithPath: "/scoped/home", isDirectory: true)
        let child = AntigravityScopedAgyStaging.childEnvironment(from: parent, home: home)

        #expect(child["HOME"] == "/scoped/home")
        #expect(child["PWD"] == "/scoped/home")
        #expect(child["SSH_TTY"] == "codexbar-scoped")
        #expect(child["TMPDIR"] == "/tmp/ambient")
        #expect(child["LANG"] == "en_US.UTF-8")
        #expect(child["HTTPS_PROXY"] == "http://proxy:8080")
        #expect(child["PATH"]?.isEmpty == false)
        #expect(child["GEMINI_API_KEY"] == nil)
        #expect(child["ANTHROPIC_API_KEY"] == nil)
        #expect(child["AWS_PROFILE"] == nil)
        #expect(child[AntigravityOAuthCredentialsStore.environmentCredentialsKey] == nil)
    }

    // MARK: - Staging and identity verification

    @Test
    func `staging writes a private token file verified against the account claim`() throws {
        let credentials = self.credentials(email: "scoped@example.com")
        let staged = try AntigravityScopedAgyStaging.stage(
            credentials: credentials, expectedAccountEmail: "scoped@example.com")
        defer { try? FileManager.default.removeItem(at: staged.stagingRoot) }

        let tokenURL = staged.home
            .appendingPathComponent(".gemini/antigravity-cli/antigravity-oauth-token")
        let attrs = try FileManager.default.attributesOfItem(atPath: tokenURL.path)
        #expect((attrs[.posixPermissions] as? Int) == 0o600)
        let homeAttrs = try FileManager.default.attributesOfItem(atPath: staged.home.path)
        #expect((homeAttrs[.posixPermissions] as? Int) == 0o700)
    }

    @Test
    func `staging rejects a token whose identity does not match the account`() throws {
        let credentials = self.credentials(email: "other@example.com")
        do {
            _ = try AntigravityScopedAgyStaging.stage(
                credentials: credentials, expectedAccountEmail: "scoped@example.com")
            Issue.record("A token for a different account must not be staged")
        } catch AntigravityScopedStagingError.identityUnverifiable {}
        #expect(self.scopedStagingDirectories().isEmpty)
    }

    @Test
    func `staging rejects credentials without an identity claim`() throws {
        let credentials = AntigravityOAuthCredentials(
            accessToken: "access",
            refreshToken: "refresh",
            expiryDate: Date().addingTimeInterval(3600))
        do {
            _ = try AntigravityScopedAgyStaging.stage(
                credentials: credentials, expectedAccountEmail: "scoped@example.com")
            Issue.record("Unverifiable staged identity must fail closed")
        } catch AntigravityScopedStagingError.identityUnverifiable {}
        #expect(self.scopedStagingDirectories().isEmpty)
    }

    // MARK: - Fallback wiring (platform-independent)

    @Test
    func `selected auto account uses the scoped report when legacy fails`() async throws {
        let strategy = AntigravityCLIHTTPSFetchStrategy()
        let expected = strategy.makeResult(
            usage: self.makeUsage(email: "scoped@example.com"), sourceLabel: "cli")
        let result = try await AntigravityCLIHTTPSFetchStrategy.fetchWithReportFallback(
            context: self.makeContext(selected: true, env: self.accountEnv(email: "scoped@example.com")),
            legacyFetch: { throw AntigravityStatusProbeError.timedOut },
            reportFetch: {
                Issue.record("Ambient identity-free print stays suppressed for selected accounts")
                throw AntigravityStatusProbeError.notRunning
            },
            scopedReportFetch: { expected })
        #expect(result.usage.identity?.accountEmail == "scoped@example.com")
    }

    @Test
    func `scoped failure preserves the original error and never runs ambient print`() async {
        await #expect(throws: AntigravityStatusProbeError.timedOut) {
            try await AntigravityCLIHTTPSFetchStrategy.fetchWithReportFallback(
                context: self.makeContext(selected: true, env: self.accountEnv(email: "scoped@example.com")),
                legacyFetch: { throw AntigravityStatusProbeError.timedOut },
                reportFetch: {
                    Issue.record("Ambient identity-free print stays suppressed for selected accounts")
                    throw AntigravityStatusProbeError.notRunning
                },
                scopedReportFetch: {
                    throw AntigravityStatusProbeError.cliReportFailed(.executableNotFound)
                })
        }
    }

    @Test
    func `cancellation stops the pipeline before the scoped fetch`() async {
        await #expect(throws: CancellationError.self) {
            try await AntigravityCLIHTTPSFetchStrategy.fetchWithReportFallback(
                context: self.makeContext(selected: true, env: self.accountEnv(email: "scoped@example.com")),
                legacyFetch: { throw CancellationError() },
                reportFetch: {
                    Issue.record("Cancellation must stop the provider pipeline")
                    throw AntigravityStatusProbeError.notRunning
                },
                scopedReportFetch: {
                    Issue.record("Cancellation must not start a scoped subprocess")
                    throw AntigravityStatusProbeError.notRunning
                })
        }
    }

    @Test
    func `unselected auto fetch still uses the ambient print report`() async throws {
        let strategy = AntigravityCLIHTTPSFetchStrategy()
        let expected = strategy.makeResult(usage: self.makeUsage(email: nil), sourceLabel: "cli")
        let result = try await AntigravityCLIHTTPSFetchStrategy.fetchWithReportFallback(
            context: self.makeContext(),
            legacyFetch: { throw AntigravityStatusProbeError.timedOut },
            reportFetch: { expected },
            scopedReportFetch: {
                Issue.record("Scoped fetch is reserved for selected or injected accounts")
                throw AntigravityStatusProbeError.notRunning
            })
        #expect(result.usage.identity?.accountEmail == nil)
    }

    @Test
    func `explicit cli mode never reaches the scoped fetch`() async throws {
        let strategy = AntigravityCLIHTTPSFetchStrategy()
        let expected = strategy.makeResult(usage: self.makeUsage(email: nil), sourceLabel: "cli")
        let result = try await AntigravityCLIHTTPSFetchStrategy.fetchWithReportFallback(
            context: self.makeContext(
                sourceMode: .cli, selected: true, env: self.accountEnv(email: "scoped@example.com")),
            legacyFetch: { throw AntigravityStatusProbeError.timedOut },
            reportFetch: { expected },
            scopedReportFetch: {
                Issue.record("Explicit cli mode stays bound to the ambient login")
                throw AntigravityStatusProbeError.notRunning
            })
        #expect(result.usage.identity?.accountEmail == nil)
    }

    // MARK: - Scoped subprocess (macOS only)

    #if os(macOS)
    @Test
    func `scoped print runs agy against the staged private home`() async throws {
        let report = try self.reportJSON()
        let fixture = try self.scopedPrintFixture(body: """
        [ -n "${SSH_TTY:-}" ] || exit 21
        [ -z "${ANTIGRAVITY_OAUTH_CREDENTIALS_JSON+x}" ] || exit 22
        [ -z "${LEAKED_PARENT_SECRET+x}" ] || exit 23
        [ "$HOME" != "/Users/ambient" ] || exit 26
        [ -f "$HOME/.gemini/antigravity-cli/antigravity-oauth-token" ] || exit 24
        /usr/bin/grep -q 'scoped-access-token' "$HOME/.gemini/antigravity-cli/antigravity-oauth-token" || exit 25
        /bin/cat <<'REPORT'
        \(report)
        REPORT
        """)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        var environment = self.accountEnv(email: "scoped@example.com")
        environment.merge(fixture.environment) { _, new in new }
        environment["HOME"] = "/Users/ambient"
        environment["LEAKED_PARENT_SECRET"] = "must-not-reach-child"

        let preexisting = Set(self.scopedStagingDirectories())
        let result = try await AntigravityCLIHTTPSFetchStrategy().fetchScopedPrintUsage(
            binary: fixture.binary.path, environment: environment)

        #expect(result.usage.identity?.accountEmail == "scoped@example.com")
        #expect(abs((result.usage.primary?.usedPercent ?? -1) - 40) < 0.001)
        #expect(Set(self.scopedStagingDirectories()) == preexisting)
    }

    @Test
    func `scoped print refuses undecodable injected credentials without spawning`() async throws {
        let fixture = try self.scopedPrintFixture(body: "echo invoked > \"$(dirname \"$0\")/invoked\"; exit 19")
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        var environment = fixture.environment
        environment[AntigravityOAuthCredentialsStore.environmentCredentialsKey] = "malformed"

        await #expect(throws: AntigravityScopedStagingError.credentialsMissingRequiredFields) {
            try await AntigravityCLIHTTPSFetchStrategy().fetchScopedPrintUsage(
                binary: fixture.binary.path, environment: environment)
        }
        #expect(!FileManager.default.fileExists(
            atPath: fixture.directory.appendingPathComponent("invoked").path))
    }

    @Test
    func `scoped print maps stderr to a classified failure`() async throws {
        let fixture = try self.scopedPrintFixture(body: """
        /bin/cat >&2 <<'STDERR'
        Eligibility check failed: account does not support Google ToS
        STDERR
        exit 1
        """)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        var environment = self.accountEnv(email: "scoped@example.com")
        environment.merge(fixture.environment) { _, new in new }

        await #expect(throws: AntigravityStatusProbeError.cliReportFailed(
            .exited(code: 1, reason: .ineligible)))
        {
            try await AntigravityCLIHTTPSFetchStrategy().fetchScopedPrintUsage(
                binary: fixture.binary.path, environment: environment)
        }
    }
    #endif

    // MARK: - Helpers

    private func credentials(email: String) -> AntigravityOAuthCredentials {
        AntigravityOAuthCredentials(
            accessToken: "scoped-access-token",
            refreshToken: "refresh",
            expiryDate: Date().addingTimeInterval(3600),
            idToken: GeminiAPITestHelpers.makeIDToken(email: email),
            email: email)
    }

    private func accountEnv(email: String) -> [String: String] {
        guard let value = try? AntigravityOAuthCredentialsStore.tokenAccountValue(
            for: self.credentials(email: email))
        else { return [:] }
        return [AntigravityOAuthCredentialsStore.environmentCredentialsKey: value]
    }

    private func makeContext(
        sourceMode: ProviderSourceMode = .auto,
        selected: Bool = false,
        env: [String: String] = [:]) -> ProviderFetchContext
    {
        var effectiveEnv = env
        effectiveEnv["HOME"] = effectiveEnv["HOME"] ?? FileManager.default.temporaryDirectory.path
        return ProviderFetchContext(
            runtime: .app,
            sourceMode: sourceMode,
            includeCredits: false,
            webTimeout: 1,
            webDebugDumpHTML: false,
            verbose: false,
            env: effectiveEnv,
            settings: nil,
            fetcher: UsageFetcher(environment: effectiveEnv),
            claudeFetcher: StubClaudeFetcher(),
            browserDetection: BrowserDetection(cacheTTL: 0),
            selectedTokenAccountID: selected ? UUID() : nil,
            persistsCLISessions: false)
    }

    private func makeUsage(email: String?) -> UsageSnapshot {
        UsageSnapshot(
            primary: nil,
            secondary: nil,
            updatedAt: Date(),
            identity: ProviderIdentitySnapshot(
                providerID: .antigravity,
                accountEmail: email,
                accountOrganization: nil,
                loginMethod: nil))
    }

    private func scopedStagingDirectories() -> [String] {
        (try? FileManager.default.contentsOfDirectory(
            atPath: FileManager.default.temporaryDirectory.path))?
            .filter { $0.hasPrefix("codexbar-agy-scoped-") } ?? []
    }

    private func reportJSON() throws -> String {
        let report: [String: Any] = [
            "status": "SUCCESS",
            "response": "Synthetic quota report",
            "command": [
                "name": "usage",
                "data": [
                    "groups": [[
                        "name": "Gemini Models",
                        "buckets": [[
                            "id": "gemini-5h",
                            "name": "Five Hour Limit Remaining",
                            "window": "5h",
                            "remaining_fraction": 0.6,
                        ]],
                    ]],
                ],
            ],
        ]
        let data = try JSONSerialization.data(withJSONObject: report)
        return try #require(String(bytes: data, encoding: .utf8))
    }

    #if os(macOS)
    private func scopedPrintFixture(body: String, version: String? = "1.2.7") throws
        -> (directory: URL, binary: URL, environment: [String: String])
    {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let binary = directory.appendingPathComponent("agy")
        var script = "#!/bin/sh\nset -eu\n"
        if let version {
            script += "if [ \"${1:-}\" = --version ]; then echo \"\(version)\"; exit 0; fi\n"
        }
        try (script + body + "\n").write(to: binary, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: binary.path)
        return (directory, binary, ["PATH": "/usr/bin:/bin"])
    }
    #endif

    private struct StubClaudeFetcher: ClaudeUsageFetching {
        func loadLatestUsage(model _: String) async throws -> ClaudeUsageSnapshot {
            throw ClaudeUsageError.parseFailed("stub")
        }

        func debugRawProbe(model _: String) async -> String {
            "stub"
        }

        func detectVersion() -> String? {
            nil
        }
    }
}
