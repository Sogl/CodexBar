import CodexBarCore
import Foundation
import Testing
@testable import CodexBar

private actor ScopedHomeRemovalRecorder {
    private var keys: [String] = []

    func record(_ key: String) {
        self.keys.append(key)
    }

    func firstKey() -> String? {
        self.keys.first
    }
}

/// Removing a saved Antigravity account must also delete its scoped `agy` staging
/// home, which holds reusable OAuth tokens for that account.
@MainActor
struct AntigravityScopedHomeRemovalTests {
    @Test
    func `removing antigravity oauth account requests scoped home deletion`() async throws {
        let recorder = ScopedHomeRemovalRecorder()
        let settings = testSettingsStore(
            suiteName: "AntigravityScopedHomeRemovalTests",
            antigravityScopedHomeRemover: { key in await recorder.record(key) })
        settings.upsertAntigravityOAuthAccount(AntigravityOAuthCredentials(
            accessToken: "scoped-access",
            refreshToken: "scoped-refresh",
            expiryDate: Date(timeIntervalSince1970: 1_700_000_000),
            email: "user@example.com"))
        let account = try #require(settings.selectedTokenAccount(for: .antigravity))
        settings.removeTokenAccount(provider: .antigravity, accountID: account.id)

        // The removal is dispatched asynchronously; wait for the scoped-home hook.
        var removedKey: String?
        for _ in 0..<100 where removedKey == nil {
            removedKey = await recorder.firstKey()
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        #expect(removedKey == account.id.uuidString)
    }
}
