#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// Shared logging helpers for the Antigravity fetch chain. All messages go to
/// the `antigravity` log category (oslog `com.steipete.codexbar` and the
/// CodexBar file log when enabled), so a single refresh produces one readable
/// trace across every strategy and the account-scoped `agy` path.
enum AntigravityFetchLog {
    static let log = CodexBarLog.logger(LogCategories.provider(.antigravity))

    /// Stable, non-PII account fingerprint: SHA-256 prefix of the normalized
    /// email. `LogRedactor` turns raw emails into `<redacted-email>`, so a
    /// fingerprint is the only way to correlate accounts across log lines.
    static func accountFingerprint(_ email: String?) -> String {
        guard let email else { return "none" }
        let normalized = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else { return "none" }
        let digest = SHA256.hash(data: Data(normalized.utf8))
        return digest.prefix(5).map { String(format: "%02x", $0) }.joined()
    }

    /// Single-line, length-capped rendering of subprocess output for log
    /// metadata. Secrets are still stripped by `LogRedactor` downstream.
    static func truncate(_ text: String, limit: Int = 400) -> String {
        let singleLine = text
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard singleLine.count > limit else { return singleLine }
        return String(singleLine.prefix(limit)) + "…"
    }

    /// Compact quota-content summary of a raw Antigravity snapshot.
    static func statusSummary(_ snapshot: AntigravityStatusSnapshot) -> String {
        if let summary = snapshot.quotaSummary {
            let buckets = summary.groups.flatMap(\.buckets)
            let known = buckets.count { !$0.disabled && $0.remainingFraction != nil }
            return "groups=\(summary.groups.count) buckets=\(buckets.count) known=\(known)"
        }
        let known = snapshot.modelQuotas.count { $0.remainingFraction != nil }
        return "models=\(snapshot.modelQuotas.count) known=\(known)"
    }

    /// Compact window summary of a normalized usage snapshot.
    static func usageSummary(_ usage: UsageSnapshot) -> String {
        let standard = [usage.primary, usage.secondary, usage.tertiary].compactMap(\.self).count
        let extras = usage.extraRateWindows?.count ?? 0
        return "windows=\(standard) extra=\(extras)"
    }
}
