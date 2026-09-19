import Foundation
import Testing
@testable import CodexBarCore

struct AntigravityUsageReportFailureTests {
    @Test
    func `usage report failure maps eligibility stderr to not eligible error`() {
        let stderr = """
        Eligibility check failed: Client is not eligible for Gemini Code Assist for \
        individuals. Client does not support Google TOS.
        """
        #expect(
            AntigravityStatusProbeError.usageReportFailure(stderr: stderr) == .cliAccountNotEligible)
    }

    @Test
    func `usage report failure maps auth stderr to authentication required`() {
        #expect(
            AntigravityStatusProbeError.usageReportFailure(
                stderr: "Authentication required. You are not logged into Antigravity.")
                == .authenticationRequired)
        #expect(
            AntigravityStatusProbeError.usageReportFailure(
                stderr: "You are not logged into Antigravity.")
                == .authenticationRequired)
    }

    @Test
    func `usage report failure keeps unknown stderr unclassified`() {
        #expect(
            AntigravityStatusProbeError.usageReportFailure(stderr: "boom")
                == .parseFailed("CLI usage report failed"))
    }

    @Test
    func `eligibility failure signature matches remote 403 bodies`() {
        #expect(
            AntigravityStatusProbeError.isEligibilityFailure(
                #"{"error":{"message":"Client is not eligible for Gemini Code Assist"}}"#))
        #expect(!AntigravityStatusProbeError.isEligibilityFailure("quota exceeded"))
    }
}
