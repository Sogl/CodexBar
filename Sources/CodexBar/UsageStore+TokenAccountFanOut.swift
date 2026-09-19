import CodexBarCore
import Foundation

extension UsageStore {
    /// Fetches one outcome per account in parallel. Results publish only after the whole
    /// fan-out completes so every account card flips to fresh data atomically instead of
    /// trickling in while the provider-level "Refreshing" indicator is still showing.
    func fetchTokenAccountOutcomes(
        provider: UsageProvider,
        accounts: [ProviderTokenAccount]) async -> [TokenAccountFetchResult]
    {
        let requests:
            [(
                index: Int,
                account: ProviderTokenAccount,
                descriptor: ProviderDescriptor,
                context: ProviderFetchContext)] =
            accounts.enumerated().map { index, account in
                let override = TokenAccountOverride(provider: provider, account: account)
                let descriptor =
                    self.providerSpecs[provider]?.descriptor
                        ?? ProviderDescriptorRegistry
                        .descriptor(for: provider)
                let context = self.makeFetchContext(provider: provider, override: override)
                return (index, account, descriptor, context)
            }

        if let delay = TokenAccountSupportCatalog.support(for: provider)?
            .minimumDelayBetweenAccountRefreshes
        {
            var results: [TokenAccountFetchResult] = []
            results.reserveCapacity(requests.count)
            for request in requests {
                if !results.isEmpty {
                    do {
                        try await Task.sleep(for: delay)
                    } catch {
                        for pending in requests.dropFirst(results.count) {
                            results.append(
                                TokenAccountFetchResult(
                                    index: pending.index,
                                    account: pending.account,
                                    outcome: ProviderFetchOutcome(
                                        result: .failure(CancellationError()),
                                        attempts: [])))
                        }
                        return results.sorted { $0.index < $1.index }
                    }
                }
                let outcome = await request.descriptor.fetchOutcome(context: request.context)
                results.append(
                    TokenAccountFetchResult(
                        index: request.index,
                        account: request.account,
                        outcome: outcome))
            }
            return results.sorted { $0.index < $1.index }
        }

        return await withTaskGroup(
            of: TokenAccountFetchResult.self,
            returning: [TokenAccountFetchResult].self)
        { group in
            for request in requests {
                group.addTask {
                    let outcome = await request.descriptor.fetchOutcome(context: request.context)
                    return TokenAccountFetchResult(
                        index: request.index,
                        account: request.account,
                        outcome: outcome)
                }
            }

            var results: [TokenAccountFetchResult] = []
            results.reserveCapacity(requests.count)
            for await result in group {
                results.append(result)
            }
            return results.sorted { $0.index < $1.index }
        }
    }
}
