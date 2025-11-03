# Security Findings

## Medium – Nested multicall resets payment guard
**Location.** [`Covenant.multicall`](src/Covenant.sol) and `_checkPayment` toggle the `_isMulticall` flag without tracking depth.【F:src/Covenant.sol†L506-L560】

**Summary.** The helper assumes batching is either on or off, using a boolean `_isMulticall`. When a payload in a batch calls `multicall` again, the inner frame clears `_isMulticall` back to `false` before the outer loop finishes. Subsequent outer payloads therefore run with `_isMulticall == false` even though execution is still inside the original batch. Any outer call that relies on the relaxed payment check (e.g., zero-value actions following a paid oracle update) now reverts with `Errors.E_IncorrectPayment` because `_checkPayment` enforces `msg.value == msgValue` mid-batch.

**Impact.** Nested batches that combine fee-paying oracle updates with zero-value actions become unusable. This DoS breaks composability with helper contracts that wrap Covenant calls inside their own multicalls.

**Steps to reproduce.**
1. Start a market and craft `bytes[] outer` where `outer[0]` is an encoded `Covenant.multicall(inner)` and `outer[1]` is a zero-value mint/redeem.
2. Let `inner` contain an oracle update that forwards non-zero `msgValue`.
3. Invoke `Covenant.multicall{value: fee}(outer)`; the second outer payload reverts with `Errors.E_IncorrectPayment` because `_isMulticall` was reset by the nested call.
   The repository already ships a regression test demonstrating this behaviour in `test/poc/MC01_NestedMulticall.t.sol` (see `test_nestedMulticall_breaksPaymentFlag`).【F:test/poc/MC01_NestedMulticall.t.sol†L52-L123】

**Remediation.** Track multicall depth (e.g., increment/decrement a counter) or explicitly forbid nesting.

## Medium – Self-referential resolved vault bricks oracle routing
**Location.** `CovenantCurator.govSetResolvedVault` records arbitrary ERC4626 assets without sanity checks; `resolveOracle` blindly recurses through `resolvedVaults` entries.【F:src/curators/CovenantCurator.sol†L67-L149】

**Summary.** Governance can register any ERC4626 vault for recursive oracle resolution. If a configured vault reports itself (or any cycle of vaults) as its underlying asset, `resolveOracle` will recurse indefinitely because the base asset never changes. Every price lookup that touches that vault exhausts gas and reverts, breaking pricing for affected markets. The recursion is triggered by the `resolvedVaults[base]` hop immediately followed by the recursive `return resolveOracle(...)` call, so a self-referential vault loops forever.【F:src/curators/CovenantCurator.sol†L118-L137】

**Impact.** A single bad configuration (or compromised vault that changes `asset()`) permanently DoSes price resolution on every path that traverses the vault, halting mint/redeem/swap flows that rely on those quotes.

**Steps to reproduce.**
1. Deploy an ERC4626 contract whose `asset()` returns its own address (or forms a cycle with another configured vault).
2. As governor, call `govSetResolvedVault(vault, true)` so `resolvedVaults[vault] = vault`.
3. Any Covenant action that queries prices with `base == vault` now calls `resolveOracle`, which repeatedly recurses and eventually runs out of gas.

**Remediation.** Reject configurations where `asset()` equals the vault itself or where adding the mapping would create a cycle; alternatively, track recursion depth and revert with a dedicated error once a limit is hit.

## Medium – Router accepts itself as configured oracle, causing infinite recursion
**Location.** `CovenantCurator.govSetConfig` and `govSetFallbackOracle` allow pointing an asset pair (or fallback) at any `IPriceOracle`, including the router itself, while `getQuote` and friends immediately delegate to the resolved oracle without cycle detection.【F:src/curators/CovenantCurator.sol†L39-L149】

**Summary.** The router assumes every configured oracle is an external implementation. If governance (maliciously or by mistake) sets a pair’s oracle—or the global fallback—to `address(this)`, `resolveOracle` returns the router address and `getQuote` performs an external call back into itself. That second invocation repeats the same resolution, leading to unbounded recursion (`getQuote → resolveOracle → getQuote → …`) until the call stack/ gas limit is exhausted. Price queries for the affected pair therefore revert, freezing any Covenant action that needs that quote.

**Impact.** A compromised governor or configuration error can permanently DoS all markets that depend on the misconfigured pair or fallback oracle, halting mint/redeem/swap flows despite the underlying LEX remaining healthy.

**Steps to reproduce.**
1. As governor, call `govSetConfig(base, quote, address(curator))` (or set `govSetFallbackOracle(address(curator))`).
2. Invoke `getQuote` (or any pricing method) for that pair.
3. The call loops until it runs out of gas because each hop re-enters the router without changing any state.

**Remediation.** Reject configurations that resolve to the router itself (and ideally detect other cycles) or add recursion-depth tracking that fails fast with a descriptive error instead of blindly re-entering.

## Review Notes – LatentSwap LEX parameter governance
Owner-accessible tuning is constrained to updating mint/redeem caps and token metadata, and the underlying math keeps per-market limits in place even after adjustments. `LatentSwapLEX` exposes only four `onlyOwner` mutators—`setDefaultNoCapLimit`, `setMarketNoCapLimit`, and metadata overrides—and validates market existence before per-market overrides apply.【F:src/lex/latentswap/LatentSwapLEX.sol†L135-L160】 Downstream, `_checkMintCap` and `_checkRedeemCap` bound inflows/outflows relative to current supply and ETWAP history, so even extreme `uint8` settings continue to gate throughput rather than bypassing collateral checks.【F:src/lex/latentswap/libraries/LatentSwapLogic.sol†L1051-L1098】

## Review Notes – ValidationLogic coverage
The shared validator enforces ID binding across all user operations, rejects zero-amount or zero-address submissions, and rechecks base-token availability on outputs. Mint/redeem flows first confirm the supplied `MarketParams` recompute the target `MarketId` before checking value limits and recipients, while swap validation also guards asset enum boundaries and base-supply exhaust cases.【F:src/libraries/ValidationLogic.sol†L17-L110】 These checks ensure calldata cannot redirect execution toward foreign markets or overdraft reserves even inside multicalls.

## Review Notes – Synth token authorization path
Each synth is minted with immutable references to both Covenant core and its LEX controller, and both contracts restrict who may invoke mint/burn. The `SynthToken` constructor locks `_lexCore` to the deploying LEX instance and gates `lexMint`/`lexBurn` behind `onlyLexCore`, preventing arbitrary inflation.【F:src/synths/SynthToken.sol†L11-L88】 During market initialization the LEX instantiates the synths with `lexCore = address(this)`, and all state-changing entry points (`initMarket`, `mint`, `redeem`, `swap`) are restricted to calls from Covenant core via `onlyCovenantCore`, so external actors cannot bypass Covenant’s validations to reach the synth authorizations directly.【F:src/lex/latentswap/LatentSwapLEX.sol†L200-L358】
