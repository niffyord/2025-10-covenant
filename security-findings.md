# Security Findings

## Medium – Nested multicall resets payment guard
**Location.** [`Covenant.multicall`](src/Covenant.sol) and `_checkPayment` toggle the `_isMulticall` flag without tracking depth.【F:src/Covenant.sol†L506-L560】

**Summary.** The helper assumes batching is either on or off, using a boolean `_isMulticall`. When a payload in a batch calls `multicall` again, the inner frame clears `_isMulticall` back to `false` before the outer loop finishes. Subsequent outer payloads therefore run with `_isMulticall == false` even though execution is still inside the original batch. Any outer call that relies on the relaxed payment check (e.g., zero-value actions following a paid oracle update) now reverts with `Errors.E_IncorrectPayment` because `_checkPayment` enforces `msg.value == msgValue` mid-batch.

**Impact.** Nested batches that combine fee-paying oracle updates with zero-value actions become unusable. This DoS breaks composability with helper contracts that wrap Covenant calls inside their own multicalls.

**Steps to reproduce.**
1. Start a market and craft `bytes[] outer` where `outer[0]` is an encoded `Covenant.multicall(inner)` and `outer[1]` is a zero-value mint/redeem.
2. Let `inner` contain an oracle update that forwards non-zero `msgValue`.
3. Invoke `Covenant.multicall{value: fee}(outer)`; the second outer payload reverts with `Errors.E_IncorrectPayment` because `_isMulticall` was reset by the nested call.

**Remediation.** Track multicall depth (e.g., increment/decrement a counter) or explicitly forbid nesting.

## Medium – Self-referential resolved vault bricks oracle routing
**Location.** `CovenantCurator.govSetResolvedVault` records arbitrary ERC4626 assets without sanity checks; `resolveOracle` blindly recurses through `resolvedVaults` entries.【F:src/curators/CovenantCurator.sol†L67-L149】

**Summary.** Governance can register any ERC4626 vault for recursive oracle resolution. If a configured vault reports itself (or any cycle of vaults) as its underlying asset, `resolveOracle` will recurse indefinitely because the base asset never changes. Every price lookup that touches that vault exhausts gas and reverts, breaking pricing for affected markets.

**Impact.** A single bad configuration (or compromised vault that changes `asset()`) permanently DoSes price resolution on every path that traverses the vault, halting mint/redeem/swap flows that rely on those quotes.

**Steps to reproduce.**
1. Deploy an ERC4626 contract whose `asset()` returns its own address (or forms a cycle with another configured vault).
2. As governor, call `govSetResolvedVault(vault, true)` so `resolvedVaults[vault] = vault`.
3. Any Covenant action that queries prices with `base == vault` now calls `resolveOracle`, which repeatedly recurses and eventually runs out of gas.

**Remediation.** Reject configurations where `asset()` equals the vault itself or where adding the mapping would create a cycle; alternatively, track recursion depth and revert with a dedicated error once a limit is hit.
