# Covenant Protocol Threat Model

## 1. System Overview
Covenant is a leverage and yield market platform that coordinates user deposits across isolated markets using the `Covenant` core contract, a market-specific LatentSwap exchange (LEX), oracle routing curated by governance, and synthetic ERC-20 tokens that represent debt and leveraged positions. The core contract manages market definitions, per-market state, authorized components, and protocol fees, while delegating pricing and mint/burn logic to the LEX implementation and to curator-selected price oracles.【F:src/Covenant.sol†L21-L175】【F:src/lex/latentswap/LatentSwapLEX.sol†L30-L193】【F:src/curators/CovenantCurator.sol†L9-L150】【F:src/synths/SynthToken.sol†L7-L88】

### Component Responsibilities
- **Covenant Core**: Ownable entry point that registers markets, enforces per-market reentrancy locks, accrues protocol fees, authorizes LEX/oracle integrations, and orchestrates mint, redeem, and swap flows using validation helpers.【F:src/Covenant.sol†L31-L200】【F:src/libraries/ValidationLogic.sol†L14-L135】
- **LatentSwap LEX**: Ownable periphery that prices swaps between base assets and synths, mints/burns `aToken`/`zToken` synths, configures per-market limits, and enforces invariant checks based on pre-computed liquidity parameters.【F:src/lex/latentswap/LatentSwapLEX.sol†L30-L200】
- **Curator / Oracle Router**: Ownable router that resolves price feeds across configured oracle contracts, ERC4626 vault conversions, and an optional fallback oracle. It requires explicit governance configuration for each asset pair.【F:src/curators/CovenantCurator.sol†L19-L198】
- **Synth Tokens**: Minimal ERC20s minted and burned exclusively by the LEX implementation for specific markets and asset types.【F:src/synths/SynthToken.sol†L11-L88】
- **Shared Libraries**: Validation logic and modifiers (e.g., `NoDelegateCall`) guard against misuse, enforce parameter correctness, and limit delegatecall-based proxy integrations.【F:src/libraries/ValidationLogic.sol†L14-L135】【F:src/libraries/NoDelegateCall.sol†L4-L15】

## 2. Security Objectives
1. **Asset Isolation** – Liquidity and accounting of each market must remain siloed so that actions in one market cannot drain another's base asset reserves.【F:src/Covenant.sol†L31-L175】
2. **Invariant Preservation** – LatentSwap's pricing and mint/redeem operations must respect configured LTV and liquidity bounds to avoid creating or redeeming value out of thin air.【F:src/lex/latentswap/LatentSwapLEX.sol†L35-L200】
3. **Oracle Integrity** – Market pricing must rely on curator-approved oracles, with clear fallbacks and restricted configuration paths to prevent malicious feeds.【F:src/curators/CovenantCurator.sol†L31-L150】
4. **Synthetics Correctness** – Synthetic tokens must only be minted/burned by the authorized LEX instance corresponding to each market to keep liabilities aligned with collateral.【F:src/synths/SynthToken.sol†L24-L88】
5. **Administrative Safety** – Owner-only actions (enabling components, fee collection, pausing) should remain constrained and auditable to limit governance compromise blast radius.【F:src/Covenant.sol†L111-L200】

## 3. Assets and Trust Boundaries
| Asset | Description | Primary Defenders | Threat Actors |
| --- | --- | --- | --- |
| Base Token Reserves | ERC20 balances held by Covenant markets and subject to swaps/mints/redeems. | Covenant core reentrancy locks, ValidationLogic output checks. | External users, compromised LEX, malicious synth holders.【F:src/Covenant.sol†L31-L175】【F:src/libraries/ValidationLogic.sol†L32-L110】 |
| Synth Token Supply (`aToken`, `zToken`) | Debt and leverage instruments minted by LEX per market. | LEX invariant enforcement, SynthToken `onlyLexCore` modifier. | Malicious LEX owner, compromised Covenant core, flash-loan attackers.【F:src/lex/latentswap/LatentSwapLEX.sol†L30-L200】【F:src/synths/SynthToken.sol†L17-L88】 |
| Oracle Configuration | Asset pair -> oracle routing and resolved vault mappings. | Curator `onlyOwner` restrictions, fallback oracle management. | Governance key compromise, misconfigured vaults/oracles.【F:src/curators/CovenantCurator.sol†L31-L198】 |
| Protocol Fees | Accrued fees per market held by Covenant. | Owner-only fee updates/collection and balance adjustments. | Malicious owner (assumed trusted), reentrancy attacks.【F:src/Covenant.sol†L134-L175】 |
| Governance Controls | Owner authority over LEX enablement, curators, pause addresses, and protocol fees. | Ownable2Step pattern, `noDelegateCall`, validation constraints. | Governance key theft, upgrade risk via external integrations.【F:src/Covenant.sol†L111-L200】【F:src/libraries/NoDelegateCall.sol†L4-L15】 |

## 4. Actors and Privileges
- **Protocol Owner/Governance**: Sole authority for enabling LEX/curators, setting fees, defining pause addresses, and collecting protocol fees. Compromise can reconfigure entire system.【F:src/Covenant.sol†L111-L200】
- **Market Pause Address**: Per-market authority to pause/unpause operations via `setMarketPause` and update pause delegates, limited to authorized addresses.【F:src/Covenant.sol†L177-L200】
- **LEX Owner**: Controls default and per-market caps, token metadata overrides, and must be trusted not to degrade invariants by misconfiguration.【F:src/lex/latentswap/LatentSwapLEX.sol†L135-L160】
- **Curator Governor**: Configures oracle routes, resolved ERC4626 vaults, and fallback oracles; bad actors can redirect price feeds.【F:src/curators/CovenantCurator.sol†L48-L150】
- **End Users / Liquidity Participants**: Interact with mint, redeem, and swap flows; may seek to extract value by manipulating pricing, oracles, or multicall sequencing.【F:src/Covenant.sol†L31-L175】【F:src/libraries/ValidationLogic.sol†L32-L110】
- **External Oracles & ERC4626 Vaults**: Provide pricing and valuation data; misbehavior or integration bugs can lead to incorrect pricing or DoS. Trust is delegated by curator configuration.【F:src/curators/CovenantCurator.sol†L54-L198】

## 5. Entry Points and Attack Surfaces
1. **User-Facing Market Actions** – `mint`, `redeem`, `swap`, and related multicall sequences pass through `lock`/`lockView` modifiers; attacks include reentrancy, dust donation, or manipulation of validation thresholds. The per-market reentrancy flag and extensive validation library enforce pre/post conditions but rely on accurate market state and oracle pricing.【F:src/Covenant.sol†L55-L200】【F:src/libraries/ValidationLogic.sol†L32-L110】
2. **Market Creation & Configuration** – Introducing a new market requires enabling a LEX implementation and curator; malicious owner input can point to rogue contracts. Validation ensures markets cannot be reinitialized but does not vet logic of the target addresses.【F:src/libraries/ValidationLogic.sol†L112-L126】【F:src/Covenant.sol†L111-L200】
3. **LEX Initialization & Controls** – LEX constructor enforces parameter bounds (LTV, sqrt price ratios, rate bias) but assumes provided values reflect realistic markets; owner functions can later loosen caps, affecting risk exposure.【F:src/lex/latentswap/LatentSwapLEX.sol†L35-L160】
4. **Oracle Resolution Path** – The curator router recursively resolves ERC4626 vaults and fallback oracles; potential loops or malicious vaults can siphon assets via `convertToAssets`. Trust in configured vaults and fallback oracles is critical.【F:src/curators/CovenantCurator.sol†L54-L198】
5. **Synthetic Token Mint/Burn** – `SynthToken` relies solely on the `_lexCore` address for authorization; if the linked LEX is compromised or replaced without updating the token, unauthorized mint/burn is possible.【F:src/synths/SynthToken.sol†L17-L88】
6. **Delegatecall and Multicall Controls** – `noDelegateCall` modifiers prevent execution through proxies, and `_isMulticall` tracks nested multicalls to detect read/write reentrancy. Any future extensions must preserve these invariants.【F:src/Covenant.sol†L49-L200】【F:src/libraries/NoDelegateCall.sol†L4-L15】

## 6. Key Assumptions & Invariants
- Enabled LEX and curator contracts are audited, honest, and immutable once enabled, as Covenant only checks the boolean authorization flags.【F:src/libraries/ValidationLogic.sol†L112-L126】【F:src/Covenant.sol†L111-L149】
- Oracle data (including fallback routes and ERC4626 valuations) is truthful post-configuration; Covenant does not enforce sanity bounds beyond curator authorization.【F:src/curators/CovenantCurator.sol†L54-L198】
- Synthetics follow standard ERC20 semantics with no transfer hooks; covenant assumes no fee-on-transfer or rebasing behavior for synths and base assets unless explicitly handled.【F:src/synths/SynthToken.sol†L11-L88】
- Protocol fees remain within bounds enforced by `ValidationLogic.checkProtocolFee`, ensuring fee schedule cannot exceed specified caps.【F:src/libraries/ValidationLogic.sol†L128-L135】

## 7. Threat Scenarios and Mitigations
| Threat | Description | Existing Mitigations | Residual Risk |
| --- | --- | --- | --- |
| Reentrancy across markets | Attacker chains calls to drain base tokens across markets. | Per-market `lock`/`lockView` modifiers enforce mutual exclusion and state checks.【F:src/Covenant.sol†L55-L200】 | Cross-contract reentrancy via LEX or external tokens remains possible if downstream contracts are unsafe. |
| Invalid parameter inputs | Users submit mismatched market IDs or zero amounts. | ValidationLogic enforces ID matching, non-zero amounts, output limits, and base supply bounds.【F:src/libraries/ValidationLogic.sol†L17-L110】 | Relies on accurate state inputs; incorrect marketParams supplied by owner could still misconfigure markets. |
| LEX invariant violation | Malicious LEX owner loosens caps or sets extreme pricing parameters post-deployment. | Constructor bounds enforce initial parameters; per-market cap adjustments remain owner-gated without hard caps beyond uint8 range.【F:src/lex/latentswap/LatentSwapLEX.sol†L35-L160】 | Governance compromise can still erode collateralization limits. |
| Oracle spoofing | Compromised curator routes requests to malicious oracle or vault. | Only owner can configure oracles and fallbacks; sorting of asset pairs reduces misrouting risk.【F:src/curators/CovenantCurator.sol†L31-L150】 | No on-chain validation of oracle freshness or authenticity; fallback oracle trust is critical. |
| Synth mint/burn abuse | Unauthorized entity mints synths to drain base reserves. | `SynthToken` restricts mint/burn to `_lexCore`; Covenant ensures LEX is authorized per market.【F:src/synths/SynthToken.sol†L17-L88】【F:src/libraries/ValidationLogic.sol†L112-L126】 | If `_lexCore` is compromised or swapped without updating token, protections fail. |
| Delegatecall proxying | Attacker invokes Covenant via proxy to bypass state assumptions. | `NoDelegateCall` modifier reverts when contract is delegate-called.【F:src/libraries/NoDelegateCall.sol†L4-L15】 | Future upgrades using proxies would require refactoring and may introduce new risks. |
| Fee extraction abuse | Owner misreports accrued fees or over-collects. | Fee collection caps withdrawals to accrued amounts and rejects zero-address recipient.【F:src/Covenant.sol†L153-L175】 | Owner can redirect funds but is an explicit trust assumption. |

## 8. Recommended Hardening Opportunities
1. **Immutable Configuration Hashes** – Persist hashes of LEX and curator configurations per market to detect unauthorized upgrades or address swaps by governance keys.【F:src/Covenant.sol†L111-L200】
2. **Oracle Response Sanity Checks** – Implement bounds checking (e.g., max price deviation, heartbeat) in Covenant or LEX before accepting oracle quotes to mitigate stale or manipulated feeds.【F:src/curators/CovenantCurator.sol†L86-L198】
3. **LEX Parameter Guardrails** – Enforce tighter limits (e.g., min/max `noCapLimit`) for owner updates to prevent governance from trivially bypassing intended collateral constraints.【F:src/lex/latentswap/LatentSwapLEX.sol†L135-L160】
4. **Synth Token Governance Hooks** – Provide a Covenant-controlled mechanism to rotate `_lexCore` for a market if the LEX implementation is upgraded, ensuring mint/burn access stays aligned with authorized logic.【F:src/synths/SynthToken.sol†L24-L88】
5. **Multicall Abuse Monitoring** – Expose analytics or emit events when `_isMulticall` toggles to aid in detecting complex multicall exploitation attempts.【F:src/Covenant.sol†L49-L200】

## 9. Open Questions
- How are off-chain governance keys secured, and are there time-locks or multi-sig requirements to mitigate single-point failures?【F:src/Covenant.sol†L111-L200】
- What monitoring exists for oracle or ERC4626 misbehavior, and can markets be auto-paused on abnormal price movements?【F:src/curators/CovenantCurator.sol†L78-L198】
- Are there documented processes for rotating synth token authorizations if LEX implementations are replaced or compromised?【F:src/synths/SynthToken.sol†L24-L88】
