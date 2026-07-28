# CHANGELOG



## v0.1.1 (2026-07-28)

### Fix

* fix(ci): update release workflow and isolate PyInstaller builds

- Fix release step tag outputs using steps.release.outputs.tag_name
- Configure explicit workpath for PyInstaller to resolve file lock errors
- Update SQLite rotation query logic to avoid timestamp type comparison bugs
- Clean up release workflow dependencies ([`c362374`](https://github.com/4ami/muraq-kms/commit/c36237474d18448a678f4047cdda1f611535b1b0))

### Unknown

* Merge pull request #16 from 4ami/development

fix(ci): update release workflow and isolate PyInstaller builds ([`755fdac`](https://github.com/4ami/muraq-kms/commit/755fdace778f71c1a4175ce435cf3621a002c9ce))


## v0.1.0 (2026-07-28)

### Build

* build: add pyinstaller and workflow tests

- Add pyinstaller to core dependencies in pyproject.toml
- Create .github/workflows/test.yml for CI test execution
- Configure dependencies for automated testing ([`a91f917`](https://github.com/4ami/muraq-kms/commit/a91f9171bec3a8a45648d48b468a31c0d412060c))

### Feature

* feat(rotation): integrate automated key rotation with creation flow

- Wire KeyManager creation to RotationManager jobs
- Implement background RotationScheduler daemon
- Fix timestamp evaluation in overdue job queries
- Add real multi-db storage integration tests ([`19daaf6`](https://github.com/4ami/muraq-kms/commit/19daaf63ac4ef07deef6fbc3be65aa1d0b00b954))

* feat(crypto): implement CLI message orchestration and stream processing primitives

- Add in-memory message encryption and decryption handlers with dynamic stdout/file routing.

- Implement chunk-based streaming encryption with structural format headers and HMAC validation.

- Protect stream decoding routines against unbound variable errors using safe local lookups.

- Establish comprehensive unit verification matrices for formatting drift and header tampering. ([`578de39`](https://github.com/4ami/muraq-kms/commit/578de39b92010234677e5e35be44775e9c99ce5f))

* feat(cli): implement key listing and secure key export operations with shell test suite

- Implemented &#39;-ls&#39; command parsing and routing to handle structural key listing operations
- Added initial &#39;-export&#39; framework supporting json, txt, and custom env structures
- Implemented handle_export controller with dedicated _handle_env, _handle_json, and _handle_txt persistence layers
- Enforced strict file-exist validation guardrails to prevent accidental plaintext or structural overwrites
- Created global &#39;test_unsealed_shell&#39; fixture inside conftest.py with mock-unsealed state injection
- Added CLI service routing test suite inside test_unseal_services.py ([`00f8bf9`](https://github.com/4ami/muraq-kms/commit/00f8bf9c3a3de7d4a780811656f99cca20662469))

* feat: refactor KMS CLI commands into unified subparser dispatch architecture

- Refactored `key` and `audit` operations to use optimized argparse subparsers with operational dispatch routing
- Fixed hyphenated sub-command parsing constraints by adjusting root prefix characters
- Enhanced `key -create` argument validation rules for conditional execution components (--borrow, --ttl)
- Standardized purpose choice case-insensitivity and forced lowercase output normalization
- Decoupled terminal frame UI formatting contexts out of the cryptographic core AuditManager
- Standardized service layer help hooks and aligned command docstring signatures ([`2cbc0ec`](https://github.com/4ami/muraq-kms/commit/2cbc0ec50444edc833376a4a78e8aa50810b9c01))

* feat(cli): integrate key borrowing loop, add log monitoring, and fix layout constraints

- Connect &#39;borrow_key_sync&#39; to the unsealed shell to display raw key material securely for the duration of its database TTL.
- Add an automated &#39;os.system&#39; screen-wipe and lease termination routine to erase volatile material without relying on manual user input.
- Add &#39;do_logs&#39; command with a &#39;--verify&#39; flag to track append-only audit entries inside a custom UI Frame layout.
- Pass the validated &#39;KeyAccessPolicy&#39; object into &#39;create_key_sync&#39; to resolve missing parameter constraints.
- Fix right-border alignment flaws in &#39;_intro_builder&#39; by calculating padding spaces using raw visible text lengths instead of raw string lengths. ([`ed9096d`](https://github.com/4ami/muraq-kms/commit/ed9096d9ae2978da06c31d2b88e66d6873601e38))

* feat: implement core audit and key management backends ([`be4bd7b`](https://github.com/4ami/muraq-kms/commit/be4bd7bbd3ae29cd35877eac8fb8cbdce592c13b))

* feat: decouple sealed and unsealed runtime shell environments

Split the monolithic administrative shell into two dedicated isolation layers: MKMSShell (Sealed boundary state) and MKMSUnsealedShell (Active execution runtime). This enforces a strict security perimeter where core workflows are explicitly routed upon successful credential reconstitution.

Key fixes and architectural improvements:
- Inverted unseal_kms flow to prevent UI rendering collisions by isolating interactive getpass requests from async background threads.
- Added a structural layout guard clause to the initialization step to safely block operators from attempting to unseal unprovisioned nodes.
- Updated SpinnerGroup.run_step to proactively instantiate fallback variables, eliminating UnboundLocalError crashes on step validation failures.
- Extracted UUIDv4 slicing logic into test assertions to cleanly verify variable deployment ID rendering without relying on brittle mocks.
- Routed user credential test interactions directly through the UI.secure_input proxy boundary to stabilize retry loop assertions. ([`7c96fcd`](https://github.com/4ami/muraq-kms/commit/7c96fcd1408e702ba1788b829768a60b2a15ae7f))

* feat(policy): implement controlled raw key access and ephemeral lease engine

- Added KeyAccessPolicy and PolicyManifest validation schemas using Pydantic
- Implemented fail-closed PolicyEvaluator to authorize borrow workflows per FR-14
- Engineered EphemeralKeyLease context manager with volatile memory zeroization
- Added enforcement gates for bounded lease Time-To-Live (TTL) tracking
- Created comprehensive unit test suite covering access denial, lease expiration, and memory scrubbing ([`558008a`](https://github.com/4ami/muraq-kms/commit/558008a03964308faf9906b0d84d60f1863893c1))

* feat(crypto): implement manifest auto-healing and identity spoofing defense

- Integrated signature.enc verification against platform deployment context
- Added identity verification check between plaintext manifest and wrapped envelope data
- Implemented automated recovery logic to rewrite manifest.json with legitimate ID truth on spoof detection
- Enforced immediate escalation to system lockout on integrity verification failure
- Protected volatile memory registers by hardening internal zeroization routines upon exceptions ([`c4020af`](https://github.com/4ami/muraq-kms/commit/c4020afdc05b5cc07df8f9b8a95e5011945e89d6))

* feat(security): implement anti-tamper throttling defense and path sandboxing

Closes out the brute-force mitigation loop and layout isolation requirements across the core appliance storage engine and interactive shell layers.

- Core Throttling Engine (core/throttling.py):
  * Designed an ACID-compliant brute-force protection system using dynamic HMAC-SHA256 signatures over state parameters.
  * Implemented defensive short-circuit triggers that intercept missing/purged database files or manual signature modification.
  * Enforces an immediate 30-minute lockdown penalty if data tampering indicators are flagged before an input prompt can be presented.
  * Solved false-positive initialization states via a temporary &#39;INITIALIZED&#39; seed verification pass that safely rolls over into a live cryptographic tracking signature.

- Sandboxed Workspace Enforcements (storage/config.py):
  * Hardened path processing parameters inside StorageConfig using combined .absolute().resolve() chaining.
  * Fully neutralizes directory-traversal vectors (e.g., ../ payloads) and structural relative injections.
  * Explicitly locks all runtime application footprints to an isolated .muraq-kms subdirectory tree, preventing unintentional local working environment directory purges.
  * Realigned the system environment fallback configuration target safely to the active user&#39;s Home Directory (Path.home()).

- Preflight Matrix and CLI Handlers (cli/):
  * Integrated orchestrator traps inside interactive unseal routines to intercept systemic security anomalies before displaying administrative credentials entry sequences.
  * Stabilized variable tracking states across loop transitions to prevent UnboundLocalError exceptions from polluting throttle validation conditions.

- Comprehensive Test Infrastructure Configuration (tests/):
  * Authored targeted platform validation suites verifying dot-input isolation containment properties, path-traversal blocking behaviors, and cross-platform canonical string alignment under macOS symlink architectures (/var vs /private/var).
  * Structured robust mock execution scenarios confirming appropriate loop failure recovery actions and precise state validation enforcement thresholds. ([`902f75a`](https://github.com/4ami/muraq-kms/commit/902f75a0670c7f0a97515e43336aa455123b1454))

* feat(core): implement CoreEngine lifecycle and unseal mechanics

- Add CoreEngine state manager with SEALED and UNSEALED states. - Implement .unseal() to stretch passphrases via Argon2id and decrypt DRS. - Extract domain-isolated runtime keys (RMK and ASK) into volatile memory. - Implement explicit .seal() with in-memory zeroization hooks. - Add comprehensive unit test suite covering engine boot-up and validation. ([`69e6eeb`](https://github.com/4ami/muraq-kms/commit/69e6eeb1a0662f7934a74315bff3168457f569e0))

* feat(core): implement secure bootstrap protocol and cryptographic primitives

- Add Argon2id passphrase key stretching in crypto/kdf
- Implement AES-GCM-256 envelope encryption for DRS persistence
- Build HKDF-SHA256 subkey isolation for audit and recovery domains
- Create core system bootstrap with automated SQLite storage migrations
- Anchor immutable tamper-evident genesis log with true HMAC signatures ([`02bc2de`](https://github.com/4ami/muraq-kms/commit/02bc2dec0b0229f8b3d0318aaa64463d6d5a623d))

### Fix

* fix: rotation to use unixepoch ([`64f6e6b`](https://github.com/4ami/muraq-kms/commit/64f6e6b2eae60c47accaa98b464beaffae06c217))

* fix: pyptoject.toml ([`7e76d09`](https://github.com/4ami/muraq-kms/commit/7e76d0980879781c21590e72979f1ae2560206db))

* fix(dependency): refactor encryption operation to add dependency to the key involved ([`c5a4050`](https://github.com/4ami/muraq-kms/commit/c5a405042b1b82c31d2cff22893990cf278b11fb))

* fix(bootstrap): refine layout hygiene checks to allow pre-provisioned folders

- Updated is_system_initialized to recognize empty KMS skeleton directories
- Allowed ensure_layout() subdirectory structures to pass fresh boot validation
- Maintained strict security isolation against foreign files and manifest deletion exploits
- Resolved pristine slate test failure caused by structural directory checks ([`9616579`](https://github.com/4ami/muraq-kms/commit/961657996e63755e237ffacae470e81225f6bb60))

### Refactor

* refactor(cli): enhance UI components and secure unseal/repair workflows - Refactor Frame widget to dynamically adjust to terminal size using os.get_terminal_size() - Implement robust ANSI and multi-byte emoji length validation inside Frame to eliminate right-border misalignment - Enhance Spinner context manager to intercept stdout and gracefully handle early returns and error flows - Refactor unseal_kms and RepairService to adopt the new responsive UI component specifications - Fix shell multi-spinner ghosting artifacts during Ctrl+D/EOF exit streams - Update do_clear command to natively flush screens and restore the core application intro layout - Adapt CLI test suites to cleanly match wrapped and colorized terminal outputs ([`cad8f3f`](https://github.com/4ami/muraq-kms/commit/cad8f3f3bcba86e0429902a12a8cd3ba81dc0497))

### Unknown

* Merge pull request #15 from 4ami/development

Development ([`05a61e3`](https://github.com/4ami/muraq-kms/commit/05a61e3017795e4e6c4e472adfc657fc14dc0964))

* Merge pull request #14 from 4ami/development

feat(rotation): integrate automated key rotation with creation flow ([`a10ca56`](https://github.com/4ami/muraq-kms/commit/a10ca5604a4df3e449b33803d819a1607e427d51))

* Merge pull request #13 from 4ami/development

fix(dependency): refactor encryption operation to add dependency to the key involved ([`50bc74e`](https://github.com/4ami/muraq-kms/commit/50bc74eec704a078d8bc6c3edbefe2f559f00802))

* Merge pull request #12 from 4ami/development

feat(crypto): implement CLI message orchestration and stream processing primitives ([`d3084c0`](https://github.com/4ami/muraq-kms/commit/d3084c09050da7cd6ed4ce543b490af4e32dd1d4))

* Merge pull request #11 from 4ami/development

feat(cli): implement key listing and secure key export operations with shell test suite ([`d938cc5`](https://github.com/4ami/muraq-kms/commit/d938cc5f049b08aa6d288c03586c4d9b00a068c7))

* Merge pull request #10 from 4ami/development

feat: refactor KMS CLI commands into unified subparser dispatch architecture ([`97c464b`](https://github.com/4ami/muraq-kms/commit/97c464b0575f3045830e61a9dc4782518bd914f0))

* Merge pull request #9 from 4ami/development

feat(cli): integrate key borrowing loop, add log monitoring, and fix layout constraints ([`7b97b19`](https://github.com/4ami/muraq-kms/commit/7b97b19f36f7d3d68d0fc341bed2657c2e7e3766))

* Merge pull request #8 from 4ami/development

feat: implement core audit and key management backends ([`97e48e3`](https://github.com/4ami/muraq-kms/commit/97e48e3b07eb3184d83bcb74b83f2472934c81a1))

* Merge pull request #7 from 4ami/development

feat: decouple sealed and unsealed runtime shell environments ([`db55662`](https://github.com/4ami/muraq-kms/commit/db55662d6c85a4674f513c91603f83b2b415568e))

* Merge pull request #6 from 4ami/development

feat(policy): implement controlled raw key access and ephemeral lease engine ([`eab6086`](https://github.com/4ami/muraq-kms/commit/eab6086f509801edaa6d77f551f5df6d4ae56b02))

* Merge pull request #5 from 4ami/development

fix(bootstrap): refine layout hygiene checks to allow pre-provisioned folders ([`1c5aab4`](https://github.com/4ami/muraq-kms/commit/1c5aab429dad7c6f6c790c4d8feb9ce00fa9ed4f))

* Merge pull request #4 from 4ami/development

feat(crypto): implement manifest auto-healing and identity spoofing defense ([`a7e6763`](https://github.com/4ami/muraq-kms/commit/a7e676354cd685a8b9cc7f4a180c0c6fa5ac0cfa))

* Merge pull request #3 from 4ami/development

feat(security): implement anti-tamper throttling defense and path sandboxing ([`ac2bfd3`](https://github.com/4ami/muraq-kms/commit/ac2bfd37c31033caa3f9cdda79650cdd65906ba9))

* Merge pull request #2 from 4ami/development

feat(core): implement CoreEngine lifecycle and unseal mechanics ([`dd1fb46`](https://github.com/4ami/muraq-kms/commit/dd1fb46a64311d248888237400479bd216a2e876))

* Merge pull request #1 from 4ami/development

feat(core): implement secure bootstrap protocol and cryptographic primitives ([`0241af7`](https://github.com/4ami/muraq-kms/commit/0241af78c5687c92ff44b35d40075bef480e724a))

* add: KMS storage and tests ([`47f67aa`](https://github.com/4ami/muraq-kms/commit/47f67aa2dd04ebcef0673e1fccfd49d7aaf8748e))
