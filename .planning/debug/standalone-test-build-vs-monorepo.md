---
status: diagnosed
trigger: "Diagnose why standalone libp2p submodule test build fails while monorepo build (W:\\gnus\\GeniusNetwork\\thirdparty\\build\\Windows) succeeds; classify failures pre-existing vs config; goal find_root_cause_only"
created: 2026-08-26T00:00:00Z
updated: 2026-08-26T12:00:00Z
---

## Current Focus
<!-- OVERWRITE on each update - reflects NOW -->

hypothesis: CONFIRMED — No dependency/Hunter mismatch. Standalone build consumes identical prebuilt deps. Failures are two distinct pre-existing test-code defects that the monorepo build never compiles (TESTING=OFF).
test: CMakeCache comparison + ExternalProject cache file read + 3 single-target builds.
expecting: Got exact expected errors (see Evidence).
next_action: Return ROOT CAUSE FOUND diagnosis (goal: find_root_cause_only).

## Symptoms
<!-- Written during gathering, then IMMUTABLE -->

expected: Standalone submodule build (with tests) should build, pointing at monorepo Hunter dependencies, allowing DI-graph tests (host_injector_test, network_injector_test, muxers_and_streams_test) to verify PermissiveConnectionGater default resolution.
actual: host_injector_test / network_injector_test fail to LINK (unresolved SecMock/Boost.DI symbol); muxers_and_streams_test fails to COMPILE (fmt v10 formatter strictness on regression::Stats::Event). Monorepo build at W:\gnus\GeniusNetwork\thirdparty\build\Windows builds fine (no tests).
errors: LINK: unresolved external SecMock/Boost.DI symbol; COMPILE: fmt v10 formatter error for libp2p::regression::Stats::Event; plus 3-arg dial() call sites, HostMock stale mocks, C++20 designated initializers in other tests.
reproduction: cmake --build w:\gnus\GeniusNetwork\thirdparty\libp2p\build --config Debug --target host_injector_test (etc.)
started: Pre-existing since commit 8640b25 (before phase work), per 01-VERIFICATION.md

## Eliminated
<!-- APPEND only - prevents re-investigating -->

## Evidence
<!-- APPEND only - facts discovered -->

- timestamp: 2026-08-26
  checked: W:\gnus\GeniusNetwork\thirdparty\build\Windows\Debug\libp2p\tmp\libp2p-cache-Debug.cmake (ExternalProject initial-cache for libp2p in monorepo)
  found: `set(HUNTER_ENABLED "OFF" FORCE)`, `set(TESTING "OFF" FORCE)`, `set(BUILD_TESTING "OFF" FORCE)`, `set(EXPOSE_MOCKS "ON" FORCE)`; all deps pinned via `<pkg>_DIR` to monorepo prebuilt dirs (Boost 1.85.0, fmt v10 from .../fmt/lib/cmake/fmt, Boost.DI, soralog, Protobuf, OpenSSL, etc.)
  implication: Monorepo builds libp2p WITHOUT tests; Hunter disabled in both. Standalone is NOT meant to "point to Hunter cache from monorepo" — deps are injected via find_package dirs, and the standalone cache points at the SAME dirs.

- timestamp: 2026-08-26
  checked: Standalone w:\...\libp2p\build\CMakeCache.txt (all *_DIR entries)
  found: Every dependency path identical to monorepo's (Boost 1.85.0, fmt_DIR=.../Windows/Debug/fmt, GTest_DIR=.../GTest, Boost.DI, soralog, tsl_hat_trie, etc.); HUNTER_ENABLED=OFF; TESTING=ON; generator/toolchain identical (VS 17 2022 x64, cxx17.cmake, MultiThreadedDebug). Only diffs: TESTING=ON (vs OFF) and EXPOSE_MOCKS=OFF (vs ON).
  implication: ZERO dependency/version/Hunter mismatch between the two builds. The difference is purely that the monorepo never compiles the test suite.

- timestamp: 2026-08-26
  checked: build\test_bin\Debug contents
  found: host_injector_test.pdb and network_injector_test.pdb exist WITHOUT .exe — compile succeeds, link fails. 40+ other test exes built fine.
  implication: Failures are narrow link/compile defects in specific tests, not a global config problem.

- timestamp: 2026-08-26
  checked: cmake --build build --config Debug --target host_injector_test (fresh run)
  found: LNK2019: unresolved `boost::ext::di::v1_3_0::concepts::abstract_type<HostInjector_CustomAdaptors_Test::TestBody::SecMock>::is_not_bound::error(...)` → LNK1120. Single unresolved symbol.
  implication: Error is in the CustomAdaptors test case (SecMock DI override), NOT the `HostInjector.Default` case which is what the blocked verification needs.

- timestamp: 2026-08-26
  checked: Monorepo Boost.DI header .../Boost.DI/include/boost/di.hpp:1162-1180
  found: `abstract_type<T>::is_not_bound::error(_)` is a `static inline` member that is DECLARED but its body exists only in a commented-out-style trailing definition; it is Boost.DI's intentionally-never-defined "friendly link error" symbol, only instantiated when di cannot resolve a type. MSVC fails to emit the definition when T is a function-local class (SecMock is defined inside TestBody) — known MSVC/template-instantiation limitations with local types as template args in this Boost.DI fork.
  implication: Pre-existing test-code/MSVC incompatibility; the `useSecurityAdaptors<Plaintext, SecMock>` binding with a local class triggers is_not_bound instantiation path. Unrelated to ConnectionGater.

- timestamp: 2026-08-26
  checked: cmake --build build --config Debug --target network_injector_test (fresh run)
  found: Identical LNK2019 for `NetworkBuilder_CustomAdaptorsBuilds_Test::TestBody::SecMock` (same mechanism).
  implication: Same root cause as host_injector_test.

- timestamp: 2026-08-26
  checked: cmake --build build --config Debug --target muxers_and_streams_test (fresh run)
  found: fmt v10 core.h(1600): error C2079 `_ uses undefined struct fmt::v10::detail::type_is_unformattable_for<T,char>` with `T=libp2p::regression::Stats::Event`; core.h(1604): C2338 static_assert "Cannot format an argument. To make type T formattable provide a formatter<T> specialization". Triggered by TRACE("Server event: {}", stats.lastEvent()) at muxers_and_streams_test.cpp:298/318/384/411 — file defines `std::ostream& operator<<(ostream&, Stats::Event)` (line 50) but fmt v10 no longer uses ostream operator<< unless `fmt/ostream.h` is included / formatter specialized.
  implication: Pre-existing incompatibility between the test (written for fmt <9 semantics) and fmt v10 shipped in the monorepo prebuilt deps. Unrelated to ConnectionGater.

- timestamp: 2026-08-26
  checked: git log -1 for each failing file
  found: muxers_and_streams_test.cpp last touched at 1d81f2f "Merged in multi protocol"; host_injector_test.cpp at b653ef9 (soralog migration, old); network_injector_test.cpp at 2ea76cd. All far predate 8640b25 and the current phase. `git status test/` shows no uncommitted modifications.
  implication: Both failure classes exist identically in the baseline; the phase did not introduce them.

## Resolution
<!-- OVERWRITE as understanding evolves -->

root_cause: No build misconfiguration. (1) Standalone and monorepo builds consume byte-identical dependency trees (same *_DIR paths, Boost 1.85.0, fmt v10, HUNTER_ENABLED=OFF in both); the monorepo succeeds solely because it forces TESTING=OFF and never compiles the test suite. (2) The standalone test build's 3 DI-graph test failures are two pre-existing test-code defects: (a) host/network_injector_test: MSVC LNK2019 on Boost.DI's intentionally-undefined `abstract_type<local-class>::is_not_bound::error` triggered by `SecMock` being a function-local class in the CustomAdaptors test cases (pre-existing MSVC/DI incompatibility); (b) muxers_and_streams_test: fmt v10 removed implicit ostream formatting for `Stats::Event`, which only provides `operator<<(std::ostream&, Event)` — needs `#include <fmt/ostream.h>` or a formatter specialization (test predates the fmt v10 dep).
fix: (not applied — find_root_cause_only) Smallest fixes: (a) hoist SecMock/MuxMock/TrMock out of TestBody to namespace scope in the two injector tests, or provide a dummy definition/specialization so the DI error symbol resolves; (b) include <fmt/ostream.h> (via trace.hpp or the test) or add `fmt::formatter<Stats::Event>`.
verification: Fresh single-target builds reproduced exactly one blocking error class per target (verbatim captured above).
files_changed: []
