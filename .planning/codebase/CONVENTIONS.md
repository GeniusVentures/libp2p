# Coding Conventions

**Analysis Date:** 2026-08-26

## Naming Patterns

**Files:**
- `snake_case.hpp` / `snake_case.cpp`, one primary class/interface per file.
- Interfaces live at `include/libp2p/<module>/<name>.hpp` (e.g. `include/libp2p/connection/stream.hpp`).
- Implementations live under `src/<module>/<subsystem>/<name>_impl.cpp` (e.g. `src/crypto/hmac_provider/hmac_provider_impl.cpp`), matched by a header of the same name under `include/libp2p/...`.
- Error definitions: `error.hpp` or `<module>_error.hpp` / `<module>_errors.hpp` per module (e.g. `include/libp2p/crypto/error.hpp`, `include/libp2p/peer/errors.hpp`).
- Test files: `<thing>_test.cpp` (e.g. `test/libp2p/crypto/hmac_test.cpp`).
- Mock files: `test/mock/libp2p/<module>/<name>_mock.hpp`, mirroring the `include/libp2p/<module>/` tree.

**Header guards:**
- `#ifndef LIBP2P_<PATH_COMPONENTS>_HPP` / `#define ...` / `#endif // LIBP2P_..._HPP` (not `#pragma once`). Guard name mirrors path, e.g. `LIBP2P_STREAM_MOCK_HPP`, `LIBP2P_CRYPTO_ERROR_HPP`.

**Namespaces:**
- Root namespace `libp2p`, with nested namespaces per module matching directory structure: `libp2p::crypto`, `libp2p::connection`, `libp2p::crypto::hmac`, etc. Namespace closing braces are commented: `}  // namespace libp2p::connection`.
- `NamespaceIndentation: All` per `.clang-format` — code inside every namespace level is indented.

**Classes / Types:**
- `PascalCase` for classes, structs, enums (`YamuxedConnection`, `HmacProviderImpl`, `CryptoProviderError`).
- Interfaces are abstract base classes named without an `I` prefix (e.g. `Stream`, `Host`); concrete implementations suffixed `Impl` (`BasicHost`, `HmacProviderImpl`) or named for their mechanism (`YamuxedConnection`).
- Mock classes suffixed `Mock` (`StreamMock`, `NetworkMock`), implementing the real interface directly via GMock macros.
- Enum class error codes use `SCREAMING_SNAKE_CASE` values (`INVALID_KEY_TYPE`, `FAILED_INITIALIZE_CONTEXT`), starting at `= 1` (0 reserved for "no error").

**Functions / Methods:**
- `camelCase` for methods and free functions (`calculateDigest`, `getPeerInfo`, `processHeader`).

**Variables:**
- `snake_case` for locals and parameters.
- Private/protected member variables use a **trailing underscore**: `config_`, `connection_`, `scheduler_`, `logger_` — enforced consistently across `src/`.
- Constants use `kPascalCase` (e.g. `YamuxFrame::kInitialWindowSize`).

## Code Style

**Formatting:**
- Enforced via `.clang-format` (root), `BasedOnStyle: Google` with overrides: `NamespaceIndentation: All`, `PointerAlignment: Right` (`Type *var`), `AllowShortFunctionsOnASingleLine: Empty`, `AllowShortIfStatementsOnASingleLine: false`, `BinPackArguments/BinPackParameters: true`.
- 2-space indentation (Google style default), 80-column soft wrap typical of Google style.
- CMake option `CLANG_FORMAT` (default ON) wires a `clang-format` target — run it before committing.

**Linting:**
- `.clang-tidy` (root) enables `clang-analyzer-*, readability-*, modernize-*, boost-*, bugprone-*, cppcoreguidelines-*, google-*, hicpp-*, performance-*` with many project-specific suppressions (see file for exact exclusion list, e.g. `-readability-magic-numbers`, `-hicpp-named-parameter`).
- `WarningsAsErrors` is limited to a small, high-value subset: `modernize-*`, `cppcoreguidelines-*`, `boost-*`, `google-build-using-namespace`, `readability-else-after-return`, `google-readability-todo`.
- `HeaderFilterRegex: 'libp2p/.*\.hpp'` — tidy only enforces on project headers, not third-party/generated code.
- CMake option `CLANG_TIDY` (default OFF) enables tidy-during-compile; test targets call `disable_clang_tidy(${target})` (`cmake/functions.cmake`) to exempt test binaries.

## Import Organization

**Order (observed in test and source files):**
1. The file's own/primary header (e.g. `#include <libp2p/crypto/hmac_provider/hmac_provider_ctr_impl.hpp>`)
2. Blank line, then other project public headers (`libp2p/...`)
3. Third-party headers (`gtest/gtest.h`, `gmock/gmock.h`, `boost/...`, `gsl/...`)
4. Local/relative test-support headers in quotes (`"mock/libp2p/connection/stream_mock.hpp"`, `"testutil/outcome.hpp"`)

`IncludeBlocks: Preserve` in `.clang-format` — the tool does not reorder/merge include groups automatically; manual grouping with blank lines is preserved and expected.

**Path aliases:** None (no path alias/module system); all includes are relative to `include/` or the project root as configured in `CMakeLists.txt`/`include_directories`.

## Error Handling

**Primary mechanism: `outcome::result<T>` (Boost.Outcome), never exceptions for expected failure paths.**
- Each module declares its own scoped `enum class <Module>Error { ... = 1, ... }` in an `error.hpp`/`errors.hpp` file (see `include/libp2p/crypto/error.hpp`, `include/libp2p/peer/errors.hpp`, `include/libp2p/security/error.hpp`).
- Errors registered with `OUTCOME_HPP_DECLARE_ERROR(libp2p::<ns>, <EnumType>)` at file scope, paired with `OUTCOME_CPP_DEFINE_CATEGORY_3` (or similar) in the corresponding `.cpp`.
- Enum values are commented with Doxygen `///<` trailing comments describing the failure.
- Functions returning fallible results use signature `outcome::result<T> doThing(...)`; callers check via `if (!result) { ... result.error() ... }` or via macros.
- Async/callback-based APIs use `outcome::result<T>` as the callback argument type (e.g. `Reader::ReadCallbackFunc = std::function<void(outcome::result<size_t>)>`).
- `assert()` is used for internal invariants that should never be false in correct code (e.g. `assert(scheduler_);` in `src/muxer/yamux/yamuxed_connection.cpp`), not for recoverable/expected errors.

## Logging

**Framework:** Custom `libp2p::log` wrapper (spdlog-based), via `log::createLogger("Name")`.

**Patterns:**
- Static logger created once per translation unit/class: `static auto logger = log::createLogger("YamuxConn");`, typically stored/exposed through a `log_()` accessor.
- Structured logging macros `SL_TRACE`, `SL_DEBUG` (and similarly `SL_INFO`/`SL_WARN`/`SL_ERROR` elsewhere) take the logger then a format string + args: `SL_TRACE(log_(), "read {} bytes from {}", n, remotePeer().value().toBase58());`
- Use `SL_TRACE` for high-frequency internal state tracing, `SL_DEBUG` for notable-but-non-error events (peer disconnects, malformed frames).

## Comments

**Doxygen-style block comments** at file top for licensing:
```cpp
/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
```
Present at the top of essentially every `.hpp`/`.cpp` file — include this exact header (author/year vary by project fork) on new files.

**Doxygen `///` / `///<`** used for brief member/enum-value documentation, not full `@param`/`@return` blocks on most functions (lightweight documentation culture).

**Test-case comments** follow a strict given/when/then Doxygen block immediately above each `TEST`/`TEST_F`:
```cpp
/**
 * @given 20 bytes key, default message
 * @when hmacDigest is applied with hash = kSha1
 * @then obtained digest matches predefined one
 */
TEST_F(HmacTest, HashSha1Success) { ... }
```
This is the dominant test-documentation convention across `test/` — apply it to all new test cases.

## Function Design

**Size:** Small, single-responsibility methods; larger orchestration classes (e.g. `YamuxedConnection`, `KademliaImpl` at 600–900 lines) delegate to private helper methods per concern (`processHeader`, `processData`, `processRst`, `processFin`).

**Parameters:** Heavy use of `std::shared_ptr<Interface>` for injected collaborators (DI-style), passed by value and `std::move`-d into member initializers. Value types (spans, small structs) passed by value or `const &`; mutable buffers via `gsl::span<uint8_t>`.

**Return Values:** `outcome::result<T>` for fallible synchronous calls; `void` + callback (`std::function<void(outcome::result<T>)>`) for async operations.

## Module Design

**Exports:** Public API surface lives entirely under `include/libp2p/`; `src/` contains only implementation `.cpp`/`_impl.hpp` files not intended for external consumption (mirrors the include tree 1:1).

**Dependency Injection:** The project uses Boost.DI-style injectors (`include/libp2p/injector/`) to wire concrete implementations to interfaces at composition-root level — new components should be interface-first (abstract base in `include/libp2p/<module>/`) with a concrete `Impl` registered in the relevant injector.

**Barrel Files:** Not used — each header is included individually; no aggregating "index" headers observed.

---

*Convention analysis: 2026-08-26*
