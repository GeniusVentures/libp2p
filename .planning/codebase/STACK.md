# Technology Stack

**Analysis Date:** 2026-08-26

## Languages

**Primary:**
- C++17 - entire library (`src/`, `include/libp2p/`), enforced via `cmake/toolchain/cxx17.cmake` (`CMAKE_CXX_STANDARD 17`, `CMAKE_CXX_STANDARD_REQUIRED ON`, `CMAKE_CXX_EXTENSIONS OFF`)
- Protobuf IDL - wire message schemas compiled to C++ (`src/**/protobuf/*.proto`)
- Python - housekeeping tooling only, not part of the library (`housekeeping/filter_compile_commands.py`)
- Bash - CI/dev scripts (`housekeeping/clang-tidy.sh`, `housekeeping/codecov.sh`)

## Runtime

**Environment:**
- Native compiled C++ library (static/shared), no language runtime/VM. Target compilers per `README.md`: GCC 7.4, Clang 6.0.1, AppleClang 11.0.

**Package Manager:**
- [Hunter](https://hunter.sh) (CMake-based C++ package manager), bootstrapped in `cmake/Hunter/init.cmake` via `HunterGate` in `cmake/Hunter/HunterGate.cmake`
- Hunter source pinned to a Soramitsu fork: `https://github.com/soramitsu/soramitsu-hunter/archive/v0.23.257-soramitsu31.tar.gz` (SHA1-pinned) in `cmake/Hunter/init.cmake`
- Local override hook: `cmake/Hunter/config.cmake` (empty template for `hunter_config(...)` overrides)
- Optional binary cache: `https://github.com/soramitsu/hunter-binary-cache`, credentials via `GITHUB_HUNTER_USERNAME` / `GITHUB_HUNTER_TOKEN` env vars (`cmake/Hunter/init.cmake`, `docker-compose.yml`)
- Lockfile: none (Hunter pins exact versions/URLs per-package inside `cmake/dependencies.cmake`, no separate lockfile artifact)

## Frameworks

**Core:**
- CMake 3.12+ build system - `CMakeLists.txt` (root), with modular includes in `cmake/` (`libp2p_add_library.cmake`, `install.cmake`, `functions.cmake`, `san.cmake`)
- Boost.DI - dependency injection framework for wiring host/network components, package `Boost.DI` in `cmake/dependencies.cmake`, used throughout `include/libp2p/injector/` and `src/injector/`
- Boost.Asio (via Boost) - async I/O / event loop for all networking (TCP transport, DNS resolution), see `src/network/cares/cares.cpp`, `src/network/impl/dnsaddr_resolver_impl.cpp`, `src/transport/tcp/`

**Testing:**
- GoogleTest / GoogleMock (GTest) - `hunter_add_package(GTest)` gated by `option(TESTING "Build tests" ON)` in `CMakeLists.txt`; test tree under `test/` (mirrors `src/` layout, plus `test/mock`, `test/testutil`, `test/acceptance`)
- CTest - test runner, invoked via `ctest` per `README.md`
- Coverage: `option(COVERAGE "Enable generation of coverage info" OFF)`, `cmake/coverage.cmake`, `cmake/3rdparty/CodeCoverage.cmake`, reported to Codecov (`codecov.yml`, `housekeeping/codecov.sh`, `.github/workflows/coverage.yml`)

**Build/Dev:**
- ccache - auto-detected and wired into compile/link rules if present (`CMakeLists.txt` top)
- clang-format - `option(CLANG_FORMAT "Enable clang-format target" ON)`, config in `.clang-format`, target defined in `cmake/clang-format.cmake`
- clang-tidy - `option(CLANG_TIDY "Enable clang-tidy checks during compilation" OFF)`, config in `cmake/clang-tidy.cmake`, driven by `housekeeping/clang-tidy.sh` and `.github/workflows/clang-tidy.yml`
- Sanitizers - `cmake/san.cmake` + `cmake/san/`, toggled via `ASAN`/`LSAN`/`MSAN`/`TSAN`/`UBSAN` CMake options, applied only to the libp2p target (not dependencies)
- Docker dev container - `docker-compose.yml`, image `soramitsu/kagome-dev:8`, mounts repo at `/app`

## Key Dependencies

**Critical:**
- Boost (`random`, `filesystem`, `program_options` components, plus Asio) - core async networking and utilities, `cmake/dependencies.cmake`
- OpenSSL - cryptographic primitives backing `src/crypto/*_provider` (RSA, ECDSA, Ed25519, secp256k1, AES, ChaChaPoly, HMAC, SHA), `cmake/dependencies.cmake`
- Protobuf - wire-format serialization for protocol messages (`src/**/protobuf/*.proto` → generated C++), `cmake/dependencies.cmake`
- c-ares - async DNS resolution used by `src/network/cares/cares.cpp`, `src/network/impl/dnsaddr_resolver_impl.cpp`
- fmt - string formatting used throughout logging and error messages
- soralog - Soramitsu logging framework, integrated in `include/libp2p/log/` and `src/log/`
- yaml-cpp - YAML config parsing (used by soralog config and/or library config)
- Microsoft.GSL - Guidelines Support Library (span, not_null, etc.) utility types
- tsl_hat_trie (`tsl::htrie_map`) - trie data structure, likely for multiaddress/peer-id lookups (`https://github.com/masterjedy/hat-trie`)
- SQLiteModernCpp - C++ wrapper around SQLite, backing `src/storage/sqlite.cpp` (Soramitsu fork: `https://github.com/soramitsu/libp2p-sqlite-modern-cpp/tree/hunter`)

**Infrastructure:**
- Boost.DI (`https://github.com/masterjedy/di` Soramitsu-hosted fork) - dependency-injection container wiring the whole host/network stack, `include/libp2p/injector/`, `src/injector/`
- Threads (`find_package(Threads)`) - native pthread/Win32 threading support

## Configuration

**Environment:**
- No `.env` files present in this submodule; configuration is entirely CMake-option and env-var driven
- Env vars: `GITHUB_HUNTER_USERNAME`, `GITHUB_HUNTER_TOKEN` (Hunter binary-cache auth, optional) — read in `cmake/Hunter/init.cmake`, passed through in `docker-compose.yml`
- Behavior toggles via CMake options in `CMakeLists.txt`: `TESTING`, `EXAMPLES`, `CLANG_FORMAT`, `CLANG_TIDY`, `COVERAGE`, `ASAN`/`LSAN`/`MSAN`/`TSAN`/`UBSAN`, `EXPOSE_MOCKS`, `METRICS_ENABLED` (adds `LIBP2P_METRICS_ENABLED` compile definition), `LOCAL_BUILD`

**Build:**
- Root `CMakeLists.txt` plus `cmake/` directory: `Hunter/` (package manager bootstrap + per-package overrides), `toolchain/cxx17.cmake` (language standard), `dependencies.cmake` (all third-party packages), `libp2p_add_library.cmake` / `functions.cmake` (internal library/test helper macros), `install.cmake` (install/export rules, `libp2pConfig.cmake.in`), `clang-format.cmake`, `clang-tidy.cmake`, `coverage.cmake`, `san.cmake`, `print.cmake`
- `LOCAL_BUILD` option triggers `cmake/localbuild.cmake` for local (non-CI) build tweaks

## Platform Requirements

**Development:**
- CMake ≥ 3.12, a C++17-capable compiler (GCC 7.4+/Clang 6.0.1+/AppleClang 11.0+), internet access for Hunter package downloads (or a warmed Hunter cache directory)
- Optional Docker workflow via `docker-compose.yml` (`soramitsu/kagome-dev:8` image)

**Production:**
- Consumed as a C++ library dependency (this repo is a git submodule of a parent project — `w:\gnus\GeniusNetwork`); no standalone deployment target of its own. `cmake/install.cmake` provides CMake package export (`libp2pConfig.cmake.in`) for downstream consumers.

---

*Stack analysis: 2026-08-26*
