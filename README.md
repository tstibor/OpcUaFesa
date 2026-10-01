# OpcUaFesa

**Version:** 0.1.1 (matches `OpcUa::version()` in `include/OpcUa/OpcUaClient.hpp`; kept in sync with each `git tag` release)

A lightweight, modern C++17 header-only OPC UA client library for **FESA** (Front-End Software Architecture) equipment classes, built on top of the open-source [`open62541`](https://open62541.org/) stack.

[![CI](https://github.com/tstibor/OpcUaFesa/actions/workflows/ci.yml/badge.svg)](https://github.com/tstibor/OpcUaFesa/actions/workflows/ci.yml)

The badge above reflects the overall workflow status; it does not break out each matrix cell individually. What the matrix (`.github/workflows/ci.yml`) actually covers:

| `open62541` branch | Encryption | Required |
| --- | --- | --- |
| 1.5 | OFF | Yes |
| 1.5 | OPENSSL | Yes |
| master | OFF | No (informational, `continue-on-error`) |
| master | OPENSSL | No (informational, `continue-on-error`) |

## Features

- **Header-only:** Modern C++17 implementation using Standard Library primitives (`std::shared_ptr`, `std::mutex`, `std::unique_ptr`).
- **Type-Safe Wrappers:** Simplified template `read<T>()`/`write<T>()` methods for common OPC UA types (`UA_Boolean`, `UA_Byte`, `UA_Int16`, `UA_Int32`, `UA_Float`), plus `readBatch<T>()`/`writeBatch<T>()` to read or write any number of same-typed nodes in a single OPC UA service call instead of one round trip per node.
- **Thread-Safe Operations:** All client operations and connections are thread-safe out of the box.
- **FESA Integration Ready:** `OpcUa::connectOpcUaClient()` provisions a device's `OpcUa::Client` (anonymous, username/password, and/or SecureChannel security - picked automatically from which of a device's `opcUaUser`/`opcUaPassword`/`opcUaClientCert`/`opcUaServerCert` fields are set) in one call, suited for FESA server/RT class lifecycles (`specificInit()`/`specificShutDown()`); `OpcUa::applyLinkHealthToDevice()` derives a device's status/control fields from OPC UA connection health.
- **Optional SecureChannel Signing/Encryption:** Connect over `SecurityPolicy#Basic256Sha256` (Sign or SignAndEncrypt) with certificate/key material via `OpcUa::SecurityCredentials`, when the linked `open62541` was built with encryption support - fully opt-in, zero impact on existing anonymous/username-password call sites.
- **Automated Mock Test Suite:** Includes a Python `asyncua`-based mock server and Google Test suite (67 tests across 9 suites) for CI/CD integration.

---

## Directory Structure

```text
OpcUaFesa/
├── CMakeLists.txt          # Root CMake build configuration
├── README.md               # Project documentation
├── include/
│   └── OpcUa/
│       └── OpcUaClient.hpp # Core header-only OPC UA client library
├── tests/
│   └── test_opcua_client.cpp # GoogleTest test suite
└── scripts/
    ├── mock_server.py      # Python asyncua mock server for local testing
    ├── sslcert-create.sh   # Generates the self-signed client/server certs below
    └── certs/               # client_cert.der/client_key.pem, server_cert.der/server_key.pem
```
---

## Requirements

* **C++ Compiler:** Supporting C++17 (GCC 7+, Clang 5+)
* **Build System:** CMake 3.14+
* **OPC UA Library:** `open62541` **>= 1.5** (installed on system or FESA environment). Older branches (confirmed against 1.4) lack `UA_ClientConfig::allowNonePolicyPassword`, which this header relies on - a `#error` at the top of `OpcUaClient.hpp` fails the build immediately with this message if built against something older, rather than the much less obvious "no member named `allowNonePolicyPassword`" compiler error you'd otherwise hit. See the CI build matrix (`.github/workflows/ci.yml`) for exactly which branches are actually built and tested against: 1.5 (required) and open62541's `master` (informational, allowed to fail - an early-warning canary for upstream API changes, not a supported target).
* **Python:** 3.8+ (for mock server & testing)
* **Optional, for SecureChannel signing/encryption:** `open62541` built with `-DUA_ENABLE_ENCRYPTION=MBEDTLS` or `OPENSSL` (see `scripts/open62541-build.sh -e <mbedtls|openssl>`). Without it, `OpcUa::Client` still builds and works exactly as before - the `OpcUa::SecurityCredentials`/`OpcUa::SecurityMode` API and every constructor/`getOrCreate()` overload that takes one are compiled out entirely (`#ifdef UA_ENABLE_ENCRYPTION`).

---

## Quick Start & Usage

### 1. Header Inclusion

```cpp
#include <OpcUa/OpcUaClient.hpp>
```

### 2. Connection Lifecycle (`specificInit()`/`specificShutDown()`)

`OpcUa::connectOpcUaClient(device)` is the recommended entry point for a FESA device: it reads a device's `opcUaServerName`/`opcUaServerPort` (endpoint), and `opcUaUser`/`opcUaPassword`/`opcUaClientCert`/`opcUaServerCert` (identity/security - see "4. Username/Password Authentication" and "5. SecureChannel Signing/Encryption" below), and gets-or-creates the right kind of client from the process-wide `OpcUa::ClientRegistry` in one call - no need to pick the right constructor/`getOrCreate()` overload by hand. It only requires those four fields to exist on the device with those names; a project with different device field names can call `OpcUa::ClientRegistry::getOrCreate()` directly instead (see "3. Reading and Writing Data" below).

```cpp
// ServerDeviceClass.cpp
#include <SourceUniversalUnit/Server/ServerDeviceClass.h>
#include <SourceUniversalUnit/Common/OpcUaClient.hpp>

namespace SourceUniversalUnit
{

void ServerDeviceClass::specificInit()
{
    const Devices& deviceCol = SourceUniversalUnitServiceLocator_->getDeviceCollection();
    for (Devices::const_iterator it = deviceCol.begin(); it != deviceCol.end(); ++it)
    {
        try
        {
            Device* device = *it;
            auto opcUaClient = OpcUa::connectOpcUaClient(device);

            LOG_INFO_FORMAT_IF(logger, "Device: %s connected to OPCUA server: %s",
                               device->getName().c_str(), OpcUa::makeOpcUaEndpoint(device).c_str());
        }
        catch (const OpcUa::Exception& exception)
        {
            LOG_ERROR_IF(logger, exception.what());
            /* Swallowed deliberately - one device's failed connection
             * should not prevent the whole FESA class from starting up. */
        }
    }
}

void ServerDeviceClass::specificShutDown()
{
    OpcUa::ClientRegistry::getInstance().releaseAll();
}

} // namespace SourceUniversalUnit
```

### 3. Reading and Writing Data

Once a device is connected (during `specificInit()`, above), any other server/RT action retrieves the *same*, already-connected client from the registry via `OpcUa::ClientRegistry::getInstance().get(endpoint)` (throws if nothing is registered yet for that endpoint) or `.getOrCreate(endpoint)` (connects one if needed):

```cpp
// SettingSetAction.cpp
auto opcUaClient = OpcUa::ClientRegistry::getInstance().get(OpcUa::makeOpcUaEndpoint(pDev));

// Read/write a scalar by tag name (automatically quoted: "A_OUT_0")
int16_t sourceId = opcUaClient->read<UA_Int16>("A_OUT_0");
opcUaClient->write<UA_Int16>("PID_Setpoint", 455);

// Read/write using an exact NodeId string instead (e.g. already contains
// embedded quoting) - readByNodeId()/writeByNodeId() skip the automatic quoting.
float val = opcUaClient->readByNodeId<UA_Float>("\"PID_Setpoint\"");
opcUaClient->writeByNodeId<UA_Float>("\"PID_Setpoint\"", 50.0f);
```

`read<T>()`/`write<T>()` (and `readByNodeId<T>()`/`writeByNodeId<T>()`) cost one OPC UA service round trip *per node*. When reading or writing several same-typed nodes together - e.g. a device's whole block of digital inputs - `readBatch<T>()`/`writeBatch<T>()` (or the NodeId-based `readByNodeIdBatch<T>()`/`writeByNodeIdBatch<T>()`) cover any number of nodes with a single Read/Write service call each, keyed by an `std::unordered_map<std::string, T>`:

```cpp
// StatusUpdateAction.cpp - reading a device's whole digital-input block
// in one call instead of 16 individual read<UA_Boolean>() round trips.
const std::vector<std::string> digitalInputTags = { /* ... resolved from instance data ... */ };
const std::unordered_map<std::string, UA_Boolean> values = opcUaClient->readBatch<UA_Boolean>(digitalInputTags);

// Writing several same-typed nodes in one call works the same way, from a map:
opcUaClient->writeBatch<UA_Int16>({{"A_OUT_0", 111}, {"A_OUT_1", 222}, {"A_OUT_2", 333}});
```

A node that fails within a batch (bad NodeId, type mismatch, ...) throws the same `OpcUa::NodeException` as the single-node `read<T>()`/`write<T>()` would, discarding the whole batch - see the doc comments on `readBatch()`/`readByNodeIdBatch()` in `OpcUaClient.hpp` for the exact semantics. This makes `readBatch()` a drop-in replacement for a loop of individual `read<T>()` calls with unchanged error handling.

### 4. Username/Password Authentication

By default, `OpcUa::Client` connects anonymously. To authenticate with a username and password instead, pass them to the constructor (or to `OpcUa::ClientRegistry::getOrCreate()`); every `connect()` call — including automatic reconnects — will then use that identity:

```cpp
// Direct construction
OpcUa::Client client("opc.tcp://localhost:4840", 3, "myUser", "myPassword");
client.connect();

// Via the registry
auto client = OpcUa::ClientRegistry::getInstance().getOrCreate(
    "opc.tcp://localhost:4840", "myUser", "myPassword");
```

A failed authentication (unknown user or wrong password) throws `OpcUa::ConnectionException`, the same exception type used for other connection failures.

> **Security note:** if the target endpoint only offers `SecurityPolicy#None` (no transport encryption - as the bundled mock server does), the username/password is sent in plaintext. `OpcUa::Client` opts into this automatically (`allowNonePolicyPassword`) so authentication works at all against such endpoints; production servers carrying real secrets should instead enable an encrypted `SecurityPolicy` on the endpoint - see the next section. Some servers (confirmed against a real Siemens S7-1500) require the login itself to be encrypted even while the channel stays `SecurityPolicy#None` - `OpcUa::Client` handles this automatically too (see `registerAuthSecurityPolicies()` in `OpcUaClient.hpp` for the mechanism), no extra caller-side setup needed.

> **Keeping the password out of FESA instance data:** `OpcUa::connectOpcUaClient()` (section 2 above) accepts a `file:`-prefixed local file reference on `opcUaPassword` too, e.g. `file:/etc/opcua/passwd` - the same `kFileUriPrefix` mechanism as `opcUaClientCert`/`opcUaServerCert` (section 5). `connectOpcUaClient()` reads that file's first line as the actual password at connect time (see `OpcUa::resolveFileUriValue()`); the instance data itself only ever holds a path, not the secret. `Client`'s own constructor and `ClientRegistry::getOrCreate()` are unaffected - they still take a plain password string, same as the examples above.

### 5. SecureChannel Signing/Encryption

Requires `open62541` built with encryption support (see Requirements above). Pass an `OpcUa::SecurityCredentials` to connect over `SecurityPolicy#Basic256Sha256` instead of `SecurityPolicy#None` - combine freely with either anonymous or username/password identity, and with `OpcUa::ClientRegistry::getOrCreate()`:

```cpp
OpcUa::SecurityCredentials security;
security.certificateFile               = "/etc/opcua/client_cert.der";
security.privateKeyFile                = "/etc/opcua/client_key.pem";
security.trustedServerCertificateFile  = "/etc/opcua/server_cert.der"; // pinned - the one server cert this client trusts
security.applicationUri                = "urn:fesa:client"; // must match the URI SAN embedded in certificateFile
security.mode                          = OpcUa::SecurityMode::SignAndEncrypt; // or SecurityMode::Sign

// Anonymous + security
OpcUa::Client client("opc.tcp://localhost:4840", 3, security);

// Username/password + security
OpcUa::Client client("opc.tcp://localhost:4840", 3, "myUser", "myPassword", security);

// Via the registry
auto client = OpcUa::ClientRegistry::getInstance().getOrCreate(
    "opc.tcp://localhost:4840", security);

client.connect();
bool secured = client.usesSecurity(); // true
```

Use `scripts/sslcert-create.sh` (run from within `scripts/`) to generate a matching self-signed client/server certificate pair for testing - it writes `certs/client_cert.der`, `certs/client_key.pem`, `certs/server_cert.der`, `certs/server_key.pem`. `applicationUri` must exactly match the `URI:` SubjectAlternativeName entry baked into the client certificate; a mismatch throws `OpcUa::ConnectionException` immediately at construction rather than failing later during `connect()`. The trusted server certificate is certificate *pinning* (this client trusts exactly that one server certificate), not CA-chain validation.

`OpcUa::connectOpcUaClient()` (section 2 above) wires this up automatically too, when a device's `opcUaClientCert`/`opcUaServerCert` fields are both set - either as Base64-encoded DER text directly, or as a `file:`-prefixed local file reference (e.g. `file:/etc/opcua/client_cert.der`, see `OpcUa::isFileUri()`), useful for keeping large certificate blobs out of the instance file entirely. The private key is never FESA instance data either way - see `kOpcUaSecurityMaterialDir`/`kOpcUaClientKeyFileName`/`kOpcUaApplicationUri` in `OpcUaClient.hpp` for where it (and, optionally, `file:`-referenced certificates) are expected: a fixed local directory (`/etc/opcua` by default) on the target's own filesystem, provisioned independently of `yocto-fesa3 release` - deliberately *not* derived from the running binary's own location, since a deploy unit's release tree is commonly NFS-shared (and often read-only), which is fine for public certificate data but not for a private key.

#### Certificates as Base64 text or raw bytes, not just files

Each of the three materials (client certificate, client private key, trusted server certificate) can be sourced three ways instead of just a file - set exactly one of the corresponding `*File`/`*Base64`/`*Bytes` fields per material (setting zero or more than one throws `OpcUa::ConnectionException` at construction):

```cpp
OpcUa::SecurityCredentials security;
// e.g. a FESA device property injected via an instance file - XML can't embed
// raw binary, so the certificate travels as Base64 text:
//   <opcUaClientCert><value>{Base64 DER bytes}</value></opcUaClientCert>
// read at runtime via device->opcUaClientCert.get():
security.certificateBase64             = device->opcUaClientCert.get();
security.privateKeyBase64              = device->opcUaClientKey.get();
security.trustedServerCertificateFile  = "/etc/opcua/server_cert.der"; // materials mix sources freely
security.applicationUri                = "urn:fesa:client";
```

`*Base64` fields are decoded internally via `open62541`'s own `UA_ByteString_fromBase64()` - no extra dependency. `*Bytes` fields (`std::vector<UA_Byte>`) take raw, already-decoded bytes for material your own code already holds in memory (e.g. from a secrets manager). The three materials resolve their sources independently, so a client certificate from a FESA property, a private key from a file, and a trusted server certificate as raw bytes can all be combined on the same `SecurityCredentials`.

### 6. Reporting Connection Health on a Device

`OpcUa::applyLinkHealthToDevice()` derives a FESA device's `status`/`moduleStatus`/`opReady`/`powerState`/`interlock`/`control` fields from OPC UA connection health - ERROR when disconnected, WARNING when connected but node access is failing, OK when fully healthy:

```cpp
// StatusUpdateAction.cpp, after the read/readBatch calls for this device:
OpcUa::applyLinkHealthToDevice<Device, fesa::MultiplexingContext, DEVICE_STATUS::DEVICE_STATUS,
                    MODULE_STATUS::MODULE_STATUS, DEVICE_POWER_STATE::DEVICE_POWER_STATE,
                    DEVICE_CONTROL::DEVICE_CONTROL>(device, context, isConnected, nodeAccessOk);
```

### 7. Reporting Library Versions

`OpcUa::version()` (this header's own version) and `OpcUa::open62541Version()` (the linked `open62541`'s version, forwarded from its own `UA_OPEN62541_VERSION` macro - always reflects whatever a given build actually used) are handy for a FESA class's own version-reporting property:

```cpp
// VersionGetAction.cpp
std::ostringstream componentVersions;
componentVersions << "Client " << OpcUa::version()
                   << ", open62541 " << OpcUa::open62541Version();
data.setComponentVersions(componentVersions.str());
```

## Running the Unit Tests (Step-by-Step)

To run the automated test suite locally, follow these complete setup and execution steps:

### Step 1: Install Python Dependencies

The mock server requires `asyncua`. Install it using `pip`:

```bash
# Direct installation
pip3 install asyncua

# OR using a Virtual Environment (Recommended if using system Python)
python3 -m venv venv
source venv/bin/activate
pip install asyncua
```

### Step 2: Start the Python Mock Server

In your first terminal, launch the mock server from the project root:

```bash
python3 scripts/mock_server.py
```

*Leave this terminal running in the background while executing the tests.*

### Step 3: Build the Test Executable

Open a second terminal window, navigate to the project root directory, and compile the test suite:

```bash
# Create build directory
mkdir -p build && cd build

# Configure build with CMake
cmake ..

# Compile unit tests
make
```

### Step 4: Execute the Tests

You can run the test suite using either `ctest --output-on-failure` or by calling the Google Test binary directly `./opcua_client_tests`. Every GoogleTest `TEST`/`TEST_F` is registered as its own CTest test (via `gtest_discover_tests()`), so `ctest -N` lists all 67 individually and `ctest -R <regex>` filters by suite or test name, e.g. `ctest -R OpcUaClientSecurityTest` runs just that suite's 15 tests - confirmed working identically in both the host-native `build/` and the yocto cross-build with `OPCUA_FESA_RUN_ON_HOST=ON` (see "Cross-Building for the FESA Yocto Target" below).

**To see the SecureChannel signing/encryption actually happening** (or any other test's underlying activity): `ctest` captures a test's stdout/stderr and only prints it *on failure* - `--output-on-failure` shows nothing when everything passes. Use `-V`/`--verbose` instead to always show it, or run the binary directly:

```bash
ctest -V -R OpcUaClientSecurityTest        # verbose, security suite only
# or:
./opcua_client_tests --gtest_filter='OpcUaClientSecurityTest.*'
```

Either way you'll see `open62541`'s own client logger interleaved with GoogleTest's `[ RUN ]`/`[ OK ]` markers, confirming the real negotiated policy per test, e.g.:

```
[ RUN      ] OpcUaClientSecurityTest.AnonymousConnectWithSignAndEncryptSucceeds
...  Endpoint 1 selected with SecurityMode SignAndEncrypt, SecurityPolicy http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256 and UserTokenPolicy anonymous
...  SecureChannel opened with SecurityMode SignAndEncrypt for SecurityPolicy http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256 and a revised lifetime of 600.0s
[       OK ] OpcUaClientSecurityTest.AnonymousConnectWithSignAndEncryptSucceeds (118 ms)
```

---

## Cross-Building for the FESA Yocto Target

The steps above build against a host-native `open62541` (found via the default `find_package(open62541 REQUIRED)` search - e.g. an install under `/usr/local`). To instead build OpcUaFesa - and its test binary - for the actual FESA yocto target (`core2-64-ffos-linux`):

### Step 1: Build `open62541` for the yocto target

```bash
./scripts/open62541-build.sh -e=openssl
```

Installs to `~/install/open62541/<yocto-version>/<open62541-branch>/` (e.g. `~/install/open62541/yocto-5/1.5/`). Check the SDK's manifest for which TLS backend it actually ships before picking `-e`:

```bash
grep -iE "mbedtls|openssl" /common/usr/embedded/yocto/fesa/current/sdk/target.manifest
```

The FESA yocto-5 SDK ships OpenSSL only (no mbedtls), hence `-e=openssl` above; a different SDK/site may differ.

### Step 2: Configure a separate build directory against the SDK

```bash
mkdir -p build-yocto && cd build-yocto
source /common/usr/embedded/yocto/fesa/current/sdk/environment-setup-core2-64-ffos-linux
cmake .. -Dopen62541_DIR=$HOME/install/open62541/yocto-5/1.5/lib/cmake/open62541
```

Use a **fresh** directory, never the host `build/` - CMake caches the detected compiler on first configure, so reusing `build/` would silently keep the host g++ instead of switching to the cross-compiler. `-Dopen62541_DIR` (a plain CMake cache variable, not a CMakeLists.txt change) points `find_package(open62541 REQUIRED)` at the yocto install instead of the host one; no toolchain file is needed for this SDK generation - cross-compilation happens because `environment-setup-core2-64-ffos-linux` exports `CC`/`CXX`/`AR`/etc. as the `x86_64-ffos-linux-*` cross-compiler (with `--sysroot` already baked in), which CMake picks up automatically when configuring a fresh build directory.

### Step 3: Build

```bash
cmake --build . -j"$(nproc)"
```

By default the resulting `opcua_client_tests` (and any consuming FESA binary built the same way) targets the FESA rootfs's glibc/ABI, not this host's, so it won't run directly here - deploy it to the actual target (or a compatible rootfs/emulation) to execute it. `ctest`/`./opcua_client_tests` on the dev host only works for the host-native `build/` from the steps above, unless you opt into Step 4 below.

### Step 4 (optional): Run the cross-compiled binary - and `ctest` - directly on this host

Pass `-DOPCUA_FESA_RUN_ON_HOST=ON` at configure time (Step 2) to link `opcua_client_tests` so it also runs directly on this dev host, without deploying to the target or using qemu/a chroot:

```bash
cmake .. -Dopen62541_DIR=$HOME/install/open62541/yocto-5/1.5/lib/cmake/open62541 -DOPCUA_FESA_RUN_ON_HOST=ON
cmake --build . -j"$(nproc)"
ctest --output-on-failure   # or ./opcua_client_tests directly - both now work here
```

Mechanically, this sets two linker flags on `opcua_client_tests` only (`target_link_options`, not a global setting - the rest of the cross-build, and any other target, is unaffected):

- `-Wl,-dynamic-linker,<...>/sysroots/x86_64-ffossdk-linux/lib/ld-linux-x86-64.so.2` - runs the binary with the SDK's own *native* loader (built to run on a wide range of host distros) instead of this host's, which may not understand symbol versions the cross-compiled binary needs.
- `-Wl,-rpath,<...>/sysroots/core2-64-ffos-linux/usr/lib:<...>/lib` `-Wl,--disable-new-dtags` - points that loader at the *target* sysroot's own `libc`/`libstdc++`/`libssl`/etc. (the exact versions the binary was actually linked against) rather than whatever this host has installed; `--disable-new-dtags` makes it an `RPATH` (applies transitively to every library in the dependency graph) rather than a `RUNPATH` (only the binary's own direct dependencies).

Requires the yocto SDK environment already sourced (`SDKTARGETSYSROOT` set) when `cmake` runs - CMakeLists.txt fails fast with a clear error otherwise. The mock server(s) still need to be started separately (Step 2 of "Running the Unit Tests" above) - `ctest` here just runs against them like the host-native build does.

---

## Test Coverage

`tests/test_opcua_client.cpp` (73 tests across 10 suites):

| Test suite | Covers |
|---|---|
| `OpcUaClientTest` | Anonymous connect/disconnect/reconnect lifecycle, `isConnected()`, destructor safety, `read<T>()`/`write<T>()` for all five supported types (round-tripped through write+read), the dot-separated tag path `"HMIinterface.02-NG02.TFT_Anzeige_NG2Ist1U"` end-to-end via `quoteTagPath()`, type-mismatch/missing-node errors, and concurrent read/write/`isConnected()` access to a single shared client from multiple threads. |
| `OpcUaClientBatchTest` | `readBatch<T>()`/`writeBatch<T>()` and the NodeId-based `readByNodeIdBatch<T>()`/`writeByNodeIdBatch<T>()`: successful multi-node round trips, empty input (no service call made), a missing node or type mismatch discarding the whole batch, the dotted-tag NodeId variant, and disconnected-state errors. |
| `OpcUaClientQuoteTest` | `OpcUa::Client::quoteTagPath()` as a pure function - single-segment tags, dot-separated tag paths, already-quoted passthrough, and consecutive-dot edge cases. No server required. |
| `MakeOpcUaEndpointTest` | `OpcUa::makeOpcUaEndpoint()` endpoint URL formatting, including via a pointer-like handle (e.g. `std::shared_ptr`). No server required. |
| `FileUriTest` | `OpcUa::isFileUri()`/`stripFileUriPrefix()`/`resolveFileUriValue()` as pure functions - detecting the `file:` prefix `connectOpcUaClient()` accepts on `opcUaClientCert`/`opcUaServerCert`/`opcUaPassword` as an alternative to an inline value, stripping it to a bare path, and (for `opcUaPassword`) reading the referenced file's content. No server required. |
| `UpdateDeviceTest` | `OpcUa::applyLinkHealthToDevice()`'s three status branches (disconnected/ERROR, connected-but-node-access-failing/WARNING, healthy/OK) against a lightweight mock FESA device. No server required. |
| `OpcUaClientAuthTest` | Username/password authentication: valid credentials, wrong password, unknown user, credential reuse across reconnects, and via `OpcUa::ClientRegistry`. |
| `OpcUaClientSecurityTest` | SecureChannel signing/encryption (`OpcUa::SecurityCredentials`/`SecurityMode`) combined with anonymous and username/password identity, reconnect behaviour, each material's `*File`/`*Base64`/`*Bytes` source resolved independently, misconfiguration errors (mismatched `applicationUri`, missing cert file, zero/ambiguous source, malformed Base64), and via `OpcUa::ClientRegistry`. Compiled only when `open62541` has encryption support - see Requirements above. |
| `OpcUaClientConnectionFailureTest` | `connect()` against an unreachable endpoint. |
| `OpcUaClientRegistryTest` | `OpcUa::ClientRegistry` get/getOrCreate/release/releaseAll semantics. |

`scripts/mock_server.py` runs **two** independent servers: a plain one on `opc.tcp://127.0.0.1:4840` (`SecurityPolicy#None`, matching all non-`OpcUaClientSecurityTest` suites) and a secured one on `opc.tcp://127.0.0.1:4843` (`SecurityPolicy#Basic256Sha256`, Sign and SignAndEncrypt, using `scripts/certs/server_cert.der`/`server_key.pem`) - see the module's doc comment for why they're kept on separate ports rather than one server offering both. Each exposes eight pre-registered variable nodes (`TestBool`, `TestByte`, `A_OUT_0`/`A_OUT_1`/`A_OUT_2`, `TestInt32`, `PID_Setpoint`, and the dot-separated `HMIinterface.02-NG02.TFT_Anzeige_NG2Ist1U` tag - the three `A_OUT_*` Int16 nodes exist so `OpcUaClientBatchTest` has several same-typed nodes to actually batch together) plus anonymous and username/password (`testuser`/`testpass`) authentication.

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE) (GPL-3.0-or-later).
