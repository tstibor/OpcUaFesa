#pragma once

/**
 * @file OpcUaClient.hpp
 * @brief Header-only, thread-safe C++17 wrapper around the open62541 OPC UA
 *        client, tailored for FESA equipment classes.
 *
 * Provides OpcUa::Client for talking to a single OPC UA server endpoint
 * (anonymously or with username/password authentication, optionally over a
 * signed/encrypted SecureChannel - see OpcUa::SecurityCredentials), and
 * OpcUa::ClientRegistry for sharing one Client per endpoint across
 * a FESA server/RT class.
 *
 * SecureChannel signing/encryption (OpcUa::SecurityCredentials,
 * OpcUa::SecurityMode, and every constructor/getOrCreate() overload that
 * takes a SecurityCredentials) is only available when the linked open62541
 * was itself built with encryption support (``-DUA_ENABLE_ENCRYPTION=MBEDTLS``
 * or ``OPENSSL`` - see scripts/open62541-build.sh's ``-e`` flag). That
 * feature surface is compiled out entirely (via `#ifdef UA_ENABLE_ENCRYPTION`)
 * when it isn't, so linking against a non-encryption open62541 build - the
 * default - still works unchanged; existing anonymous/username-password
 * call sites are completely unaffected either way.
 */

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/config.h>
#include <open62541/types.h>
#include <open62541/types_generated.h>

/* Confirmed via CI build matrix (see .github/workflows/ci.yml): open62541
 * 1.4 lacks UA_ClientConfig::allowNonePolicyPassword (used below in
 * applyUsernameIdentityToken()), added upstream between the 1.4 and 1.5
 * release lines. 1.5 and the current development branch both build and
 * pass the full test suite cleanly, so 1.5 is the floor - fail fast with a
 * clear message instead of the much less obvious "no member named
 * allowNonePolicyPassword" compiler error a pre-1.5 build would otherwise
 * hit deep inside this header. */
#if UA_OPEN62541_VER_MAJOR < 1 || (UA_OPEN62541_VER_MAJOR == 1 && UA_OPEN62541_VER_MINOR < 5)
#error "OpcUaFesa requires open62541 >= 1.5 (UA_ClientConfig::allowNonePolicyPassword is not available before 1.5)"
#endif

#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef UA_ENABLE_ENCRYPTION
#include <open62541/plugin/certificategroup.h>
#include <open62541/plugin/securitypolicy_default.h>

#include <cstring>
#include <sstream>
#endif

namespace OpcUa {

/**
 * @brief Version string of this header-only library.
 *
 * Hardcoded rather than derived from git: as a header-only library, this
 * file is often just copied into a consuming project without its
 * CMakeLists.txt or .git history coming along, so there is no reliable
 * build step to run `git describe` in. Instead, this constant is bumped by
 * hand to match the git tag whenever a release is tagged - e.g. after
 * `git tag 1.1.0`, update the string below to "1.1.0" in the same commit.
 */
constexpr const char* version() noexcept { return "0.1.1"; }

/**
 * @brief Version string of the open62541 library this header is compiled
 *        and linked against, e.g. "v1.5.8".
 *
 * Unlike version() this is not hand-maintained: it forwards
 * UA_OPEN62541_VERSION, a macro open62541 itself defines in
 * <open62541/config.h> from its own build, so it always reflects whichever
 * open62541 a given build actually used - useful for logging/diagnostics
 * when a FESA server/RT class starts up.
 */
constexpr const char* open62541Version() noexcept { return UA_OPEN62541_VERSION; }

/**
 * @brief Base exception for all errors raised by Client.
 *
 * The formatted what() message always includes the human-readable name of
 * the underlying open62541 UA_StatusCode, e.g.
 * "Connection to opc.tcp://host:4840 failed (BadConnectionClosed)".
 */
class Exception : public std::runtime_error {
public:
    /**
     * @brief Construct the exception.
     * @param what  Human-readable description of what failed. The
     *              open62541 status code name is appended automatically.
     * @param code  The open62541 status code that caused the failure.
     */
    Exception(const std::string& what, UA_StatusCode code)
        : std::runtime_error(what + " (" + UA_StatusCode_name(code) + ")")
        , code_(code)
    {
    }

    /** @brief The raw open62541 status code that caused this exception. */
    UA_StatusCode code() const noexcept { return code_; }

private:
    /** @brief Raw open62541 status code backing code(). */
    UA_StatusCode code_;
};

/**
 * @brief Thrown when establishing or maintaining the OPC UA session fails.
 *
 * Covers connect() failures (unreachable server, TCP/handshake errors) and
 * authentication failures (unknown user, wrong password, rejected identity
 * token). Never thrown for a failure that is specific to a single node -
 * see NodeException for that.
 */
class ConnectionException : public Exception {
public:
    using Exception::Exception;
};

/**
 * @brief Thrown when a specific node read or write fails, but the link is fine.
 *
 * Examples: the tag/NodeId does not exist on the server, or the value's
 * runtime type does not match the requested C++ type T.
 */
class NodeException : public Exception {
public:
    /**
     * @brief Construct the exception.
     * @param what    Human-readable description of what failed.
     * @param code    The open62541 status code that caused the failure.
     * @param nodeId  The (already-quoted, namespace-qualified) NodeId
     *                string that the failing operation targeted.
     */
    NodeException(const std::string& what, UA_StatusCode code, std::string nodeId)
        : Exception(what, code)
        , nodeId_(std::move(nodeId))
    {
    }

    /** @brief The NodeId string that the failing read/write targeted. */
    const std::string& nodeId() const noexcept { return nodeId_; }

private:
    /** @brief NodeId string backing nodeId(). */
    std::string nodeId_;
};

#ifdef UA_ENABLE_ENCRYPTION

/**
 * @brief SecureChannel protection level requested for a security-enabled
 *        Client (see OpcUa::SecurityCredentials).
 */
enum class SecurityMode {
    /** @brief Messages are signed (tamper-evident) but not encrypted. */
    Sign,
    /** @brief Messages are signed and encrypted - the strongest protection. */
    SignAndEncrypt,
};

/**
 * @brief Certificate/key material and desired protection level for opening
 *        a signed/encrypted OPC UA SecureChannel (SecurityPolicy#Basic256Sha256).
 *
 * Pass one of these to an Client constructor or
 * ClientRegistry::getOrCreate() overload to use transport-level signing
 * and encryption instead of SecurityPolicy#None. Combine freely with either
 * anonymous or username/password identity - SecureChannel security and user
 * identity are independent OPC UA concepts.
 *
 * Each of the three materials below (client certificate, client private key,
 * trusted server certificate) can be sourced three ways - set exactly one of
 * the corresponding `*File`/`*Base64`/`*Bytes` fields per material; setting
 * zero or more than one is rejected at construction time with a clear
 * ConnectionException:
 *  - `*File`:   read from disk once, at Client construction time.
 *               scripts/sslcert-create.sh generates a matching self-signed
 *               client/server certificate pair suitable for use here and by
 *               scripts/mock_server.py.
 *  - `*Base64`: standard Base64 text, decoded internally via open62541's own
 *               UA_ByteString_fromBase64(). Intended for material that
 *               arrives as text rather than a file - e.g. a FESA device
 *               property injected via an instance file, since XML cannot
 *               embed raw binary directly:
 *                   <opcUaClientCert><value>{Base64 DER bytes}</value></opcUaClientCert>
 *               read at runtime via `device->opcUaClientCert.get()` and
 *               assigned straight to certificateBase64.
 *  - `*Bytes`:  raw, already-decoded bytes, for material your own code
 *               already holds in memory (e.g. from a secrets manager).
 */
struct SecurityCredentials {
    /** @brief Path to this client's own certificate (DER-encoded). */
    std::string certificateFile;
    /** @brief This client's own certificate (DER-encoded), as Base64 text. */
    std::string certificateBase64;
    /** @brief This client's own certificate, as raw DER-encoded bytes. */
    std::vector<UA_Byte> certificateBytes;

    /** @brief Path to this client's own private key (PEM or DER). */
    std::string privateKeyFile;
    /** @brief This client's own private key (PEM or DER), as Base64 text. */
    std::string privateKeyBase64;
    /** @brief This client's own private key, as raw PEM/DER-encoded bytes. */
    std::vector<UA_Byte> privateKeyBytes;

    /**
     * @brief Path to the server certificate this client should trust
     *        (DER-encoded). Only connections presenting exactly this
     *        certificate will be accepted - i.e. certificate pinning, not
     *        CA-chain validation.
     */
    std::string trustedServerCertificateFile;
    /** @brief The trusted server certificate (DER-encoded), as Base64 text. */
    std::string trustedServerCertificateBase64;
    /** @brief The trusted server certificate, as raw DER-encoded bytes. */
    std::vector<UA_Byte> trustedServerCertificateBytes;

    /**
     * @brief This client's own ApplicationUri, exactly matching the URI
     *        embedded in the SubjectAlternativeName of the client
     *        certificate (e.g. the "URI:urn:fesa:client" SAN entry
     *        sslcert-create.sh bakes into client_cert.der). open62541
     *        requires this to match the certificate; a mismatch is rejected
     *        at construction time with a clear ConnectionException
     *        rather than failing later, confusingly, during connect().
     */
    std::string applicationUri;
    /** @brief Requested SecureChannel protection level. Defaults to the strongest. */
    SecurityMode mode = SecurityMode::SignAndEncrypt;
};

#endif // UA_ENABLE_ENCRYPTION

/**
 * @brief Build an OPC UA endpoint URL from a FESA device's configuration.
 *
 * Reads the device's opcUaServerName and opcUaServerPort properties and
 * formats them as "opc.tcp://<name>:<port>", suitable for passing directly
 * to the Client constructor or ClientRegistry::getOrCreate().
 *
 * @tparam T          Deduced pointer-like device type; only requires
 *                     ->opcUaServerName.get() and ->opcUaServerPort.get().
 * @param device      Pointer (or pointer-like handle) to the FESA device.
 * @return The formatted "opc.tcp://host:port" endpoint URL.
 */
template <typename T>
inline std::string makeOpcUaEndpoint(T&& device)
{
    return "opc.tcp://" + std::string(device->opcUaServerName.get()) + ":" + std::to_string(device->opcUaServerPort.get());
}

/**
 * @brief Update a FESA device's status/control fields from OPC UA link health.
 *
 * Sets the device unconditionally to REMOTE control (OPC UA communication
 * has no LOCAL mode), records the OPC UA connection and node-access health
 * as detailed-status bits, and then derives status/moduleStatus/opReady/
 * powerState/interlock from @p isConnected and @p nodeAccessOk:
 * - not connected: ERROR/ERROR, not ready, powerState UNKNOWN.
 * - connected but node access failing: WARNING/WARNING, modules ready but
 *   not op-ready, powerState ON.
 * - fully healthy: OK/OK, modules ready and op-ready, powerState ON.
 * interlock is always cleared to false in every branch.
 *
 * @tparam DeviceT         FESA device type exposing control/detailedStatus/
 *                         status/modulesReady/moduleStatus/opReady/
 *                         powerState/interlock setters.
 * @tparam ContextT        FESA context type passed through to every set() call.
 * @tparam DeviceStatusT   Enum type for device->status (ERROR/WARNING/OK).
 * @tparam ModuleStatusT   Enum type for the "OPCUA" moduleStatus entry.
 * @tparam DevicePowerT    Enum type for device->powerState.
 * @tparam DeviceControlT  Enum type for device->control (only REMOTE is used).
 * @param device        Pointer to the FESA device to update.
 * @param context        FESA context forwarded to every set() call.
 * @param isConnected    Whether the OPC UA client connection is up.
 * @param nodeAccessOk   Whether reading/writing the OPC UA nodes succeeded.
 */
template <typename DeviceT, typename ContextT, typename DeviceStatusT, typename ModuleStatusT,
    typename DevicePowerT, typename DeviceControlT>
void applyLinkHealthToDevice(DeviceT* device, const ContextT* context, bool isConnected, bool nodeAccessOk)
{
    /* Since we communicate via OPCUA, there exists only REMOTE mode (no LOCAL). */
    device->control.set(DeviceControlT::REMOTE, context);
    /* OPC UA communication/connection failed. */
    device->detailedStatus.setBit("OPCUA_CONNECTION", isConnected, context);
    /* OPC UA reading/writing nodes failed. */
    device->detailedStatus.setBit("OPCUA_NODE_ACCESS", nodeAccessOk, context);
    if (!isConnected) {
        /* We cannot read any values from the hardware device via OPC UA. */
        device->status.set(DeviceStatusT::ERROR, context);
        device->modulesReady.set(false, context);
        device->moduleStatus.set("OPCUA", ModuleStatusT::ERROR, context);
        device->opReady.set(false, context);
        device->powerState.set(DevicePowerT::UNKNOWN, context);
        device->interlock.set(false, context);
    } else if (!nodeAccessOk) {
        /* We are connected to OPCUA server but cannot read or write (some) nodes. */
        device->status.set(DeviceStatusT::WARNING, context);
        device->modulesReady.set(true, context);
        device->moduleStatus.set("OPCUA", ModuleStatusT::WARNING, context);
        device->opReady.set(false, context);
        device->powerState.set(DevicePowerT::ON, context);
        device->interlock.set(false, context);
    } else {
        device->status.set(DeviceStatusT::OK, context);
        device->modulesReady.set(true, context);
        device->moduleStatus.set("OPCUA", ModuleStatusT::OK, context);
        device->opReady.set(true, context);
        device->powerState.set(DevicePowerT::ON, context);
        device->interlock.set(false, context);
    }
}

/**
 * @brief Thread-safe, single-endpoint OPC UA client.
 *
 * Wraps one open62541 UA_Client connection to a single OPC UA server
 * endpoint. All public operations (connect, disconnect, isConnected, read,
 * write, readBatch, writeBatch) lock an internal mutex, so one Client
 * instance may safely be shared and used concurrently from multiple threads.
 *
 * read()/write() (and readByNodeId()/writeByNodeId()) each cost one OPC UA
 * service round trip per node. When reading or writing several nodes of the
 * same type together - e.g. a device's whole block of digital inputs -
 * prefer readBatch()/writeBatch() (or readByNodeIdBatch()/
 * writeByNodeIdBatch()): they cover any number of nodes with a single
 * Read/Write service call each.
 *
 * Not copyable or movable - the underlying UA_Client owns non-trivial
 * connection state, so instances are meant to be held via
 * std::shared_ptr/std::unique_ptr (see ClientRegistry for a
 * shared-ownership pool keyed by endpoint).
 *
 * By default a client connects anonymously; construct with a
 * username/password to authenticate instead (see the 4-argument
 * constructor and usesCredentials()).
 */
class Client {
public:
    /**
     * @brief Version string of this header-only library.
     *
     * Convenience forwarder to OpcUa::version() - see there for how the
     * value is kept in sync with the project's git tags.
     *
     * @return The version string, e.g. "v1.0.0".
     */
    static constexpr const char* version() noexcept { return OpcUa::version(); }

    /**
     * @brief Construct a client that will connect anonymously.
     * @param endpointUrl      OPC UA server endpoint, e.g. "opc.tcp://host:4840".
     * @param nodeIdNamespace  Namespace index used to qualify every NodeId
     *                         built by read()/write() and readByNodeId()/
     *                         writeByNodeId() (default 3).
     * @throws std::runtime_error if the underlying UA_Client could not be allocated.
     */
    explicit Client(std::string endpointUrl, UA_UInt16 nodeIdNamespace = 3)
        : Client(std::move(endpointUrl), nodeIdNamespace, std::string(), std::string())
    {
    }

    /**
     * @brief Construct a client that authenticates with a username/password
     *        identity token instead of connecting anonymously.
     *
     * If @p username is non-empty, every call to connect() (including
     * reconnects triggered by ClientRegistry) authenticates using
     * @p username / @p password instead of the anonymous identity token.
     *
     * @param endpointUrl      OPC UA server endpoint, e.g. "opc.tcp://host:4840".
     * @param nodeIdNamespace  Namespace index used to qualify every NodeId
     *                         built by read()/write() and readByNodeId()/
     *                         writeByNodeId().
     * @param username         Identity to authenticate as. An empty string
     *                         is equivalent to the anonymous constructor.
     * @param password         Password for @p username.
     * @throws std::runtime_error if the underlying UA_Client could not be allocated.
     */
    Client(std::string endpointUrl, UA_UInt16 nodeIdNamespace, std::string username, std::string password)
        : client_(UA_Client_new(), &UA_Client_delete)
        , endpointUrl_(std::move(endpointUrl))
        , nodeIdNamespace_(nodeIdNamespace)
        , username_(std::move(username))
        , password_(std::move(password))
    {
        if (!client_) {
            throw std::runtime_error("Failed to allocate UA_Client");
        }
        UA_ClientConfig_setDefault(UA_Client_getConfig(client_.get()));
    }

#ifdef UA_ENABLE_ENCRYPTION

    /**
     * @brief Construct a client that connects anonymously over a
     *        signed/encrypted SecureChannel instead of SecurityPolicy#None.
     *
     * @param endpointUrl      OPC UA server endpoint, e.g. "opc.tcp://host:4840".
     * @param nodeIdNamespace  Namespace index used to qualify every NodeId
     *                         built by read()/write() and readByNodeId()/
     *                         writeByNodeId().
     * @param security         Certificate/key material and protection level
     *                         for the SecureChannel - see SecurityCredentials.
     * @throws std::runtime_error if the underlying UA_Client could not be allocated.
     * @throws ConnectionException if a certificate/key file cannot be
     *         read, or @p security.applicationUri does not match the URI
     *         embedded in @p security.certificateFile.
     */
    Client(std::string endpointUrl, UA_UInt16 nodeIdNamespace, SecurityCredentials security)
        : Client(std::move(endpointUrl), nodeIdNamespace, std::string(), std::string(), std::move(security))
    {
    }

    /**
     * @brief Construct a client that authenticates with a username/password
     *        identity token and connects over a signed/encrypted
     *        SecureChannel instead of SecurityPolicy#None.
     *
     * SecureChannel security (@p security) and user identity (@p username /
     * @p password) are independent OPC UA concepts and combine freely, same
     * as the plain 4-argument username/password constructor.
     *
     * @param endpointUrl      OPC UA server endpoint, e.g. "opc.tcp://host:4840".
     * @param nodeIdNamespace  Namespace index used to qualify every NodeId
     *                         built by read()/write() and readByNodeId()/
     *                         writeByNodeId().
     * @param username         Identity to authenticate as. An empty string
     *                         is equivalent to the anonymous 3-argument
     *                         security constructor.
     * @param password         Password for @p username.
     * @param security         Certificate/key material and protection level
     *                         for the SecureChannel - see SecurityCredentials.
     * @throws std::runtime_error if the underlying UA_Client could not be allocated.
     * @throws ConnectionException if a certificate/key file cannot be
     *         read, or @p security.applicationUri does not match the URI
     *         embedded in @p security.certificateFile.
     */
    Client(std::string endpointUrl, UA_UInt16 nodeIdNamespace, std::string username, std::string password, SecurityCredentials security)
        : Client(std::move(endpointUrl), nodeIdNamespace, std::move(username), std::move(password))
    {
        configureSecurity(std::move(security));
    }

#endif // UA_ENABLE_ENCRYPTION

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) = delete;
    Client& operator=(Client&&) = delete;

    /** @brief Disconnect (if connected) and free the underlying UA_Client. Never throws. */
    ~Client()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        /* The client_ is initialized in the constructor and cannot be nullptr. */
        UA_Client_disconnect(client_.get());
    }

    /**
     * @brief Open the connection (and session) to the server.
     *
     * Connects anonymously unless this client was constructed with a
     * non-empty username, in which case the stored username/password
     * identity token is (re-)applied before connecting - so calling
     * connect() again after disconnect() reuses the same identity.
     *
     * @throws ConnectionException if the connection or authentication
     *         attempt fails (e.g. unreachable server, wrong password,
     *         rejected identity token).
     */
    void connect()
    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!username_.empty()) {
            applyUsernameIdentityToken();
        }

        const UA_StatusCode retval = UA_Client_connect(client_.get(), endpointUrl_.c_str());
        if (retval != UA_STATUSCODE_GOOD) {
            const std::string what = username_.empty()
                ? "Connection to " + endpointUrl_ + " failed"
                : "Connection to " + endpointUrl_ + " as user '" + username_ + "' failed";
            throw ConnectionException(what, retval);
        }
    }

    /** @brief True if this client was constructed with a username/password identity. */
    bool usesCredentials() const noexcept { return !username_.empty(); }

    /**
     * @brief True if this client was constructed with SecurityCredentials,
     *        i.e. connects over a signed/encrypted SecureChannel rather
     *        than SecurityPolicy#None. Always false when built against an
     *        open62541 without encryption support.
     */
    bool usesSecurity() const noexcept { return hasSecurity_; }

    /** @brief Close the connection, if open. Safe to call when already disconnected; never throws. */
    void disconnect()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        UA_Client_disconnect(client_.get());
    }

    /**
     * @brief Check whether the client currently has an open, activated session.
     * @return true only if the secure channel is open, the session is
     *         activated, and the last known connection status is good.
     */
    bool isConnected() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);

        UA_SecureChannelState channelState;
        UA_SessionState sessionState;
        UA_StatusCode connectStatus;
        UA_Client_getState(client_.get(), &channelState, &sessionState, &connectStatus);

        return channelState == UA_SECURECHANNELSTATE_OPEN && sessionState == UA_SESSIONSTATE_ACTIVATED && connectStatus == UA_STATUSCODE_GOOD;
    }

    /**
     * @brief Read a scalar value by FESA tag name.
     *
     * Equivalent to readByNodeId(quoteTagPath(tagName)) - the tag name is
     * automatically wrapped in double quotes to form the NodeId string
     * (matching the FESA/SILECS tag-naming convention), then qualified
     * with the namespace index passed to the constructor.
     *
     * @tparam T  One of UA_Boolean, UA_Byte, UA_Int16, UA_Int32, UA_Float.
     * @param tagName  Unquoted tag name, e.g. "A_OUT_0".
     * @return The current value of the node.
     * @throws NodeException if the node does not exist, the read
     *         fails, or the node's runtime type does not match T.
     */
    template <typename T>
    T read(const std::string& tagName)
    {
        return readByNodeId<T>(quoteTagPath(tagName));
    }

    /**
     * @brief Write a scalar value by FESA tag name.
     *
     * Equivalent to writeByNodeId(quoteTagPath(tagName), value).
     *
     * @tparam T  One of UA_Boolean, UA_Byte, UA_Int16, UA_Int32, UA_Float.
     * @param tagName  Unquoted tag name, e.g. "PID_Setpoint".
     * @param value    Value to write.
     * @throws NodeException if the node does not exist or the write fails.
     */
    template <typename T>
    void write(const std::string& tagName, T value)
    {
        writeByNodeId<T>(quoteTagPath(tagName), value);
    }

    /**
     * @brief Read a scalar value using an exact NodeId string.
     *
     * Use this (instead of read()) when the NodeId string is not simply a
     * quoted tag name - e.g. it already contains embedded quoting or other
     * server-specific formatting.
     *
     * @tparam T  One of UA_Boolean, UA_Byte, UA_Int16, UA_Int32, UA_Float.
     * @param nodeIdString  Exact NodeId identifier string, qualified with
     *                      the namespace index passed to the constructor.
     * @return The current value of the node.
     * @throws NodeException if the node does not exist, the read
     *         fails, or the node's runtime type does not match T.
     */
    template <typename T>
    T readByNodeId(const std::string& nodeIdString)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        const UA_DataType& type = uaType<T>();

        UA_NodeId nodeId = UA_NODEID_STRING_ALLOC(nodeIdNamespace_, nodeIdString.c_str());
        UA_Variant value;
        UA_Variant_init(&value);

        const UA_StatusCode retval = UA_Client_readValueAttribute(client_.get(), nodeId, &value);
        UA_NodeId_clear(&nodeId);

        if (retval != UA_STATUSCODE_GOOD) {
            UA_Variant_clear(&value);
            throw NodeException("Failed to read '" + nodeIdString + "'", retval, nodeIdString);
        }
        if (!UA_Variant_hasScalarType(&value, &type)) {
            UA_Variant_clear(&value);
            throw NodeException("Type mismatch reading '" + nodeIdString + "'", UA_STATUSCODE_BADTYPEMISMATCH, nodeIdString);
        }

        T result = *static_cast<T*>(value.data);
        UA_Variant_clear(&value);

        return result;
    }

    /**
     * @brief Write a scalar value using an exact NodeId string.
     *
     * Use this (instead of write()) when the NodeId string is not simply a
     * quoted tag name.
     *
     * @tparam T  One of UA_Boolean, UA_Byte, UA_Int16, UA_Int32, UA_Float.
     * @param nodeIdString  Exact NodeId identifier string, qualified with
     *                      the namespace index passed to the constructor.
     * @param value         Value to write.
     * @throws NodeException if the node does not exist or the write fails.
     */
    template <typename T>
    void writeByNodeId(const std::string& nodeIdString, T value)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        const UA_DataType& type = uaType<T>();

        UA_NodeId nodeId = UA_NODEID_STRING_ALLOC(nodeIdNamespace_, nodeIdString.c_str());
        UA_Variant variant;
        UA_Variant_init(&variant);
        UA_Variant_setScalarCopy(&variant, &value, &type);

        const UA_StatusCode retval = UA_Client_writeValueAttribute(client_.get(), nodeId, &variant);

        UA_Variant_clear(&variant);
        UA_NodeId_clear(&nodeId);

        if (retval != UA_STATUSCODE_GOOD) {
            throw NodeException("Failed to write '" + nodeIdString + "'", retval, nodeIdString);
        }
    }

    /**
     * @brief Read multiple scalar values of the same type in a single OPC UA
     *        Read service call, by FESA tag name.
     *
     * Equivalent to calling read<T>() once per name, but issues exactly one
     * network round trip for the whole batch instead of one per node - see
     * readByNodeIdBatch() for the underlying mechanism and the error-handling
     * semantics this inherits unchanged. Useful for FESA classes that poll
     * many same-typed I/O points every cycle (e.g. StatusUpdateAction reading
     * a device's digital inputs): 16 individual read<UA_Boolean>() calls
     * become one readBatch<UA_Boolean>() call.
     *
     * @tparam T  One of UA_Boolean, UA_Byte, UA_Int16, UA_Int32, UA_Float.
     * @param tagNames  Unquoted tag names to read. A duplicate name is read
     *                  once per occurrence on the wire, but (being a map)
     *                  the returned container naturally collapses it to a
     *                  single entry.
     * @return Map from each requested tag name to its read value; empty if
     *         @p tagNames is empty (no service call is made in that case).
     * @throws ConnectionException if the batch Read service call itself
     *         fails outright (e.g. link down), or returns an unexpected
     *         number of results.
     * @throws NodeException for the first node in the batch whose
     *         individual read failed (bad NodeId, type mismatch, ...) - as
     *         with a plain loop of read<T>() calls, the whole batch is
     *         considered failed and any other, already-read values are
     *         discarded.
     */
    template <typename T>
    std::unordered_map<std::string, T> readBatch(const std::vector<std::string>& tagNames)
    {
        std::vector<std::string> nodeIdStrings;
        nodeIdStrings.reserve(tagNames.size());
        for (const auto& tagName : tagNames) {
            nodeIdStrings.push_back(quoteTagPath(tagName));
        }

        const std::unordered_map<std::string, T> byNodeId = readByNodeIdBatch<T>(nodeIdStrings);

        std::unordered_map<std::string, T> result;
        result.reserve(tagNames.size());
        for (std::size_t i = 0; i < tagNames.size(); ++i) {
            result.emplace(tagNames[i], byNodeId.at(nodeIdStrings[i]));
        }
        return result;
    }

    /**
     * @brief Write multiple scalar values of the same type in a single OPC
     *        UA Write service call, by FESA tag name.
     *
     * Equivalent to calling write<T>() once per entry, but issues exactly
     * one network round trip for the whole batch instead of one per node -
     * see writeByNodeIdBatch() for the underlying mechanism and the
     * error-handling semantics this inherits unchanged.
     *
     * @tparam T  One of UA_Boolean, UA_Byte, UA_Int16, UA_Int32, UA_Float.
     * @param values  Map from unquoted tag name to the value to write.
     * @throws ConnectionException if the batch Write service call
     *         itself fails outright (e.g. link down), or returns an
     *         unexpected number of results.
     * @throws NodeException for the first node in the batch whose
     *         individual write failed (bad NodeId, ...).
     */
    template <typename T>
    void writeBatch(const std::unordered_map<std::string, T>& values)
    {
        std::unordered_map<std::string, T> byNodeId;
        byNodeId.reserve(values.size());
        for (const auto& [tagName, value] : values) {
            byNodeId.emplace(quoteTagPath(tagName), value);
        }
        writeByNodeIdBatch<T>(byNodeId);
    }

    /**
     * @brief Read multiple scalar values of the same type in a single OPC UA
     *        Read service call, using exact NodeId strings.
     *
     * Use this (instead of readBatch()) when the NodeId strings are not
     * simply quoted tag names. Builds one UA_ReadRequest covering every
     * entry in @p nodeIdStrings and issues it via UA_Client_Service_read() -
     * a single request/response round trip regardless of how many nodes are
     * requested, unlike calling readByNodeId() in a loop.
     *
     * @tparam T  One of UA_Boolean, UA_Byte, UA_Int16, UA_Int32, UA_Float.
     * @param nodeIdStrings  Exact NodeId identifier strings, each qualified
     *                       with the namespace index passed to the
     *                       constructor.
     * @return Map from each requested NodeId string to its read value;
     *         empty if @p nodeIdStrings is empty (no service call is made
     *         in that case).
     * @throws ConnectionException if the batch Read service call itself
     *         fails outright (e.g. link down), or returns an unexpected
     *         number of results.
     * @throws NodeException for the first node in the batch whose
     *         individual read failed (bad NodeId, type mismatch, ...) - the
     *         whole batch is considered failed and any other, already-read
     *         values are discarded, matching readByNodeId()'s per-call
     *         all-or-nothing semantics.
     */
    template <typename T>
    std::unordered_map<std::string, T> readByNodeIdBatch(const std::vector<std::string>& nodeIdStrings)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (nodeIdStrings.empty()) {
            return {};
        }

        const UA_DataType& type = uaType<T>();

        std::vector<UA_ReadValueId> readValueIds(nodeIdStrings.size());
        for (std::size_t i = 0; i < nodeIdStrings.size(); ++i) {
            UA_ReadValueId_init(&readValueIds[i]);
            readValueIds[i].nodeId = UA_NODEID_STRING_ALLOC(nodeIdNamespace_, nodeIdStrings[i].c_str());
            readValueIds[i].attributeId = UA_ATTRIBUTEID_VALUE;
        }

        UA_ReadRequest request;
        UA_ReadRequest_init(&request);
        request.timestampsToReturn = UA_TIMESTAMPSTORETURN_NEITHER;
        request.nodesToRead = readValueIds.data();
        request.nodesToReadSize = readValueIds.size();

        UA_ReadResponse response = UA_Client_Service_read(client_.get(), request);

        /* readValueIds is our own std::vector, not something open62541
         * allocated - only clear each entry's own heap-allocated NodeId
         * string here (never the array itself, which std::vector's
         * destructor frees when this function returns). The response, in
         * contrast, IS allocated by open62541 and must go through
         * UA_ReadResponse_clear() - handled by ResponseGuard below. */
        for (auto& readValueId : readValueIds) {
            UA_ReadValueId_clear(&readValueId);
        }

        struct ResponseGuard {
            UA_ReadResponse* response;
            ~ResponseGuard() { UA_ReadResponse_clear(response); }
        } guard { &response };

        if (response.responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
            throw ConnectionException("Batch read failed", response.responseHeader.serviceResult);
        }
        if (response.resultsSize != nodeIdStrings.size()) {
            throw ConnectionException("Batch read returned an unexpected result count", UA_STATUSCODE_BADUNEXPECTEDERROR);
        }

        std::unordered_map<std::string, T> result;
        result.reserve(nodeIdStrings.size());
        for (std::size_t i = 0; i < nodeIdStrings.size(); ++i) {
            const UA_DataValue& dataValue = response.results[i];
            if (dataValue.status != UA_STATUSCODE_GOOD) {
                throw NodeException("Failed to read '" + nodeIdStrings[i] + "'", dataValue.status, nodeIdStrings[i]);
            }
            if (!UA_Variant_hasScalarType(&dataValue.value, &type)) {
                throw NodeException("Type mismatch reading '" + nodeIdStrings[i] + "'", UA_STATUSCODE_BADTYPEMISMATCH, nodeIdStrings[i]);
            }
            result.emplace(nodeIdStrings[i], *static_cast<T*>(dataValue.value.data));
        }
        return result;
    }

    /**
     * @brief Write multiple scalar values of the same type in a single OPC
     *        UA Write service call, using exact NodeId strings.
     *
     * Use this (instead of writeBatch()) when the NodeId strings are not
     * simply quoted tag names. Builds one UA_WriteRequest covering every
     * entry in @p values and issues it via UA_Client_Service_write() - a
     * single request/response round trip regardless of how many nodes are
     * written, unlike calling writeByNodeId() in a loop.
     *
     * @tparam T  One of UA_Boolean, UA_Byte, UA_Int16, UA_Int32, UA_Float.
     * @param values  Map from exact NodeId string to the value to write.
     * @throws ConnectionException if the batch Write service call
     *         itself fails outright (e.g. link down), or returns an
     *         unexpected number of results.
     * @throws NodeException for the first node in the batch whose
     *         individual write failed (bad NodeId, ...).
     */
    template <typename T>
    void writeByNodeIdBatch(const std::unordered_map<std::string, T>& values)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (values.empty()) {
            return;
        }

        const UA_DataType& type = uaType<T>();

        std::vector<std::string> nodeIdStrings;
        nodeIdStrings.reserve(values.size());
        std::vector<UA_WriteValue> writeValues(values.size());

        std::size_t i = 0;
        for (const auto& [nodeIdString, value] : values) {
            nodeIdStrings.push_back(nodeIdString);
            UA_WriteValue_init(&writeValues[i]);
            writeValues[i].nodeId = UA_NODEID_STRING_ALLOC(nodeIdNamespace_, nodeIdString.c_str());
            writeValues[i].attributeId = UA_ATTRIBUTEID_VALUE;
            writeValues[i].value.hasValue = true;
            UA_Variant_setScalarCopy(&writeValues[i].value.value, &value, &type);
            ++i;
        }

        UA_WriteRequest request;
        UA_WriteRequest_init(&request);
        request.nodesToWrite = writeValues.data();
        request.nodesToWriteSize = writeValues.size();

        UA_WriteResponse response = UA_Client_Service_write(client_.get(), request);

        /* writeValues is our own std::vector - see the matching comment in
         * readByNodeIdBatch() for why only each entry is cleared here, never
         * the array itself. */
        for (auto& writeValue : writeValues) {
            UA_WriteValue_clear(&writeValue);
        }

        struct ResponseGuard {
            UA_WriteResponse* response;
            ~ResponseGuard() { UA_WriteResponse_clear(response); }
        } guard { &response };

        if (response.responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
            throw ConnectionException("Batch write failed", response.responseHeader.serviceResult);
        }
        if (response.resultsSize != nodeIdStrings.size()) {
            throw ConnectionException("Batch write returned an unexpected result count", UA_STATUSCODE_BADUNEXPECTEDERROR);
        }

        for (std::size_t j = 0; j < nodeIdStrings.size(); ++j) {
            if (response.results[j] != UA_STATUSCODE_GOOD) {
                throw NodeException("Failed to write '" + nodeIdStrings[j] + "'", response.results[j], nodeIdStrings[j]);
            }
        }
    }

    /** @brief Wrap a dot-separated tag path in Siemens per-segment quoting.
     *
     *  "HMIinterface.02-NG02.TFT_Anzeige_NG2Ist1U"
     *      -> "HMIinterface"."02-NG02"."TFT_Anzeige_NG2Ist1U"
     *
     *  A bare tag without dots yields the previous behaviour:
     *      "Gerät2DI2-1/16" -> "Gerät2DI2-1/16"  (single quoted segment)
     *
     *  A tag that already contains a double quote is assumed to be written in
     *  full Siemens form and is passed through unchanged, which is the only way
     *  to express a symbol whose own name contains a dot.
     */
    static std::string quoteTagPath(const std::string& tagPath)
    {
        if (tagPath.find('"') != std::string::npos) {
            return tagPath;
        }

        std::string quoted;
        quoted.reserve(tagPath.size() + 8);

        std::size_t start = 0;
        while (true) {
            const std::size_t dot = tagPath.find('.', start);
            const std::size_t end = (dot == std::string::npos) ? tagPath.size() : dot;

            if (!quoted.empty()) {
                quoted += '.';
            }
            quoted += '"';
            quoted.append(tagPath, start, end - start);
            quoted += '"';

            if (dot == std::string::npos) {
                break;
            }
            start = dot + 1;
        }

        return quoted;
    }

private:
    /**
     * @brief Maps a C++ scalar type T to its open62541 UA_DataType descriptor.
     *
     * Only declared here; defined via the explicit specializations below
     * for each type supported by read()/write(). Instantiating this
     * primary template (i.e. calling it for an unsupported T) is a link
     * error by design.
     */
    template <typename T>
    static const UA_DataType& uaType();

    /**
     * @brief Install a UserNameIdentityToken (username_/password_) into the
     *        client's config so the next UA_Client_connect() call
     *        authenticates as that user instead of anonymously.
     *
     * Also sets UA_ClientConfig::allowNonePolicyPassword so authentication
     * still works against an endpoint that only offers SecurityPolicy#None
     * (no transport encryption) - open62541 otherwise refuses to send a
     * password in plaintext. Endpoints carrying real secrets should prefer
     * an encrypted SecurityPolicy instead of relying on this override.
     *
     * Caller must hold mutex_.
     */
    void applyUsernameIdentityToken()
    {
        UA_ClientConfig* config = UA_Client_getConfig(client_.get());

        /* This mock/test setup (and possibly some real FESA-side servers)
         * expose the UserName token over SecurityPolicy#None. open62541
         * refuses to transmit credentials in plaintext unless explicitly
         * told to. Real deployments that carry secrets should instead
         * enable transport encryption on the endpoint, but for username
         * authentication to work at all against an unencrypted endpoint
         * this must be opted into. */
        config->allowNonePolicyPassword = true;

#ifdef UA_ENABLE_ENCRYPTION
        /* Some servers - confirmed against a real Siemens S7-1500 - require
         * the UserName token's own password to be encrypted with a crypto
         * SecurityPolicy even when the SecureChannel itself stays
         * SecurityPolicy#None; see registerAuthSecurityPolicies(). */
        registerAuthSecurityPolicies(config);
#endif

        UA_UserNameIdentityToken* identityToken = UA_UserNameIdentityToken_new();
        identityToken->userName = UA_STRING_ALLOC(username_.c_str());
        identityToken->password = UA_STRING_ALLOC(password_.c_str());

        UA_ExtensionObject_clear(&config->userIdentityToken);
        config->userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
        config->userIdentityToken.content.decoded.type = &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN];
        config->userIdentityToken.content.decoded.data = identityToken;
    }

#ifdef UA_ENABLE_ENCRYPTION

    /**
     * @brief Register the standard crypto SecurityPolicy plugins into
     *        config->authSecurityPolicies, for *authenticating* a UserName
     *        identity token - independent of, and regardless of, whatever
     *        SecureChannel security (if any) is otherwise configured.
     *
     * UA_ClientConfig_setDefault() (called from every Client
     * constructor) only ever registers SecurityPolicy#None here. Some OPC
     * UA servers - confirmed against a real Siemens S7-1500 - require a
     * UserName token's password to be encrypted with one of the other
     * standard policies (Basic256Sha256, Aes128Sha256RsaOaep,
     * Aes256Sha256RsaPss, ...) even when the SecureChannel itself is
     * SecurityPolicy#None: OPC UA lets a UserTokenPolicy specify its own
     * securityPolicyUri, independent of the channel's. Without this, every
     * UserTokenPolicy the server advertises for that endpoint gets
     * rejected with "the SecurityPolicy ... is not available", and the
     * connection fails with BadIdentityTokenRejected even though the
     * username/password themselves are entirely correct - live server log:
     *
     *   Endpoint 0: UserTokenPolicy UserName_Basic256Sha256_Token rejected
     *     -- the SecurityPolicy .../Basic256Sha256 is not available
     *   Endpoint 0: Rejected, no matching UserTokenPolicy
     *   No suitable endpoint found
     *
     * These policy instances need *some* local certificate/private key to
     * initialize, even though - being used only to encrypt the password
     * with the *server's* certificate (obtained via GetEndpoints at
     * connect time), never to sign or encrypt the SecureChannel itself -
     * they never actually use it cryptographically. open62541's own
     * addAllSecurityPolicies() doc comment in plugins/ua_config_default.c
     * claims "Certificate and/or privateKey can be NULL and will not be
     * used then", but this does NOT hold for the OpenSSL crypto backend in
     * practice: passing UA_BYTESTRING_NULL for both here was confirmed,
     * via a standalone debug build against the real S7-1500, to make
     * UA_SecurityPolicy_Basic256Sha256() (and the other two) fail their
     * own initialization with BadCertificateInvalid, silently leaving
     * authSecurityPolicies empty and reproducing the exact same
     * BadIdentityTokenRejected symptom this function exists to fix.
     * kAuthOnlyCertificateDer/kAuthOnlyPrivateKeyPem below are a
     * throwaway, non-secret, self-signed placeholder keypair generated
     * solely to satisfy that initialization requirement - never presented
     * to a server as this client's identity (SecureChannel security, when
     * used, is configured separately by configureSecurity() with the
     * caller's real certificate) and never relied on to protect anything.
     *
     * A no-op once config->authSecurityPolicies already holds more than
     * the SecurityPolicy#None default - i.e. on every reconnect after the
     * first call, and whenever configureSecurity() has already populated
     * it with the real client certificate (which covers this same
     * requirement as a side effect - see
     * UA_ClientConfig_setDefaultEncryption()).
     *
     * Caller must hold mutex_.
     */
    static void registerAuthSecurityPolicies(UA_ClientConfig* config)
    {
        if (config->authSecurityPoliciesSize > 1) {
            return;
        }

        /* Deliberately does *not* also add SecurityPolicy#None here:
         * config->securityPolicies already has a None instance (from
         * UA_ClientConfig_setDefault()), and matchUserTokenPolicy()'s
         * lookup already falls back to config->securityPolicies when a
         * SecurityPolicy isn't found in authSecurityPolicies (see
         * ua_client_connect.c). Adding a *second*, independent None
         * instance here caused a real regression: open62541 rejects
         * ActivateSession with BadSecurityPolicyRejected ("SecurityPolicy
         * ... cannot be instantiated. A different SecurityPolicy is in
         * place already") once two distinct SecurityPolicy instances share
         * the same policyUri. */
        constexpr std::size_t maxPolicies = 3;
        UA_SecurityPolicy* policies = static_cast<UA_SecurityPolicy*>(
            UA_malloc(sizeof(UA_SecurityPolicy) * maxPolicies));
        if (!policies) {
            return;
        }

        /* clang-format off */
        static const unsigned char kAuthOnlyCertificateDer[] = {
            0x30, 0x82, 0x03, 0x33, 0x30, 0x82, 0x02, 0x1b, 0xa0, 0x03, 0x02, 0x01,
            0x02, 0x02, 0x14, 0x4f, 0xe2, 0xcd, 0x9c, 0x41, 0x06, 0x8e, 0xa4, 0x80,
            0xcb, 0xfa, 0x05, 0xfa, 0x58, 0x6c, 0xde, 0x7c, 0x21, 0x61, 0x9b, 0x30,
            0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
            0x05, 0x00, 0x30, 0x29, 0x31, 0x27, 0x30, 0x25, 0x06, 0x03, 0x55, 0x04,
            0x03, 0x0c, 0x1e, 0x4f, 0x70, 0x63, 0x55, 0x61, 0x46, 0x65, 0x73, 0x61,
            0x2d, 0x41, 0x75, 0x74, 0x68, 0x4f, 0x6e, 0x6c, 0x79, 0x2d, 0x50, 0x6c,
            0x61, 0x63, 0x65, 0x68, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x30, 0x1e, 0x17,
            0x0d, 0x32, 0x36, 0x30, 0x39, 0x31, 0x38, 0x30, 0x38, 0x31, 0x34, 0x32,
            0x33, 0x5a, 0x17, 0x0d, 0x34, 0x36, 0x30, 0x39, 0x31, 0x33, 0x30, 0x38,
            0x31, 0x34, 0x32, 0x33, 0x5a, 0x30, 0x29, 0x31, 0x27, 0x30, 0x25, 0x06,
            0x03, 0x55, 0x04, 0x03, 0x0c, 0x1e, 0x4f, 0x70, 0x63, 0x55, 0x61, 0x46,
            0x65, 0x73, 0x61, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x4f, 0x6e, 0x6c, 0x79,
            0x2d, 0x50, 0x6c, 0x61, 0x63, 0x65, 0x68, 0x6f, 0x6c, 0x64, 0x65, 0x72,
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
            0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xe2, 0x0e, 0xdc,
            0x26, 0x85, 0xc8, 0x67, 0xa8, 0xb8, 0xb4, 0x7a, 0x05, 0xae, 0x03, 0x3e,
            0x3f, 0x53, 0x9e, 0x3f, 0x34, 0x74, 0xb9, 0xf8, 0x59, 0x2d, 0x6d, 0xbf,
            0xfe, 0x77, 0xd6, 0x3a, 0x92, 0xcd, 0xe5, 0xe3, 0x09, 0x8d, 0xb8, 0x98,
            0x70, 0x33, 0x3d, 0x8b, 0x4f, 0x80, 0x30, 0x78, 0x45, 0x6a, 0x7d, 0xe0,
            0xcf, 0x94, 0x90, 0x62, 0x69, 0x76, 0x2f, 0xa1, 0xb8, 0x52, 0xfe, 0xd4,
            0xc0, 0xf2, 0xe2, 0x7d, 0x7d, 0x9f, 0x83, 0xc9, 0x1d, 0xc1, 0x90, 0x92,
            0xf7, 0x8b, 0x72, 0x71, 0x5d, 0x1a, 0x23, 0x48, 0x85, 0x6c, 0xfc, 0x36,
            0x26, 0x9f, 0x32, 0x46, 0xf4, 0x1b, 0x0b, 0xe3, 0x4e, 0x65, 0x88, 0x14,
            0xa5, 0xc6, 0x22, 0x3e, 0x0c, 0x99, 0xb0, 0xb6, 0xa8, 0x8d, 0xb1, 0x2e,
            0xaf, 0x5c, 0x4b, 0x85, 0x0a, 0xf8, 0x1e, 0xed, 0x5f, 0x17, 0x49, 0xf3,
            0xb6, 0x55, 0x25, 0x3a, 0xc5, 0x06, 0xeb, 0xc1, 0x5d, 0x89, 0x1f, 0x65,
            0xe9, 0xad, 0x75, 0xfc, 0xbc, 0x47, 0xfc, 0x8d, 0xd2, 0x6e, 0xe4, 0xb6,
            0xec, 0x65, 0x44, 0x1f, 0xff, 0x9a, 0x88, 0x55, 0x0b, 0x96, 0xf3, 0xb0,
            0x90, 0xe5, 0x2c, 0xb1, 0x16, 0xee, 0x32, 0xb6, 0xff, 0xb3, 0x0d, 0xe5,
            0xc5, 0xae, 0xa5, 0x5a, 0x24, 0xca, 0x67, 0x16, 0x7e, 0xac, 0xe4, 0xeb,
            0x37, 0x65, 0x83, 0xa8, 0xb1, 0xdb, 0x34, 0x6c, 0xa0, 0x2e, 0x54, 0x79,
            0xe7, 0x71, 0x9e, 0x9c, 0xb3, 0x49, 0x14, 0xaa, 0x43, 0x27, 0x18, 0xa6,
            0x73, 0xcd, 0x6c, 0x02, 0x75, 0x84, 0x6f, 0x58, 0xfd, 0x70, 0x5a, 0xe2,
            0xfb, 0x0e, 0x20, 0x7b, 0xec, 0x8f, 0x3e, 0x7e, 0xf2, 0xa8, 0x18, 0xa1,
            0x86, 0x12, 0x3d, 0xed, 0x30, 0x6c, 0x8c, 0x63, 0xf8, 0x86, 0x35, 0x49,
            0xca, 0x92, 0x1f, 0x25, 0xe2, 0x29, 0x83, 0x42, 0xc8, 0x0b, 0xb9, 0x8e,
            0xd7, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d,
            0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x46, 0xb7, 0x22,
            0x6c, 0x02, 0xc5, 0xac, 0xf6, 0xc8, 0x5b, 0xa2, 0xc7, 0x6b, 0x90, 0x62,
            0x74, 0xca, 0xbe, 0xe3, 0xf3, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
            0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x46, 0xb7, 0x22, 0x6c, 0x02, 0xc5,
            0xac, 0xf6, 0xc8, 0x5b, 0xa2, 0xc7, 0x6b, 0x90, 0x62, 0x74, 0xca, 0xbe,
            0xe3, 0xf3, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
            0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a,
            0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
            0x01, 0x01, 0x00, 0x78, 0x1e, 0xf8, 0x5e, 0xc1, 0xcf, 0xad, 0x9e, 0x26,
            0x56, 0x13, 0x34, 0xca, 0x23, 0xa2, 0x0e, 0xe2, 0xee, 0x8d, 0x47, 0xca,
            0xe2, 0xbd, 0x4c, 0x3c, 0x33, 0xaf, 0x3b, 0xe8, 0xda, 0xb2, 0x49, 0x5e,
            0xc9, 0xdb, 0x1f, 0x2e, 0xc1, 0x68, 0xd6, 0x18, 0x49, 0x5d, 0xa9, 0xd7,
            0xfb, 0xc7, 0xac, 0x2b, 0x6b, 0xda, 0xc9, 0xd3, 0xa5, 0xb3, 0x7a, 0x4f,
            0x1b, 0xa6, 0x98, 0x83, 0x19, 0x55, 0x70, 0x22, 0x59, 0x8b, 0x0c, 0x20,
            0xc3, 0x05, 0x42, 0xaa, 0x34, 0xa2, 0x3a, 0xa2, 0x60, 0x84, 0xe9, 0x60,
            0xc2, 0xb2, 0x96, 0xb0, 0x87, 0xd1, 0xfb, 0xb5, 0x53, 0x91, 0x96, 0xf0,
            0x8a, 0x99, 0x96, 0xaa, 0xbe, 0x3c, 0x64, 0x8f, 0xb1, 0x53, 0x1c, 0xa3,
            0xd6, 0x93, 0xe9, 0x11, 0x6d, 0x36, 0x41, 0x7b, 0xf9, 0xe9, 0xe2, 0xfc,
            0x9a, 0xeb, 0xc9, 0x4a, 0x6d, 0x67, 0xd5, 0x3d, 0x5b, 0x6d, 0x61, 0x1a,
            0xa0, 0xc7, 0x2a, 0x19, 0x04, 0x9e, 0x4a, 0x63, 0x59, 0x25, 0x6c, 0xac,
            0xf2, 0xa5, 0x3c, 0xcd, 0x74, 0x45, 0x1e, 0x6f, 0xdb, 0xda, 0x4b, 0xa6,
            0xa5, 0xc5, 0x41, 0x7a, 0x4b, 0xd7, 0xb4, 0xe2, 0x5e, 0xc8, 0xb8, 0xdf,
            0x70, 0x83, 0xf4, 0xfc, 0x0f, 0x10, 0x36, 0x9d, 0xe2, 0x91, 0x72, 0x52,
            0xb0, 0xa9, 0x2d, 0x54, 0xc0, 0x97, 0x63, 0x68, 0xea, 0xbf, 0x9d, 0x7b,
            0x26, 0xa7, 0xd7, 0x8d, 0xc3, 0xc0, 0x9b, 0x99, 0x16, 0x7c, 0x4d, 0x9d,
            0x3b, 0x31, 0x67, 0xb2, 0x4b, 0x91, 0x04, 0x70, 0x1b, 0xc8, 0xef, 0x8f,
            0x67, 0x8a, 0x07, 0xfc, 0xd9, 0x56, 0x27, 0xb1, 0xfa, 0x52, 0xe5, 0xb1,
            0x1c, 0xb8, 0x4b, 0x90, 0x5c, 0x3f, 0xa7, 0xd8, 0x2f, 0x56, 0xd3, 0x0d,
            0x14, 0x5c, 0x25, 0x3c, 0xab, 0x3c, 0x97, 0x60, 0x9b, 0x88, 0x02, 0x4c,
            0xd8, 0x79, 0xa8, 0x54, 0x81, 0x82, 0x89,
        };
        static const unsigned char kAuthOnlyPrivateKeyPem[] = {
            0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50,
            0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d,
            0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x45, 0x76, 0x77, 0x49, 0x42,
            0x41, 0x44, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47,
            0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x45, 0x46, 0x41, 0x41, 0x53, 0x43,
            0x42, 0x4b, 0x6b, 0x77, 0x67, 0x67, 0x53, 0x6c, 0x41, 0x67, 0x45, 0x41,
            0x41, 0x6f, 0x49, 0x42, 0x41, 0x51, 0x44, 0x69, 0x44, 0x74, 0x77, 0x6d,
            0x68, 0x63, 0x68, 0x6e, 0x71, 0x4c, 0x69, 0x30, 0x0a, 0x65, 0x67, 0x57,
            0x75, 0x41, 0x7a, 0x34, 0x2f, 0x55, 0x35, 0x34, 0x2f, 0x4e, 0x48, 0x53,
            0x35, 0x2b, 0x46, 0x6b, 0x74, 0x62, 0x62, 0x2f, 0x2b, 0x64, 0x39, 0x59,
            0x36, 0x6b, 0x73, 0x33, 0x6c, 0x34, 0x77, 0x6d, 0x4e, 0x75, 0x4a, 0x68,
            0x77, 0x4d, 0x7a, 0x32, 0x4c, 0x54, 0x34, 0x41, 0x77, 0x65, 0x45, 0x56,
            0x71, 0x66, 0x65, 0x44, 0x50, 0x6c, 0x4a, 0x42, 0x69, 0x61, 0x58, 0x59,
            0x76, 0x0a, 0x6f, 0x62, 0x68, 0x53, 0x2f, 0x74, 0x54, 0x41, 0x38, 0x75,
            0x4a, 0x39, 0x66, 0x5a, 0x2b, 0x44, 0x79, 0x52, 0x33, 0x42, 0x6b, 0x4a,
            0x4c, 0x33, 0x69, 0x33, 0x4a, 0x78, 0x58, 0x52, 0x6f, 0x6a, 0x53, 0x49,
            0x56, 0x73, 0x2f, 0x44, 0x59, 0x6d, 0x6e, 0x7a, 0x4a, 0x47, 0x39, 0x42,
            0x73, 0x4c, 0x34, 0x30, 0x35, 0x6c, 0x69, 0x42, 0x53, 0x6c, 0x78, 0x69,
            0x49, 0x2b, 0x44, 0x4a, 0x6d, 0x77, 0x0a, 0x74, 0x71, 0x69, 0x4e, 0x73,
            0x53, 0x36, 0x76, 0x58, 0x45, 0x75, 0x46, 0x43, 0x76, 0x67, 0x65, 0x37,
            0x56, 0x38, 0x58, 0x53, 0x66, 0x4f, 0x32, 0x56, 0x53, 0x55, 0x36, 0x78,
            0x51, 0x62, 0x72, 0x77, 0x56, 0x32, 0x4a, 0x48, 0x32, 0x58, 0x70, 0x72,
            0x58, 0x58, 0x38, 0x76, 0x45, 0x66, 0x38, 0x6a, 0x64, 0x4a, 0x75, 0x35,
            0x4c, 0x62, 0x73, 0x5a, 0x55, 0x51, 0x66, 0x2f, 0x35, 0x71, 0x49, 0x0a,
            0x56, 0x51, 0x75, 0x57, 0x38, 0x37, 0x43, 0x51, 0x35, 0x53, 0x79, 0x78,
            0x46, 0x75, 0x34, 0x79, 0x74, 0x76, 0x2b, 0x7a, 0x44, 0x65, 0x58, 0x46,
            0x72, 0x71, 0x56, 0x61, 0x4a, 0x4d, 0x70, 0x6e, 0x46, 0x6e, 0x36, 0x73,
            0x35, 0x4f, 0x73, 0x33, 0x5a, 0x59, 0x4f, 0x6f, 0x73, 0x64, 0x73, 0x30,
            0x62, 0x4b, 0x41, 0x75, 0x56, 0x48, 0x6e, 0x6e, 0x63, 0x5a, 0x36, 0x63,
            0x73, 0x30, 0x6b, 0x55, 0x0a, 0x71, 0x6b, 0x4d, 0x6e, 0x47, 0x4b, 0x5a,
            0x7a, 0x7a, 0x57, 0x77, 0x43, 0x64, 0x59, 0x52, 0x76, 0x57, 0x50, 0x31,
            0x77, 0x57, 0x75, 0x4c, 0x37, 0x44, 0x69, 0x42, 0x37, 0x37, 0x49, 0x38,
            0x2b, 0x66, 0x76, 0x4b, 0x6f, 0x47, 0x4b, 0x47, 0x47, 0x45, 0x6a, 0x33,
            0x74, 0x4d, 0x47, 0x79, 0x4d, 0x59, 0x2f, 0x69, 0x47, 0x4e, 0x55, 0x6e,
            0x4b, 0x6b, 0x68, 0x38, 0x6c, 0x34, 0x69, 0x6d, 0x44, 0x0a, 0x51, 0x73,
            0x67, 0x4c, 0x75, 0x59, 0x37, 0x58, 0x41, 0x67, 0x4d, 0x42, 0x41, 0x41,
            0x45, 0x43, 0x67, 0x67, 0x45, 0x41, 0x46, 0x31, 0x6c, 0x5a, 0x50, 0x75,
            0x49, 0x4a, 0x6e, 0x44, 0x39, 0x5a, 0x51, 0x30, 0x77, 0x2b, 0x6a, 0x5a,
            0x73, 0x7a, 0x4a, 0x6a, 0x2b, 0x72, 0x6e, 0x74, 0x36, 0x6c, 0x72, 0x49,
            0x48, 0x43, 0x4b, 0x76, 0x47, 0x50, 0x6b, 0x6c, 0x4b, 0x57, 0x76, 0x6a,
            0x70, 0x6b, 0x0a, 0x6c, 0x45, 0x36, 0x61, 0x4d, 0x59, 0x4f, 0x30, 0x45,
            0x62, 0x36, 0x37, 0x30, 0x73, 0x6d, 0x71, 0x34, 0x42, 0x62, 0x45, 0x49,
            0x4c, 0x77, 0x37, 0x61, 0x4c, 0x72, 0x47, 0x63, 0x51, 0x76, 0x46, 0x36,
            0x53, 0x53, 0x52, 0x35, 0x6f, 0x49, 0x41, 0x76, 0x2f, 0x6e, 0x68, 0x44,
            0x2f, 0x7a, 0x57, 0x50, 0x75, 0x56, 0x46, 0x4d, 0x72, 0x57, 0x4e, 0x53,
            0x7a, 0x6c, 0x4d, 0x4e, 0x61, 0x4f, 0x78, 0x0a, 0x56, 0x70, 0x79, 0x66,
            0x31, 0x4d, 0x4a, 0x32, 0x4f, 0x32, 0x59, 0x43, 0x61, 0x6b, 0x46, 0x6f,
            0x75, 0x38, 0x45, 0x62, 0x68, 0x67, 0x62, 0x59, 0x75, 0x63, 0x69, 0x74,
            0x78, 0x38, 0x4b, 0x59, 0x61, 0x30, 0x71, 0x2f, 0x35, 0x39, 0x46, 0x6b,
            0x61, 0x6a, 0x6a, 0x50, 0x76, 0x32, 0x73, 0x44, 0x49, 0x58, 0x71, 0x6d,
            0x48, 0x45, 0x43, 0x48, 0x57, 0x34, 0x36, 0x35, 0x68, 0x34, 0x6a, 0x45,
            0x0a, 0x4e, 0x5a, 0x33, 0x32, 0x77, 0x49, 0x43, 0x49, 0x4b, 0x6f, 0x57,
            0x37, 0x34, 0x42, 0x36, 0x4f, 0x74, 0x47, 0x75, 0x4d, 0x42, 0x48, 0x43,
            0x52, 0x6c, 0x64, 0x2f, 0x2f, 0x4c, 0x65, 0x52, 0x32, 0x51, 0x30, 0x35,
            0x5a, 0x32, 0x77, 0x44, 0x42, 0x49, 0x6f, 0x52, 0x4d, 0x4f, 0x38, 0x51,
            0x64, 0x79, 0x4f, 0x64, 0x61, 0x52, 0x6d, 0x4d, 0x33, 0x70, 0x59, 0x35,
            0x67, 0x51, 0x51, 0x37, 0x6b, 0x0a, 0x5a, 0x52, 0x7a, 0x46, 0x67, 0x2b,
            0x4f, 0x6c, 0x63, 0x2b, 0x58, 0x42, 0x31, 0x69, 0x45, 0x42, 0x33, 0x52,
            0x32, 0x74, 0x38, 0x6a, 0x74, 0x53, 0x5a, 0x4a, 0x34, 0x50, 0x45, 0x33,
            0x66, 0x4c, 0x77, 0x72, 0x62, 0x52, 0x45, 0x68, 0x55, 0x36, 0x75, 0x67,
            0x6d, 0x6d, 0x49, 0x68, 0x69, 0x53, 0x72, 0x4c, 0x6c, 0x42, 0x73, 0x36,
            0x39, 0x6e, 0x4e, 0x7a, 0x47, 0x75, 0x48, 0x4d, 0x4c, 0x79, 0x0a, 0x56,
            0x36, 0x33, 0x69, 0x61, 0x58, 0x36, 0x4d, 0x35, 0x6d, 0x42, 0x74, 0x52,
            0x42, 0x57, 0x54, 0x4d, 0x31, 0x59, 0x44, 0x6a, 0x77, 0x57, 0x4d, 0x5a,
            0x51, 0x32, 0x2f, 0x76, 0x51, 0x54, 0x52, 0x66, 0x50, 0x76, 0x70, 0x72,
            0x61, 0x57, 0x58, 0x43, 0x51, 0x4b, 0x42, 0x67, 0x51, 0x44, 0x34, 0x77,
            0x44, 0x63, 0x72, 0x2b, 0x4c, 0x72, 0x55, 0x56, 0x49, 0x62, 0x36, 0x75,
            0x66, 0x6a, 0x35, 0x0a, 0x69, 0x50, 0x51, 0x37, 0x6b, 0x46, 0x4d, 0x63,
            0x50, 0x41, 0x53, 0x49, 0x38, 0x52, 0x64, 0x34, 0x4a, 0x73, 0x50, 0x6a,
            0x39, 0x4b, 0x32, 0x41, 0x68, 0x75, 0x74, 0x68, 0x48, 0x77, 0x4f, 0x57,
            0x70, 0x58, 0x48, 0x73, 0x4f, 0x59, 0x74, 0x4d, 0x32, 0x36, 0x6b, 0x4d,
            0x74, 0x35, 0x39, 0x46, 0x4e, 0x69, 0x46, 0x73, 0x68, 0x30, 0x38, 0x6c,
            0x32, 0x31, 0x53, 0x6f, 0x37, 0x37, 0x39, 0x5a, 0x0a, 0x73, 0x37, 0x74,
            0x5a, 0x76, 0x48, 0x4c, 0x66, 0x6b, 0x6f, 0x33, 0x4b, 0x30, 0x6d, 0x6d,
            0x6f, 0x49, 0x36, 0x56, 0x48, 0x65, 0x6f, 0x53, 0x4f, 0x65, 0x6d, 0x77,
            0x6e, 0x6d, 0x34, 0x37, 0x4e, 0x78, 0x63, 0x4b, 0x30, 0x34, 0x77, 0x2b,
            0x64, 0x43, 0x61, 0x34, 0x54, 0x38, 0x72, 0x6e, 0x4d, 0x36, 0x52, 0x67,
            0x76, 0x47, 0x47, 0x6a, 0x38, 0x33, 0x49, 0x72, 0x4d, 0x35, 0x6e, 0x69,
            0x70, 0x0a, 0x4d, 0x52, 0x66, 0x31, 0x67, 0x61, 0x49, 0x37, 0x6d, 0x2f,
            0x55, 0x68, 0x32, 0x31, 0x66, 0x4b, 0x7a, 0x68, 0x48, 0x51, 0x59, 0x47,
            0x70, 0x49, 0x47, 0x51, 0x4b, 0x42, 0x67, 0x51, 0x44, 0x6f, 0x70, 0x56,
            0x6a, 0x47, 0x71, 0x6a, 0x66, 0x75, 0x48, 0x63, 0x45, 0x78, 0x31, 0x33,
            0x59, 0x75, 0x70, 0x41, 0x58, 0x38, 0x5a, 0x6d, 0x77, 0x63, 0x7a, 0x6b,
            0x68, 0x73, 0x70, 0x71, 0x4b, 0x4b, 0x0a, 0x31, 0x51, 0x51, 0x79, 0x38,
            0x6e, 0x68, 0x30, 0x74, 0x51, 0x6d, 0x78, 0x32, 0x67, 0x46, 0x37, 0x77,
            0x59, 0x72, 0x65, 0x70, 0x75, 0x66, 0x42, 0x47, 0x74, 0x74, 0x36, 0x31,
            0x37, 0x62, 0x50, 0x37, 0x55, 0x4d, 0x61, 0x79, 0x45, 0x4c, 0x39, 0x2f,
            0x43, 0x54, 0x4f, 0x73, 0x31, 0x46, 0x33, 0x37, 0x36, 0x36, 0x55, 0x31,
            0x76, 0x6b, 0x43, 0x41, 0x44, 0x57, 0x79, 0x64, 0x76, 0x6a, 0x4f, 0x0a,
            0x34, 0x4d, 0x59, 0x43, 0x77, 0x5a, 0x7a, 0x34, 0x49, 0x38, 0x58, 0x65,
            0x34, 0x30, 0x4a, 0x37, 0x69, 0x6e, 0x56, 0x73, 0x41, 0x6b, 0x36, 0x53,
            0x7a, 0x38, 0x6f, 0x37, 0x57, 0x65, 0x64, 0x71, 0x45, 0x71, 0x35, 0x52,
            0x78, 0x72, 0x4e, 0x74, 0x31, 0x7a, 0x68, 0x74, 0x53, 0x43, 0x4d, 0x6d,
            0x6b, 0x37, 0x48, 0x32, 0x51, 0x6c, 0x4a, 0x65, 0x74, 0x4e, 0x30, 0x57,
            0x54, 0x45, 0x70, 0x6d, 0x0a, 0x54, 0x64, 0x35, 0x54, 0x36, 0x30, 0x41,
            0x73, 0x62, 0x77, 0x4b, 0x42, 0x67, 0x51, 0x44, 0x44, 0x66, 0x63, 0x53,
            0x65, 0x55, 0x52, 0x62, 0x37, 0x59, 0x67, 0x62, 0x47, 0x71, 0x7a, 0x74,
            0x70, 0x57, 0x4f, 0x47, 0x67, 0x6f, 0x68, 0x63, 0x2b, 0x2f, 0x45, 0x67,
            0x51, 0x47, 0x33, 0x46, 0x33, 0x59, 0x76, 0x66, 0x57, 0x67, 0x65, 0x65,
            0x4e, 0x4e, 0x2f, 0x74, 0x71, 0x55, 0x34, 0x5a, 0x74, 0x0a, 0x63, 0x55,
            0x36, 0x72, 0x2b, 0x4c, 0x6c, 0x71, 0x53, 0x4d, 0x4e, 0x39, 0x6c, 0x42,
            0x32, 0x65, 0x74, 0x69, 0x44, 0x6b, 0x65, 0x78, 0x36, 0x50, 0x77, 0x4f,
            0x53, 0x79, 0x38, 0x2b, 0x41, 0x74, 0x4c, 0x68, 0x78, 0x53, 0x4e, 0x4e,
            0x45, 0x4f, 0x74, 0x63, 0x32, 0x72, 0x6c, 0x56, 0x75, 0x6c, 0x34, 0x59,
            0x57, 0x32, 0x50, 0x43, 0x70, 0x4c, 0x45, 0x78, 0x6c, 0x47, 0x73, 0x33,
            0x45, 0x79, 0x0a, 0x64, 0x48, 0x5a, 0x46, 0x31, 0x4b, 0x44, 0x6a, 0x71,
            0x4d, 0x54, 0x66, 0x4e, 0x6f, 0x59, 0x67, 0x37, 0x52, 0x75, 0x74, 0x66,
            0x34, 0x43, 0x62, 0x49, 0x50, 0x51, 0x51, 0x66, 0x68, 0x78, 0x62, 0x30,
            0x35, 0x4a, 0x68, 0x78, 0x6d, 0x52, 0x71, 0x64, 0x6e, 0x48, 0x62, 0x44,
            0x74, 0x66, 0x62, 0x4d, 0x63, 0x49, 0x38, 0x51, 0x6c, 0x6d, 0x6b, 0x6d,
            0x51, 0x4b, 0x42, 0x67, 0x51, 0x43, 0x61, 0x0a, 0x64, 0x65, 0x31, 0x54,
            0x4f, 0x59, 0x43, 0x59, 0x33, 0x37, 0x68, 0x39, 0x56, 0x77, 0x68, 0x6f,
            0x50, 0x77, 0x36, 0x61, 0x58, 0x59, 0x59, 0x36, 0x4f, 0x64, 0x74, 0x73,
            0x42, 0x39, 0x61, 0x7a, 0x52, 0x6d, 0x72, 0x62, 0x53, 0x4a, 0x45, 0x68,
            0x4b, 0x33, 0x47, 0x63, 0x57, 0x35, 0x6e, 0x51, 0x69, 0x4e, 0x65, 0x69,
            0x72, 0x44, 0x34, 0x43, 0x76, 0x38, 0x6f, 0x6f, 0x37, 0x54, 0x2b, 0x37,
            0x0a, 0x48, 0x56, 0x51, 0x49, 0x58, 0x42, 0x33, 0x65, 0x63, 0x36, 0x49,
            0x63, 0x65, 0x6f, 0x49, 0x45, 0x6c, 0x32, 0x58, 0x5a, 0x2f, 0x45, 0x43,
            0x6e, 0x53, 0x32, 0x78, 0x62, 0x61, 0x52, 0x49, 0x59, 0x69, 0x4c, 0x50,
            0x75, 0x38, 0x49, 0x30, 0x2f, 0x55, 0x73, 0x44, 0x31, 0x45, 0x76, 0x33,
            0x34, 0x2b, 0x42, 0x79, 0x74, 0x38, 0x58, 0x6f, 0x70, 0x6a, 0x7a, 0x77,
            0x39, 0x32, 0x35, 0x73, 0x42, 0x0a, 0x6d, 0x68, 0x57, 0x53, 0x78, 0x64,
            0x49, 0x72, 0x67, 0x31, 0x45, 0x37, 0x66, 0x55, 0x47, 0x5a, 0x51, 0x30,
            0x5a, 0x4d, 0x73, 0x67, 0x76, 0x75, 0x52, 0x54, 0x62, 0x6b, 0x72, 0x78,
            0x4a, 0x57, 0x69, 0x69, 0x79, 0x71, 0x6d, 0x75, 0x36, 0x6f, 0x6b, 0x51,
            0x4b, 0x42, 0x67, 0x51, 0x44, 0x64, 0x6c, 0x49, 0x32, 0x62, 0x39, 0x63,
            0x7a, 0x48, 0x6d, 0x75, 0x41, 0x68, 0x31, 0x74, 0x65, 0x4a, 0x0a, 0x54,
            0x7a, 0x39, 0x36, 0x6b, 0x66, 0x41, 0x37, 0x63, 0x42, 0x46, 0x58, 0x78,
            0x7a, 0x79, 0x79, 0x34, 0x71, 0x63, 0x46, 0x33, 0x4e, 0x76, 0x43, 0x35,
            0x54, 0x78, 0x64, 0x41, 0x4a, 0x48, 0x64, 0x34, 0x4d, 0x7a, 0x55, 0x6e,
            0x43, 0x66, 0x49, 0x38, 0x73, 0x37, 0x45, 0x38, 0x4d, 0x32, 0x69, 0x59,
            0x37, 0x34, 0x59, 0x4c, 0x50, 0x4c, 0x4b, 0x76, 0x35, 0x42, 0x34, 0x4e,
            0x61, 0x58, 0x6d, 0x0a, 0x46, 0x74, 0x51, 0x32, 0x77, 0x4f, 0x56, 0x33,
            0x47, 0x42, 0x51, 0x70, 0x7a, 0x49, 0x54, 0x33, 0x69, 0x68, 0x58, 0x6b,
            0x75, 0x50, 0x77, 0x32, 0x36, 0x31, 0x6f, 0x78, 0x4a, 0x78, 0x6a, 0x54,
            0x6e, 0x77, 0x68, 0x70, 0x54, 0x6a, 0x77, 0x51, 0x31, 0x62, 0x74, 0x4f,
            0x69, 0x6d, 0x74, 0x31, 0x2f, 0x2f, 0x68, 0x61, 0x78, 0x58, 0x42, 0x6f,
            0x74, 0x2b, 0x69, 0x56, 0x61, 0x67, 0x51, 0x58, 0x0a, 0x48, 0x6e, 0x56,
            0x41, 0x46, 0x46, 0x6c, 0x4f, 0x64, 0x77, 0x6b, 0x73, 0x4d, 0x6a, 0x73,
            0x31, 0x52, 0x59, 0x68, 0x49, 0x71, 0x30, 0x2f, 0x32, 0x71, 0x41, 0x3d,
            0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x50,
            0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d,
            0x2d, 0x2d, 0x2d, 0x0a,
        };
        /* clang-format on */
        UA_ByteString authOnlyCertificate;
        authOnlyCertificate.length = sizeof(kAuthOnlyCertificateDer);
        authOnlyCertificate.data = const_cast<UA_Byte*>(kAuthOnlyCertificateDer);
        UA_ByteString authOnlyPrivateKey;
        authOnlyPrivateKey.length = sizeof(kAuthOnlyPrivateKeyPem);
        authOnlyPrivateKey.data = const_cast<UA_Byte*>(kAuthOnlyPrivateKeyPem);

        std::size_t count = 0;
        if (UA_SecurityPolicy_Basic256Sha256(&policies[count], authOnlyCertificate, authOnlyPrivateKey, config->logging) == UA_STATUSCODE_GOOD) {
            ++count;
        }
        if (UA_SecurityPolicy_Aes256Sha256RsaPss(&policies[count], authOnlyCertificate, authOnlyPrivateKey, config->logging) == UA_STATUSCODE_GOOD) {
            ++count;
        }
        if (UA_SecurityPolicy_Aes128Sha256RsaOaep(&policies[count], authOnlyCertificate, authOnlyPrivateKey, config->logging) == UA_STATUSCODE_GOOD) {
            ++count;
        }

        if (count == 0) {
            UA_free(policies);
            return;
        }

        for (std::size_t i = 0; i < config->authSecurityPoliciesSize; ++i) {
            config->authSecurityPolicies[i].clear(&config->authSecurityPolicies[i]);
        }
        UA_free(config->authSecurityPolicies);

        config->authSecurityPolicies = policies;
        config->authSecurityPoliciesSize = count;
    }

    /**
     * @brief Read an entire file into memory, binary-safe.
     * @throws ConnectionException if @p path cannot be opened.
     */
    static std::string readFile(const std::string& path)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            throw ConnectionException("Failed to open certificate/key file '" + path + "'", UA_STATUSCODE_BADNOTFOUND);
        }
        std::ostringstream contents;
        contents << file.rdbuf();
        return contents.str();
    }

    /** @brief Copy binary-safe @p data into a new, caller-owned UA_ByteString. Never throws. */
    static UA_ByteString toByteString(const std::string& data)
    {
        UA_ByteString result;
        result.length = data.size();
        result.data = data.empty() ? nullptr : static_cast<UA_Byte*>(UA_malloc(data.size()));
        if (result.data) {
            std::memcpy(result.data, data.data(), data.size());
        }
        return result;
    }

    /** @brief Decode Base64 text into raw bytes via open62541's own decoder. @throws ConnectionException on malformed input. */
    static std::string decodeBase64(const std::string& text)
    {
        const UA_String input = UA_STRING(const_cast<char*>(text.c_str()));
        UA_ByteString decoded;
        UA_ByteString_init(&decoded);
        const UA_StatusCode retval = UA_ByteString_fromBase64(&decoded, &input);
        if (retval != UA_STATUSCODE_GOOD) {
            throw ConnectionException("Failed to decode Base64 certificate/key data", retval);
        }
        std::string result(reinterpret_cast<const char*>(decoded.data), decoded.length);
        UA_ByteString_clear(&decoded);
        return result;
    }

    /**
     * @brief Resolve one SecurityCredentials material (client certificate,
     *        private key, or trusted server certificate) to raw bytes, from
     *        whichever of its three `*File`/`*Base64`/`*Bytes` fields is set.
     *
     * @param fieldPrefix  The material's field-name prefix, e.g.
     *                     "certificate" for certificateFile/certificateBase64/
     *                     certificateBytes - used only to name the offending
     *                     field(s) in the exception message.
     * @throws ConnectionException if zero or more than one of the three
     *         source fields is set, the file cannot be read, or the Base64
     *         text is malformed.
     */
    static std::string resolveMaterial(const std::string& fieldPrefix, const std::string& file,
        const std::string& base64, const std::vector<UA_Byte>& bytes)
    {
        const int sourcesSet = (!file.empty() ? 1 : 0) + (!base64.empty() ? 1 : 0) + (!bytes.empty() ? 1 : 0);
        if (sourcesSet != 1) {
            throw ConnectionException(
                "SecurityCredentials." + fieldPrefix + ": exactly one of " + fieldPrefix + "File/"
                    + fieldPrefix + "Base64/" + fieldPrefix + "Bytes must be set (found " + std::to_string(sourcesSet) + ")",
                UA_STATUSCODE_BADINVALIDARGUMENT);
        }

        if (!bytes.empty()) {
            return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        }
        if (!base64.empty()) {
            return decodeBase64(base64);
        }
        return readFile(file);
    }

    /**
     * @brief Load @p security's certificate/key material (from a file,
     *        Base64 text, or raw bytes - see SecurityCredentials) and
     *        configure client_'s config for a signed/encrypted SecureChannel
     *        (SecurityPolicy#Basic256Sha256).
     *
     * Runs once, at construction time - unlike the username identity token
     * (re-applied on every connect()), the SecureChannel security
     * configuration lives on the UA_ClientConfig and is reused across
     * reconnects for as long as this Client exists.
     *
     * Must only be called from a constructor, before this Client is
     * visible to any other thread - unlike the public API, it does not lock
     * mutex_.
     *
     * @throws ConnectionException if a material's source is ambiguous
     *         (see resolveMaterial()), a file cannot be read, Base64 text is
     *         malformed, @p security.applicationUri does not match the URI
     *         embedded in the client certificate, or open62541 rejects the
     *         certificate/key pair.
     */
    void configureSecurity(SecurityCredentials security)
    {
        UA_ByteString certificate = toByteString(
            resolveMaterial("certificate", security.certificateFile, security.certificateBase64, security.certificateBytes));
        UA_ByteString privateKey = toByteString(
            resolveMaterial("privateKey", security.privateKeyFile, security.privateKeyBase64, security.privateKeyBytes));
        UA_ByteString trustedServer = toByteString(
            resolveMaterial("trustedServerCertificate", security.trustedServerCertificateFile,
                security.trustedServerCertificateBase64, security.trustedServerCertificateBytes));

        /* open62541 requires clientDescription.applicationUri to match the
         * URI embedded in the certificate's SubjectAlternativeName - check
         * this explicitly so a mismatch fails loudly here, instead of
         * silently producing a certificate the server later rejects. */
        const UA_String applicationUri = UA_STRING(const_cast<char*>(security.applicationUri.c_str()));
        const UA_StatusCode uriCheck = UA_CertificateUtils_verifyApplicationUri(&certificate, &applicationUri);
        if (uriCheck != UA_STATUSCODE_GOOD) {
            UA_ByteString_clear(&certificate);
            UA_ByteString_clear(&privateKey);
            UA_ByteString_clear(&trustedServer);
            throw ConnectionException(
                "SecurityCredentials.applicationUri '" + security.applicationUri + "' does not match the URI embedded in the configured client certificate",
                uriCheck);
        }

        UA_ClientConfig* config = UA_Client_getConfig(client_.get());
        const UA_StatusCode retval = UA_ClientConfig_setDefaultEncryption(
            config, certificate, privateKey, &trustedServer, 1, nullptr, 0);

        UA_ByteString_clear(&certificate);
        UA_ByteString_clear(&privateKey);
        UA_ByteString_clear(&trustedServer);

        if (retval != UA_STATUSCODE_GOOD) {
            throw ConnectionException("Failed to configure OPC UA transport security for " + endpointUrl_, retval);
        }

        UA_String_clear(&config->clientDescription.applicationUri);
        config->clientDescription.applicationUri = UA_STRING_ALLOC(security.applicationUri.c_str());

        config->securityMode = (security.mode == SecurityMode::SignAndEncrypt)
            ? UA_MESSAGESECURITYMODE_SIGNANDENCRYPT
            : UA_MESSAGESECURITYMODE_SIGN;

        /* Pin the policy explicitly (rather than leaving securityPolicyUri
         * empty, which lets the client auto-select among every endpoint
         * matching securityMode) so which policy gets used is deterministic. */
        UA_String_clear(&config->securityPolicyUri);
        config->securityPolicyUri = UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");

        hasSecurity_ = true;
    }

#endif // UA_ENABLE_ENCRYPTION

    /** @brief Guards every operation on client_ (and the identity token config within it). */
    mutable std::mutex mutex_;
    /** @brief The underlying open62541 client handle; owns the connection/session state. */
    std::unique_ptr<UA_Client, decltype(&UA_Client_delete)> client_;
    /** @brief OPC UA server endpoint this client connects to, e.g. "opc.tcp://host:4840". */
    std::string endpointUrl_;
    /** @brief Namespace index used to qualify every NodeId built by read()/write() and readByNodeId()/writeByNodeId(). */
    UA_UInt16 nodeIdNamespace_;
    /** @brief Username to authenticate as; empty means "connect anonymously" (see usesCredentials()). */
    std::string username_;
    /** @brief Password for username_; only meaningful when username_ is non-empty. */
    std::string password_;
    /** @brief True once configureSecurity() has run (see usesSecurity()). Always false when built without UA_ENABLE_ENCRYPTION. */
    bool hasSecurity_ = false;
};

/** @brief uaType<T>() specialization mapping UA_Boolean to UA_TYPES_BOOLEAN. */
template <>
inline const UA_DataType& Client::uaType<UA_Boolean>() { return UA_TYPES[UA_TYPES_BOOLEAN]; }
/** @brief uaType<T>() specialization mapping UA_Byte to UA_TYPES_BYTE. */
template <>
inline const UA_DataType& Client::uaType<UA_Byte>() { return UA_TYPES[UA_TYPES_BYTE]; }
/** @brief uaType<T>() specialization mapping UA_Int16 to UA_TYPES_INT16. */
template <>
inline const UA_DataType& Client::uaType<UA_Int16>() { return UA_TYPES[UA_TYPES_INT16]; }
/** @brief uaType<T>() specialization mapping UA_Int32 to UA_TYPES_INT32. */
template <>
inline const UA_DataType& Client::uaType<UA_Int32>() { return UA_TYPES[UA_TYPES_INT32]; }
/** @brief uaType<T>() specialization mapping UA_Float to UA_TYPES_FLOAT. */
template <>
inline const UA_DataType& Client::uaType<UA_Float>() { return UA_TYPES[UA_TYPES_FLOAT]; }

/**
 * @brief Registry for Client instances, keyed by endpoint URL.
 *
 * Ensures at most one Client — and therefore one underlying UA_Client
 * connection — exists per endpoint, shared across every caller that asks
 * for it. This is the recommended way to obtain Client instances when
 * more than one endpoint may be in use; OpcUa::connect()/OpcUa::client
 * below are kept only for backward compatibility with single-endpoint code.
 */
class ClientRegistry {
public:
    /** @brief Access the process-wide registry singleton. */
    static ClientRegistry& getInstance()
    {
        static ClientRegistry instance;

        return instance;
    }

    /**
     * @brief Get or create a connected Client for the given endpoint.
     *
     * If no client is registered for @p endpointUrl yet, one is
     * constructed and connect() is called before it is stored. If a
     * client is already registered but has since lost its connection,
     * it is reconnected before being returned.
     *
     * @param endpointUrl      OPC UA server endpoint, e.g. "opc.tcp://host:4840"
     * @param nodeIdNamespace  Namespace index used for node lookups (default 3)
     * @return Shared pointer to the connected, registered client.
     * @throws ConnectionException if a new client's initial connect() fails,
     *         or if reconnecting an existing dropped client fails.
     */
    std::shared_ptr<Client> getOrCreate(const std::string& endpointUrl, UA_UInt16 nodeIdNamespace = 3)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = clients_.find(endpointUrl);
        if (it != clients_.end()) {
            if (!it->second->isConnected()) {
                it->second->connect();
            }

            return it->second;
        }

        auto newClient = std::make_shared<Client>(endpointUrl, nodeIdNamespace);
        newClient->connect();
        clients_.emplace(endpointUrl, newClient);

        return newClient;
    }

    /**
     * @brief Get or create a connected Client authenticating with
     *        @p username / @p password for the given endpoint.
     *
     * Behaves like getOrCreate(), including automatic reconnection using
     * the same credentials if the client has lost its connection. Note the
     * registry key is still the endpoint URL alone, so calling this and
     * the anonymous getOrCreate() for the same endpoint returns the same
     * cached client - whichever call created it first decides the identity.
     *
     * @param endpointUrl      OPC UA server endpoint, e.g. "opc.tcp://host:4840"
     * @param username         Identity to authenticate as.
     * @param password         Password for @p username.
     * @param nodeIdNamespace  Namespace index used for node lookups (default 3)
     * @return Shared pointer to the connected, registered client.
     * @throws ConnectionException if a new client's initial connect() fails
     *         (e.g. wrong password), or if reconnecting an existing dropped
     *         client fails.
     */
    std::shared_ptr<Client> getOrCreate(const std::string& endpointUrl, const std::string& username,
        const std::string& password, UA_UInt16 nodeIdNamespace = 3)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = clients_.find(endpointUrl);
        if (it != clients_.end()) {
            if (!it->second->isConnected()) {
                it->second->connect();
            }

            return it->second;
        }

        auto newClient = std::make_shared<Client>(endpointUrl, nodeIdNamespace, username, password);
        newClient->connect();
        clients_.emplace(endpointUrl, newClient);

        return newClient;
    }

#ifdef UA_ENABLE_ENCRYPTION

    /**
     * @brief Get or create a connected Client that connects anonymously
     *        over a signed/encrypted SecureChannel for the given endpoint.
     *
     * Behaves like getOrCreate(), including automatic reconnection (reusing
     * the same SecurityCredentials) if the client has lost its connection.
     *
     * @param endpointUrl      OPC UA server endpoint, e.g. "opc.tcp://host:4840"
     * @param security         Certificate/key material and protection level
     *                         for the SecureChannel - see SecurityCredentials.
     * @param nodeIdNamespace  Namespace index used for node lookups (default 3)
     * @return Shared pointer to the connected, registered client.
     * @throws ConnectionException if a new client's initial connect() fails,
     *         or if reconnecting an existing dropped client fails.
     */
    std::shared_ptr<Client> getOrCreate(const std::string& endpointUrl, const SecurityCredentials& security, UA_UInt16 nodeIdNamespace = 3)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = clients_.find(endpointUrl);
        if (it != clients_.end()) {
            if (!it->second->isConnected()) {
                it->second->connect();
            }

            return it->second;
        }

        auto newClient = std::make_shared<Client>(endpointUrl, nodeIdNamespace, security);
        newClient->connect();
        clients_.emplace(endpointUrl, newClient);

        return newClient;
    }

    /**
     * @brief Get or create a connected Client authenticating with
     *        @p username / @p password over a signed/encrypted SecureChannel
     *        for the given endpoint.
     *
     * Behaves like getOrCreate(), including automatic reconnection using the
     * same credentials and SecurityCredentials if the client has lost its
     * connection.
     *
     * @param endpointUrl      OPC UA server endpoint, e.g. "opc.tcp://host:4840"
     * @param username         Identity to authenticate as.
     * @param password         Password for @p username.
     * @param security         Certificate/key material and protection level
     *                         for the SecureChannel - see SecurityCredentials.
     * @param nodeIdNamespace  Namespace index used for node lookups (default 3)
     * @return Shared pointer to the connected, registered client.
     * @throws ConnectionException if a new client's initial connect() fails
     *         (e.g. wrong password), or if reconnecting an existing dropped
     *         client fails.
     */
    std::shared_ptr<Client> getOrCreate(const std::string& endpointUrl, const std::string& username,
        const std::string& password, const SecurityCredentials& security, UA_UInt16 nodeIdNamespace = 3)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = clients_.find(endpointUrl);
        if (it != clients_.end()) {
            if (!it->second->isConnected()) {
                it->second->connect();
            }

            return it->second;
        }

        auto newClient = std::make_shared<Client>(endpointUrl, nodeIdNamespace, username, password, security);
        newClient->connect();
        clients_.emplace(endpointUrl, newClient);

        return newClient;
    }

#endif // UA_ENABLE_ENCRYPTION

    /**
     * @brief Get an already-registered client without creating one.
     *
     * @param endpointUrl  OPC UA server endpoint previously passed to getOrCreate().
     * @return Shared pointer to the registered client (its connection state is not checked).
     * @throws std::runtime_error if no client is registered for @p endpointUrl.
     */
    std::shared_ptr<Client> get(const std::string& endpointUrl)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = clients_.find(endpointUrl);
        if (it == clients_.end()) {
            throw std::runtime_error("ClientRegistry: no client registered for endpoint: " + endpointUrl);
        }

        return it->second;
    }

    /**
     * @brief Disconnect and remove a single client.
     * @param endpointUrl  OPC UA server endpoint to release. A no-op (does
     *                     not throw) if no client is registered for it.
     */
    void release(const std::string& endpointUrl)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = clients_.find(endpointUrl);
        if (it != clients_.end()) {
            it->second->disconnect();
            clients_.erase(it);
        }
    }

    /**
     * @brief Disconnect and remove all registered clients.
     *
     * Intended for use from specificShutDown().
     */
    void releaseAll()
    {
        std::lock_guard<std::mutex> lock(mutex_);

        for (auto& [endpointUrl, client] : clients_) {
            client->disconnect();
        }
        clients_.clear();
    }

private:
    /** @brief Private - use getInstance() to access the singleton. */
    ClientRegistry() = default;
    /** @brief Private - registered clients are disconnected individually via release()/releaseAll(); the process teardown handles the rest. */
    ~ClientRegistry() = default;
    ClientRegistry(const ClientRegistry&) = delete;
    ClientRegistry& operator=(const ClientRegistry&) = delete;

    /** @brief Guards clients_ against concurrent getOrCreate()/get()/release()/releaseAll() calls. */
    std::mutex mutex_;
    /** @brief One Client per endpoint URL, shared with every caller that has obtained it. */
    std::unordered_map<std::string, std::shared_ptr<Client>> clients_;
};

/**
 * @brief Local, non-shared directory expected to hold OPC UA security
 *        material for connectOpcUaClient() below: the private key
 *        (kOpcUaClientKeyFileName) always, and optionally the client/
 *        trusted-server certificates too, if a device's opcUaClientCert/
 *        opcUaServerCert field uses the kFileUriPrefix form instead of
 *        carrying Base64 data inline (see isFileUri()).
 *
 * Deliberately a fixed local path rather than derived from the running
 * binary's own location (e.g. via /proc/self/exe): a FESA deploy unit's
 * binary is itself reached through yocto-fesa3's release tree, which is
 * commonly NFS-mounted (often read-only) and readable by everyone with
 * access to that mount - fine for the certificates (public data) but not
 * for the private key. kOpcUaSecurityMaterialDir instead names a path on
 * the target's own local root filesystem, provisioned independently of
 * yocto-fesa3 release (e.g. scp'd directly onto each target) and outside
 * any NFS-shared tree. Adjust to match your own provisioning convention if
 * this path differs on your targets.
 */
constexpr const char* kOpcUaSecurityMaterialDir = "/etc/opcua";

/**
 * @brief File name, under kOpcUaSecurityMaterialDir, expected to hold the
 *        private key matching whatever client certificate a device
 *        presents via its opcUaClientCert field (see connectOpcUaClient()
 *        below) - SecurityCredentials always needs all three materials
 *        (certificate, private key, trusted server certificate) together,
 *        never just the certificate on its own.
 *
 * Unlike the client/trusted-server certificates (public data, so
 * connectOpcUaClient() accepts them either as ordinary FESA instance data
 * or, via kFileUriPrefix, as a local file reference), the private key is
 * secret and typically shared by every device on a FEC, so it is always
 * expected as a plain file under kOpcUaSecurityMaterialDir instead -
 * never as FESA instance data. yocto-fesa3's `release` operation has no
 * knowledge of this file or this directory; provisioning it onto each
 * target is entirely outside yocto-fesa3's release flow (e.g. scp'd
 * directly onto the target's local disk, independent of the NFS-shared
 * release tree).
 */
constexpr const char* kOpcUaClientKeyFileName = "client_key.pem";

/**
 * @brief Default ApplicationUri connectOpcUaClient() identifies its client
 *        as - MUST exactly match the URI embedded in the
 *        SubjectAlternativeName of whatever certificate a device's
 *        opcUaClientCert carries (open62541 rejects a mismatch at
 *        Client construction, immediately, with a clear
 *        ConnectionException - see SecurityCredentials::applicationUri
 *        above). Adjust this to match your actual provisioned certificates'
 *        SAN entry if it differs.
 */
constexpr const char* kOpcUaApplicationUri = "urn:fesa:client";

/**
 * @brief Prefix marking a FESA instance-data string (opcUaClientCert or
 *        opcUaServerCert) as a local file reference rather than inline
 *        Base64-encoded DER data - e.g. "file:/etc/opcua/client_cert.der".
 *        See isFileUri()/stripFileUriPrefix() and connectOpcUaClient().
 */
constexpr const char* kFileUriPrefix = "file:";

/**
 * @brief True if @p value is a kFileUriPrefix-prefixed local file
 *        reference rather than inline Base64 data.
 */
inline bool isFileUri(const std::string& value)
{
    return value.rfind(kFileUriPrefix, 0) == 0;
}

/**
 * @brief Strip kFileUriPrefix from @p value, returning the bare file path.
 * @pre isFileUri(value)
 */
inline std::string stripFileUriPrefix(const std::string& value)
{
    return value.substr(std::string(kFileUriPrefix).size());
}

/**
 * @brief Resolve @p value for a plain-string secret field (currently just
 *        opcUaPassword): if it's a kFileUriPrefix-prefixed local file
 *        reference (see isFileUri()), read and return that file's first
 *        line (trailing newline stripped); otherwise return @p value
 *        unchanged.
 *
 * Unlike opcUaClientCert/opcUaServerCert - where connectOpcUaClient() just
 * hands the bare path to SecurityCredentials::certificateFile and
 * open62541 itself reads it at connect time - a password has to already
 * be a plain std::string by the time it reaches Client's constructor, so
 * this reads the file eagerly here instead.
 *
 * @throws ConnectionException if isFileUri(value) and the referenced file
 *         cannot be opened.
 */
inline std::string resolveFileUriValue(const std::string& value)
{
    if (!isFileUri(value)) {
        return value;
    }
    const std::string path = stripFileUriPrefix(value);
    std::ifstream in(path);
    if (!in) {
        throw ConnectionException("Failed to open file reference '" + value + "'", UA_STATUSCODE_BADIDENTITYTOKENINVALID);
    }
    std::string content;
    std::getline(in, content);
    return content;
}

/**
 * @brief Get-or-create @p device's Client from the process-wide
 *        ClientRegistry, picking the right getOrCreate() overload
 *        based on which of a FESA device's opcUaUser/opcUaPassword/
 *        opcUaClientCert/opcUaServerCert fields are actually configured:
 *          - none set:                          anonymous, no SecureChannel
 *                                                security - same as the
 *                                                plain getOrCreate(endpoint)
 *                                                overload.
 *          - user + password:                   username/password
 *                                                identity, still no
 *                                                SecureChannel security.
 *                                                opcUaPassword may itself
 *                                                be a kFileUriPrefix local
 *                                                file reference instead of
 *                                                carrying the password
 *                                                inline (see
 *                                                resolveFileUriValue()) -
 *                                                useful for keeping a real
 *                                                password out of the
 *                                                instance file, which
 *                                                yocto-fesa3 release
 *                                                copies onto a commonly
 *                                                NFS-shared tree.
 *          - opcUaClientCert + opcUaServerCert:  SecureChannel security
 *                                                (SignAndEncrypt), client/
 *                                                trusted server certificate
 *                                                taken from those two
 *                                                fields - either inline
 *                                                Base64, or a local file
 *                                                reference via
 *                                                kFileUriPrefix (see
 *                                                isFileUri()) - private
 *                                                key always from the
 *                                                fixed local file
 *                                                described on
 *                                                kOpcUaClientKeyFileName -
 *                                                combined with username/
 *                                                password identity too, if
 *                                                that is *also* set
 *                                                (SecureChannel security
 *                                                and user identity are
 *                                                independent OPC UA
 *                                                concepts, see
 *                                                SecurityCredentials above;
 *                                                whether a given OPC UA
 *                                                server still requires a
 *                                                username/password identity
 *                                                token over an
 *                                                already-encrypted channel
 *                                                is a server-side access-
 *                                                control setting, not
 *                                                something the client side
 *                                                decides).
 *
 * This is a convention-based convenience wrapper, not a required entry
 * point: it assumes a FESA device exposes exactly those four fields by
 * those names, with opcUaClientCert/opcUaServerCert as either Base64-
 * encoded DER text (see SecurityCredentials' `*Base64` fields above) or a
 * kFileUriPrefix-prefixed local file reference, and the matching private
 * key provisioned as described on kOpcUaClientKeyFileName. A project with
 * different device field names, or that doesn't want this particular
 * certs-as-instance-data + key-as-file split, can keep calling
 * ClientRegistry::getOrCreate() directly instead.
 *
 * @tparam DeviceT  FESA generated device type; only requires
 *                  ->opcUaUser/opcUaPassword/opcUaClientCert/
 *                  opcUaServerCert.get() and whatever makeOpcUaEndpoint()
 *                  itself requires.
 * @throws std::runtime_error if exactly one of opcUaClientCert/
 *         opcUaServerCert is set without the other.
 * @throws ConnectionException if opcUaPassword is a kFileUriPrefix
 *         reference to a file that cannot be opened; if opcUaClientCert/
 *         opcUaServerCert are both set but this build has no OPC UA
 *         encryption support (UA_ENABLE_ENCRYPTION); or (at connect time)
 *         if the private key file described on kOpcUaClientKeyFileName,
 *         or a kFileUriPrefix-referenced certificate, is missing.
 */
template <typename DeviceT>
std::shared_ptr<Client> connectOpcUaClient(DeviceT* device)
{
    const std::string endpoint = makeOpcUaEndpoint(device);
    const std::string username(device->opcUaUser.get());
    const std::string password = resolveFileUriValue(device->opcUaPassword.get());
    const std::string clientCert(device->opcUaClientCert.get());
    const std::string serverCert(device->opcUaServerCert.get());

    auto& registry = ClientRegistry::getInstance();

    if (clientCert.empty() && serverCert.empty()) {
        if (username.empty()) {
            return registry.getOrCreate(endpoint);
        }
        return registry.getOrCreate(endpoint, username, password);
    }

    if (clientCert.empty() || serverCert.empty()) {
        throw std::runtime_error(
            "Device " + device->getName()
            + " configures only one of opcUaClientCert/opcUaServerCert - both are required together");
    }

#ifdef UA_ENABLE_ENCRYPTION
    SecurityCredentials security;
    if (isFileUri(clientCert)) {
        security.certificateFile = stripFileUriPrefix(clientCert);
    } else {
        security.certificateBase64 = clientCert;
    }
    security.privateKeyFile = std::string(kOpcUaSecurityMaterialDir) + "/" + kOpcUaClientKeyFileName;
    if (isFileUri(serverCert)) {
        security.trustedServerCertificateFile = stripFileUriPrefix(serverCert);
    } else {
        security.trustedServerCertificateBase64 = serverCert;
    }
    security.applicationUri = kOpcUaApplicationUri;

    if (username.empty()) {
        return registry.getOrCreate(endpoint, security);
    }
    return registry.getOrCreate(endpoint, username, password, security);
#else
    throw ConnectionException(
        "Device configures opcUaClientCert/opcUaServerCert but this build has no OPC UA encryption support (UA_ENABLE_ENCRYPTION)",
        UA_STATUSCODE_BADNOTSUPPORTED);
#endif
}

} // namespace OpcUa
