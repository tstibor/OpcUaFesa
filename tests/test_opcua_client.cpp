/**
 * @file test_opcua_client.cpp
 * @brief GoogleTest suite for OpcUa::Client / OpcUa::ClientRegistry
 *        (include/OpcUa/OpcUaClient.hpp).
 *
 * Prerequisite: scripts/mock_server.py must already be running on
 * opc.tcp://127.0.0.1:4840 before this executable (or `ctest`) is invoked -
 * see the README's "Running the Unit Tests" section. The server is not
 * started automatically by CMake/CTest.
 *
 * Fixtures, one per area of behavior:
 *  - OpcUaClientTest                    connect/disconnect lifecycle and
 *                                        anonymous read<T>()/write<T>().
 *  - OpcUaClientAuthTest                username/password authentication
 *                                        (credentials must match
 *                                        scripts/mock_server.py's
 *                                        VALID_USERS).
 *  - OpcUaClientSecurityTest             SecureChannel signing/encryption via
 *                                        OpcUa::SecurityCredentials, combined
 *                                        with anonymous and username/password
 *                                        identity, and each material's
 *                                        File/Base64/Bytes source resolved
 *                                        independently (including the
 *                                        ambiguous/missing-source error
 *                                        cases). Compiled only when the
 *                                        linked open62541 has encryption
 *                                        support (`#ifdef UA_ENABLE_ENCRYPTION`,
 *                                        matching OpcUaClient.hpp itself).
 *  - OpcUaClientConnectionFailureTest   connect() against a port with no
 *                                        server listening (127.0.0.1:4841).
 *  - OpcUaClientRegistryTest            ClientRegistry get/getOrCreate/
 *                                        release/releaseAll.
 *
 * write<T>() is round-tripped through write+read for every supported type
 * (UA_Boolean/UA_Byte/UA_Int16/UA_Int32/UA_Float) across
 * OpcUaClientTest.WriteSupportedTypes and .WriteRemainingSupportedTypes.
 * OpcUaClientTest.ConcurrentReadWriteFromMultipleThreadsIsThreadSafe covers
 * concurrent access to a single Client from multiple threads, as the
 * class's own documentation claims is safe.
 *
 * Client::quoteTagPath()'s per-segment quoting of dot-separated tag paths is
 * covered two ways: OpcUaClientQuoteTest below tests the pure static
 * function directly (no server needed), and
 * OpcUaClientTest.ReadWriteDottedTagPathUsesPerSegmentQuoting exercises it
 * end-to-end against mock_server.py's matching multi-segment node.
 *
 * OpcUa::makeOpcUaEndpoint() and OpcUa::applyLinkHealthToDevice() are free template
 * functions over FESA device/context pointers, not Client members, so
 * they need no OPC UA server at all - MakeOpcUaEndpointTest and
 * UpdateDeviceTest below exercise them against the lightweight mock FESA
 * device/context types declared just above those tests.
 */

#include <gtest/gtest.h>
#include <OpcUa/OpcUaClient.hpp>

#include <atomic>
#include <chrono>
#include <cmath>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>

using namespace OpcUa;

// --- Client::quoteTagPath() Coverage ---
//
// Pure static function, no server connection required. Mirrors the worked
// examples in quoteTagPath()'s own doc comment (include/OpcUa/OpcUaClient.hpp).
// See OpcUaClientTest.ReadWriteDottedTagPathUsesPerSegmentQuoting for the
// end-to-end counterpart against a real server-side node.

TEST(OpcUaClientQuoteTest, QuotesSingleSegmentTagAsOneQuotedSegment) {
    EXPECT_EQ(Client::quoteTagPath("A_OUT_0"), "\"A_OUT_0\"");
}

TEST(OpcUaClientQuoteTest, QuotesEachDotSeparatedSegmentIndependently) {
    EXPECT_EQ(Client::quoteTagPath("HMIinterface.02-NG02.TFT_Anzeige_NG2Ist1U"),
        "\"HMIinterface\".\"02-NG02\".\"TFT_Anzeige_NG2Ist1U\"");
}

TEST(OpcUaClientQuoteTest, LeavesBareDotFreeTagAsASingleQuotedSegment) {
    // Matches the previous (pre-dot-support) quoting behaviour for tags
    // that happen to contain no dots.
    EXPECT_EQ(Client::quoteTagPath("Ger\xC3\xA4t2DI2-1/16"), "\"Ger\xC3\xA4t2DI2-1/16\"");
}

TEST(OpcUaClientQuoteTest, PassesThroughTagThatAlreadyContainsAQuoteUnchanged) {
    // A tag containing an embedded double quote is assumed to already be
    // in full Siemens form and must be returned verbatim - this is the
    // only way to express a symbol whose own name contains a dot.
    const std::string alreadyQuoted = "\"Foo\".\"Bar.Baz\"";
    EXPECT_EQ(Client::quoteTagPath(alreadyQuoted), alreadyQuoted);
}

TEST(OpcUaClientQuoteTest, TreatsConsecutiveDotsAsAnEmptyMiddleSegment) {
    EXPECT_EQ(Client::quoteTagPath("A..B"), "\"A\".\"\".\"B\"");
}

// --- Lightweight mock FESA device/context types ---
//
// makeOpcUaEndpoint() and applyLinkHealthToDevice() are templates over FESA device
// (and, for applyLinkHealthToDevice(), context and status/control enum) types; they
// don't touch Client or any OPC UA server at all. These mocks provide
// just the members each function actually calls, so
// MakeOpcUaEndpointTest/UpdateDeviceTest below can exercise both without a
// running mock_server.py.

namespace {

/** @brief Stand-in for a FESA device's opcUaServerName property (device->opcUaServerName.get()). */
struct MockServerNameProperty {
    std::string value;
    std::string get() const { return value; }
};

/** @brief Stand-in for a FESA device's opcUaServerPort property (device->opcUaServerPort.get()). */
struct MockServerPortProperty {
    int value = 0;
    int get() const { return value; }
};

/** @brief Minimal FESA-like device exposing only what makeOpcUaEndpoint() reads. */
struct MockEndpointDevice {
    MockServerNameProperty opcUaServerName;
    MockServerPortProperty opcUaServerPort;
};

/** @brief Stand-in for a FESA context handle; applyLinkHealthToDevice() only forwards this pointer to every set()/setBit() call. */
struct MockContext {};

enum class MockControl { UNSET, REMOTE };
enum class MockDeviceStatus { UNSET, OK, WARNING, ERROR };
enum class MockModuleStatus { UNSET, OK, WARNING, ERROR };
enum class MockPowerState { UNSET, UNKNOWN, ON };

/** @brief Records the value/context last passed to a FESA-style scalar property's set(value, context). */
template <typename T>
struct MockProperty {
    T value{};
    const MockContext* lastContext = nullptr;
    int setCount = 0;

    void set(T v, const MockContext* ctx) {
        value = v;
        lastContext = ctx;
        ++setCount;
    }
};

/** @brief Stand-in for device->detailedStatus.setBit(name, value, context); tracks only the two bit names applyLinkHealthToDevice() sets. */
struct MockDetailedStatus {
    bool opcUaConnectionBit = false;
    bool opcUaNodeAccessBit = false;
    const MockContext* lastContext = nullptr;

    void setBit(const std::string& name, bool value, const MockContext* ctx) {
        if (name == "OPCUA_CONNECTION") {
            opcUaConnectionBit = value;
        } else if (name == "OPCUA_NODE_ACCESS") {
            opcUaNodeAccessBit = value;
        }
        lastContext = ctx;
    }
};

/** @brief Stand-in for device->moduleStatus.set(name, value, context); tracks only the "OPCUA" entry applyLinkHealthToDevice() writes. */
struct MockModuleStatusProperty {
    std::string lastName;
    MockModuleStatus lastValue = MockModuleStatus::UNSET;
    const MockContext* lastContext = nullptr;

    void set(const std::string& name, MockModuleStatus value, const MockContext* ctx) {
        lastName = name;
        lastValue = value;
        lastContext = ctx;
    }
};

/** @brief Minimal FESA-like device exposing only what applyLinkHealthToDevice() reads/writes. */
struct MockFesaDevice {
    MockProperty<MockControl> control;
    MockDetailedStatus detailedStatus;
    MockProperty<MockDeviceStatus> status;
    MockProperty<bool> modulesReady;
    MockModuleStatusProperty moduleStatus;
    MockProperty<bool> opReady;
    MockProperty<MockPowerState> powerState;
    MockProperty<bool> interlock;
};

} // namespace

// --- makeOpcUaEndpoint() Coverage ---

TEST(MakeOpcUaEndpointTest, BuildsEndpointUrlFromDeviceNameAndPort) {
    MockEndpointDevice device;
    device.opcUaServerName.value = "localhost";
    device.opcUaServerPort.value = 4840;

    EXPECT_EQ(makeOpcUaEndpoint(&device), "opc.tcp://localhost:4840");
}

TEST(MakeOpcUaEndpointTest, WorksWithAnyPointerLikeHandleNotJustRawPointers) {
    // makeOpcUaEndpoint() is documented as accepting "pointer (or
    // pointer-like handle)" - verify a std::shared_ptr works too, not just
    // a raw T*.
    auto device = std::make_shared<MockEndpointDevice>();
    device->opcUaServerName.value = "127.0.0.1";
    device->opcUaServerPort.value = 4841;

    EXPECT_EQ(makeOpcUaEndpoint(device), "opc.tcp://127.0.0.1:4841");
}

// --- applyLinkHealthToDevice() Coverage ---
//
// Exercises all three isConnected/nodeAccessOk branches documented on
// applyLinkHealthToDevice(), against the mock FESA device/context types above.

TEST(UpdateDeviceTest, DisconnectedSetsErrorStatusAndUnknownPower) {
    MockFesaDevice device;
    MockContext context;

    applyLinkHealthToDevice<MockFesaDevice, MockContext, MockDeviceStatus, MockModuleStatus, MockPowerState, MockControl>(
        &device, &context, /*isConnected=*/false, /*nodeAccessOk=*/false);

    EXPECT_EQ(device.control.value, MockControl::REMOTE);
    EXPECT_FALSE(device.detailedStatus.opcUaConnectionBit);
    EXPECT_FALSE(device.detailedStatus.opcUaNodeAccessBit);
    EXPECT_EQ(device.status.value, MockDeviceStatus::ERROR);
    EXPECT_FALSE(device.modulesReady.value);
    EXPECT_EQ(device.moduleStatus.lastName, "OPCUA");
    EXPECT_EQ(device.moduleStatus.lastValue, MockModuleStatus::ERROR);
    EXPECT_FALSE(device.opReady.value);
    EXPECT_EQ(device.powerState.value, MockPowerState::UNKNOWN);
    EXPECT_FALSE(device.interlock.value);
    EXPECT_EQ(device.status.lastContext, &context);
}

TEST(UpdateDeviceTest, ConnectedButNodeAccessFailingSetsWarningStatus) {
    MockFesaDevice device;
    MockContext context;

    applyLinkHealthToDevice<MockFesaDevice, MockContext, MockDeviceStatus, MockModuleStatus, MockPowerState, MockControl>(
        &device, &context, /*isConnected=*/true, /*nodeAccessOk=*/false);

    EXPECT_EQ(device.control.value, MockControl::REMOTE);
    EXPECT_TRUE(device.detailedStatus.opcUaConnectionBit);
    EXPECT_FALSE(device.detailedStatus.opcUaNodeAccessBit);
    EXPECT_EQ(device.status.value, MockDeviceStatus::WARNING);
    EXPECT_TRUE(device.modulesReady.value);
    EXPECT_EQ(device.moduleStatus.lastName, "OPCUA");
    EXPECT_EQ(device.moduleStatus.lastValue, MockModuleStatus::WARNING);
    EXPECT_FALSE(device.opReady.value);
    EXPECT_EQ(device.powerState.value, MockPowerState::ON);
    EXPECT_FALSE(device.interlock.value);
}

TEST(UpdateDeviceTest, FullyHealthySetsOkStatus) {
    MockFesaDevice device;
    MockContext context;

    applyLinkHealthToDevice<MockFesaDevice, MockContext, MockDeviceStatus, MockModuleStatus, MockPowerState, MockControl>(
        &device, &context, /*isConnected=*/true, /*nodeAccessOk=*/true);

    EXPECT_EQ(device.control.value, MockControl::REMOTE);
    EXPECT_TRUE(device.detailedStatus.opcUaConnectionBit);
    EXPECT_TRUE(device.detailedStatus.opcUaNodeAccessBit);
    EXPECT_EQ(device.status.value, MockDeviceStatus::OK);
    EXPECT_TRUE(device.modulesReady.value);
    EXPECT_EQ(device.moduleStatus.lastName, "OPCUA");
    EXPECT_EQ(device.moduleStatus.lastValue, MockModuleStatus::OK);
    EXPECT_TRUE(device.opReady.value);
    EXPECT_EQ(device.powerState.value, MockPowerState::ON);
    EXPECT_FALSE(device.interlock.value);
}

/**
 * @brief Fixture for anonymous connect/disconnect and read<T>()/write<T>()
 *        coverage against the mock server's eight pre-registered nodes
 *        (TestBool, TestByte, A_OUT_0, A_OUT_1, A_OUT_2, TestInt32,
 *        PID_Setpoint, and the dot-separated
 *        "HMIinterface.02-NG02.TFT_Anzeige_NG2Ist1U" tag). A_OUT_1/A_OUT_2
 *        exist alongside A_OUT_0 purely for OpcUaClientBatchTest below, which
 *        needs several same-typed nodes to actually batch together.
 */
class OpcUaClientTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        Client bootstrapClient("opc.tcp://127.0.0.1:4840", 3);
        bootstrapClient.connect();
        bootstrapClient.write<UA_Boolean>("TestBool", true);
        bootstrapClient.write<UA_Byte>("TestByte", 255);
        bootstrapClient.write<UA_Int16>("A_OUT_0", -15000);
        bootstrapClient.write<UA_Int16>("A_OUT_1", -15001);
        bootstrapClient.write<UA_Int16>("A_OUT_2", -15002);
        bootstrapClient.write<UA_Int32>("TestInt32", 123456789);
        bootstrapClient.write<UA_Float>("PID_Setpoint", 45.5f);
        bootstrapClient.write<UA_Int32>("HMIinterface.02-NG02.TFT_Anzeige_NG2Ist1U", 777);
        bootstrapClient.disconnect();
    }

    void SetUp() override {
        client = std::make_unique<Client>("opc.tcp://127.0.0.1:4840", 3);
    }

    void TearDown() override {
        if (client->isConnected()) {
            client->disconnect();
        }
    }

    std::unique_ptr<Client> client;
};

// --- Basic Connection / Disconnection Coverage ---

TEST_F(OpcUaClientTest, BasicConnectionAndDisconnection) {
    EXPECT_FALSE(client->isConnected());
    EXPECT_NO_THROW(client->connect());
    EXPECT_TRUE(client->isConnected());

    EXPECT_NO_THROW(client->disconnect());
    EXPECT_FALSE(client->isConnected());
}

TEST_F(OpcUaClientTest, DisconnectWithoutConnectingIsSafe) {
    Client freshClient("opc.tcp://127.0.0.1:4840", 3);
    EXPECT_FALSE(freshClient.isConnected());
    EXPECT_NO_THROW(freshClient.disconnect());
    EXPECT_FALSE(freshClient.isConnected());
}

TEST_F(OpcUaClientTest, DoubleDisconnectIsSafe) {
    client->connect();
    EXPECT_TRUE(client->isConnected());

    EXPECT_NO_THROW(client->disconnect());
    EXPECT_FALSE(client->isConnected());

    // Calling disconnect a second time when already disconnected
    EXPECT_NO_THROW(client->disconnect());
    EXPECT_FALSE(client->isConnected());
}

TEST_F(OpcUaClientTest, ReconnectAfterDisconnect) {
    client->connect();
    EXPECT_TRUE(client->isConnected());

    client->disconnect();
    EXPECT_FALSE(client->isConnected());

    // Re-connecting the same client object
    EXPECT_NO_THROW(client->connect());
    EXPECT_TRUE(client->isConnected());
}

TEST_F(OpcUaClientTest, DestructorCleansUpConnectedClientSafely) {
    {
        Client scopedClient("opc.tcp://127.0.0.1:4840", 3);
        scopedClient.connect();
        EXPECT_TRUE(scopedClient.isConnected());
    } // ~Client() must disconnect without crashing or throwing
}

TEST_F(OpcUaClientTest, ReadAndWriteFailWhenDisconnected) {
    EXPECT_FALSE(client->isConnected());
    
    EXPECT_THROW(client->read<UA_Boolean>("TestBool"), Exception);
    EXPECT_THROW(client->write<UA_Boolean>("TestBool", true), Exception);
}

// --- Read / Write Functionality Coverage ---

TEST_F(OpcUaClientTest, ReadSupportedTypes) {
    client->connect();

    auto boolVal = client->read<UA_Boolean>("TestBool");
    EXPECT_EQ(boolVal, true);

    auto byteVal = client->read<UA_Byte>("TestByte");
    EXPECT_EQ(byteVal, 255);

    auto int16Val = client->read<UA_Int16>("A_OUT_0");
    EXPECT_EQ(int16Val, -15000);

    auto int32Val = client->read<UA_Int32>("TestInt32");
    EXPECT_EQ(int32Val, 123456789);

    auto floatVal = client->read<UA_Float>("PID_Setpoint");
    EXPECT_FLOAT_EQ(floatVal, 45.5f);
}

TEST_F(OpcUaClientTest, WriteSupportedTypes) {
    client->connect();

    constexpr UA_Int16 originalInt16 = -15000;
    constexpr UA_Float originalFloat = 45.5f;

    client->write<UA_Int16>("A_OUT_0", 42);
    auto int16Val = client->read<UA_Int16>("A_OUT_0");
    EXPECT_EQ(int16Val, 42);

    client->write<UA_Float>("PID_Setpoint", 99.9f);
    auto floatVal = client->read<UA_Float>("PID_Setpoint");
    EXPECT_FLOAT_EQ(floatVal, 99.9f);

    client->write<UA_Int16>("A_OUT_0", originalInt16);
    client->write<UA_Float>("PID_Setpoint", originalFloat);

    ASSERT_EQ(client->read<UA_Int16>("A_OUT_0"), originalInt16);
    ASSERT_FLOAT_EQ(client->read<UA_Float>("PID_Setpoint"), originalFloat);
}

// Covers the three supported write<T>() types WriteSupportedTypes above
// doesn't: UA_Boolean, UA_Byte, UA_Int32.
TEST_F(OpcUaClientTest, WriteRemainingSupportedTypes) {
    client->connect();

    constexpr UA_Boolean originalBool = true;
    constexpr UA_Byte originalByte = 255;
    constexpr UA_Int32 originalInt32 = 123456789;

    client->write<UA_Boolean>("TestBool", false);
    EXPECT_EQ(client->read<UA_Boolean>("TestBool"), false);

    client->write<UA_Byte>("TestByte", 128);
    EXPECT_EQ(client->read<UA_Byte>("TestByte"), 128);

    client->write<UA_Int32>("TestInt32", -999999);
    EXPECT_EQ(client->read<UA_Int32>("TestInt32"), -999999);

    client->write<UA_Boolean>("TestBool", originalBool);
    client->write<UA_Byte>("TestByte", originalByte);
    client->write<UA_Int32>("TestInt32", originalInt32);

    ASSERT_EQ(client->read<UA_Boolean>("TestBool"), originalBool);
    ASSERT_EQ(client->read<UA_Byte>("TestByte"), originalByte);
    ASSERT_EQ(client->read<UA_Int32>("TestInt32"), originalInt32);
}

// End-to-end counterpart to OpcUaClientQuoteTest below: proves that
// read<T>()/write<T>() on an unquoted, dot-separated tag name actually
// resolves - via Client::quoteTagPath()'s per-segment quoting - to the
// matching multi-segment node registered by mock_server.py, not just that
// quoteTagPath() produces the expected string in isolation.
TEST_F(OpcUaClientTest, ReadWriteDottedTagPathUsesPerSegmentQuoting) {
    client->connect();

    constexpr UA_Int32 originalValue = 777;
    const std::string dottedTag = "HMIinterface.02-NG02.TFT_Anzeige_NG2Ist1U";

    EXPECT_EQ(client->read<UA_Int32>(dottedTag), originalValue);

    client->write<UA_Int32>(dottedTag, 4242);
    EXPECT_EQ(client->read<UA_Int32>(dottedTag), 4242);

    client->write<UA_Int32>(dottedTag, originalValue);
    ASSERT_EQ(client->read<UA_Int32>(dottedTag), originalValue);
}

// Client documents itself as thread-safe: "one Client instance may
// safely be shared and used concurrently from multiple threads" (mutex_
// guards every public operation). Each worker below owns one node
// exclusively, so a worker's own write-then-read-back sequence has an
// unambiguous expected value even while other workers hammer the same
// shared client concurrently on different nodes - isolating "does the
// shared mutex keep internal UA_Client/UA_Variant/UA_NodeId state from
// getting corrupted under concurrent access" from "what does concurrent
// access to the *same* node resolve to" (inherently racy server-side, and
// not what this test is about). Assertions are deferred to the main thread
// via failureCount - GoogleTest assertion macros are not meant to be
// invoked concurrently from worker threads.
TEST_F(OpcUaClientTest, ConcurrentReadWriteFromMultipleThreadsIsThreadSafe) {
    client->connect();

    constexpr int kIterations = 25;
    std::atomic<int> failureCount{0};

    auto boolWorker = [&] {
        for (int i = 0; i < kIterations; ++i) {
            const UA_Boolean value = (i % 2 == 0);
            try {
                client->write<UA_Boolean>("TestBool", value);
                if (client->read<UA_Boolean>("TestBool") != value) {
                    ++failureCount;
                }
            } catch (...) {
                ++failureCount;
            }
        }
    };
    auto byteWorker = [&] {
        for (int i = 0; i < kIterations; ++i) {
            const UA_Byte value = static_cast<UA_Byte>(i);
            try {
                client->write<UA_Byte>("TestByte", value);
                if (client->read<UA_Byte>("TestByte") != value) {
                    ++failureCount;
                }
            } catch (...) {
                ++failureCount;
            }
        }
    };
    auto int16Worker = [&] {
        for (int i = 0; i < kIterations; ++i) {
            const UA_Int16 value = static_cast<UA_Int16>(-15000 + i);
            try {
                client->write<UA_Int16>("A_OUT_0", value);
                if (client->read<UA_Int16>("A_OUT_0") != value) {
                    ++failureCount;
                }
            } catch (...) {
                ++failureCount;
            }
        }
    };
    auto int32Worker = [&] {
        for (int i = 0; i < kIterations; ++i) {
            const UA_Int32 value = 123456789 + i;
            try {
                client->write<UA_Int32>("TestInt32", value);
                if (client->read<UA_Int32>("TestInt32") != value) {
                    ++failureCount;
                }
            } catch (...) {
                ++failureCount;
            }
        }
    };
    auto floatWorker = [&] {
        for (int i = 0; i < kIterations; ++i) {
            const UA_Float value = 45.5f + static_cast<float>(i);
            try {
                client->write<UA_Float>("PID_Setpoint", value);
                if (std::fabs(client->read<UA_Float>("PID_Setpoint") - value) > 1e-3f) {
                    ++failureCount;
                }
            } catch (...) {
                ++failureCount;
            }
        }
    };
    auto isConnectedWorker = [&] {
        for (int i = 0; i < kIterations; ++i) {
            if (!client->isConnected()) {
                ++failureCount;
            }
        }
    };

    std::vector<std::thread> workers;
    workers.emplace_back(boolWorker);
    workers.emplace_back(byteWorker);
    workers.emplace_back(int16Worker);
    workers.emplace_back(int32Worker);
    workers.emplace_back(floatWorker);
    workers.emplace_back(isConnectedWorker);
    workers.emplace_back(isConnectedWorker);

    for (auto& worker : workers) {
        worker.join();
    }

    EXPECT_EQ(failureCount.load(), 0);
    EXPECT_TRUE(client->isConnected());

    // Restore the values other tests rely on.
    client->write<UA_Boolean>("TestBool", true);
    client->write<UA_Byte>("TestByte", 255);
    client->write<UA_Int16>("A_OUT_0", -15000);
    client->write<UA_Int32>("TestInt32", 123456789);
    client->write<UA_Float>("PID_Setpoint", 45.5f);
}

TEST_F(OpcUaClientTest, HandlesTypeMismatch) {
    client->connect();
    EXPECT_THROW(client->read<UA_Boolean>("PID_Setpoint"), NodeException);

    try {
        client->read<UA_Boolean>("PID_Setpoint");
        FAIL() << "Expected NodeException to be thrown";
    } catch (const NodeException& e) {
        EXPECT_EQ(e.code(), UA_STATUSCODE_BADTYPEMISMATCH);
        EXPECT_EQ(e.nodeId(), "\"PID_Setpoint\"");
    }
}

TEST_F(OpcUaClientTest, HandlesMissingNode) {
    client->connect();
    EXPECT_THROW(client->read<UA_Int32>("NonExistentTag"), NodeException);

    try {
        client->read<UA_Int32>("NonExistentTag");
        FAIL() << "Expected NodeException to be thrown";
    } catch (const NodeException& e) {
        EXPECT_EQ(e.nodeId(), "\"NonExistentTag\"");
        EXPECT_NE(e.code(), UA_STATUSCODE_GOOD);
    }

    EXPECT_THROW(client->read<UA_Int32>("NonExistentTag"), Exception);
}

TEST_F(OpcUaClientTest, HandlesMissingNodeOnWrite) {
    client->connect();
    EXPECT_THROW(client->write<UA_Int32>("NonExistentTag", 1), NodeException);
    EXPECT_TRUE(client->isConnected());
}

TEST_F(OpcUaClientTest, DoesNotThrowConnectionExceptionForNodeErrors) {
    client->connect();
    try {
        client->read<UA_Int32>("NonExistentTag");
        FAIL() << "Expected NodeException to be thrown";
    } catch (const ConnectionException&) {
        FAIL() << "Node error must not be reported as a communication exception";
    } catch (const NodeException&) {
        // Expected
    }
}

// --- Batch Read / Write Coverage ---
//
// readBatch()/writeBatch() (tag-name) and readByNodeIdBatch()/
// writeByNodeIdBatch() (exact NodeId) cover the same ground as
// read<T>()/write<T>() in a loop, but as a single OPC UA service call - see
// OpcUaClient.hpp's class doc comment. Reuses OpcUaClientTest's fixture and
// its A_OUT_0/A_OUT_1/A_OUT_2 (same-typed Int16 nodes, added specifically
// for this) plus the dotted multi-segment tag for the exact-NodeId variant.
class OpcUaClientBatchTest : public OpcUaClientTest {};

TEST_F(OpcUaClientBatchTest, ReadBatchReturnsAllRequestedValues) {
    client->connect();

    client->write<UA_Int16>("A_OUT_0", 10);
    client->write<UA_Int16>("A_OUT_1", 20);
    client->write<UA_Int16>("A_OUT_2", 30);

    const auto values = client->readBatch<UA_Int16>({"A_OUT_0", "A_OUT_1", "A_OUT_2"});

    ASSERT_EQ(values.size(), 3u);
    EXPECT_EQ(values.at("A_OUT_0"), 10);
    EXPECT_EQ(values.at("A_OUT_1"), 20);
    EXPECT_EQ(values.at("A_OUT_2"), 30);

    client->write<UA_Int16>("A_OUT_0", -15000);
    client->write<UA_Int16>("A_OUT_1", -15001);
    client->write<UA_Int16>("A_OUT_2", -15002);
}

TEST_F(OpcUaClientBatchTest, ReadBatchWithEmptyInputReturnsEmptyMapWithoutConnecting) {
    // Deliberately not calling client->connect() - an empty batch must be
    // answered locally, with no service call (and so no need for a live
    // session) at all.
    const auto values = client->readBatch<UA_Int16>({});
    EXPECT_TRUE(values.empty());
}

TEST_F(OpcUaClientBatchTest, ReadBatchThrowsForMissingNodeAndDiscardsWholeBatch) {
    client->connect();

    try {
        client->readBatch<UA_Int16>({"A_OUT_0", "NonExistentTag", "A_OUT_1"});
        FAIL() << "Expected NodeException to be thrown";
    } catch (const NodeException& e) {
        EXPECT_EQ(e.nodeId(), "\"NonExistentTag\"");
        EXPECT_NE(e.code(), UA_STATUSCODE_GOOD);
    }
}

TEST_F(OpcUaClientBatchTest, ReadBatchThrowsOnTypeMismatch) {
    client->connect();

    try {
        client->readBatch<UA_Boolean>({"TestBool", "PID_Setpoint"});
        FAIL() << "Expected NodeException to be thrown";
    } catch (const NodeException& e) {
        EXPECT_EQ(e.code(), UA_STATUSCODE_BADTYPEMISMATCH);
        EXPECT_EQ(e.nodeId(), "\"PID_Setpoint\"");
    }
}

TEST_F(OpcUaClientBatchTest, WriteBatchWritesAllValues) {
    client->connect();

    client->writeBatch<UA_Int16>({{"A_OUT_0", 111}, {"A_OUT_1", 222}, {"A_OUT_2", 333}});

    EXPECT_EQ(client->read<UA_Int16>("A_OUT_0"), 111);
    EXPECT_EQ(client->read<UA_Int16>("A_OUT_1"), 222);
    EXPECT_EQ(client->read<UA_Int16>("A_OUT_2"), 333);

    client->write<UA_Int16>("A_OUT_0", -15000);
    client->write<UA_Int16>("A_OUT_1", -15001);
    client->write<UA_Int16>("A_OUT_2", -15002);
}

TEST_F(OpcUaClientBatchTest, WriteBatchWithEmptyInputIsNoOpWithoutConnecting) {
    // Deliberately not calling client->connect() - an empty batch must be a
    // no-op locally, with no service call (and so no need for a live
    // session) at all.
    EXPECT_NO_THROW(client->writeBatch<UA_Int16>({}));
}

TEST_F(OpcUaClientBatchTest, WriteBatchThrowsForMissingNodeAndDiscardsWholeBatch) {
    client->connect();
    EXPECT_THROW(client->writeBatch<UA_Int16>({{"A_OUT_0", 1}, {"NonExistentTag", 2}}), NodeException);
    EXPECT_TRUE(client->isConnected());
}

// Exact-NodeId variants (readByNodeIdBatch()/writeByNodeIdBatch()) - covers
// the same underlying UA_Client_Service_read()/UA_Client_Service_write()
// mechanism, but keyed by the already-quoted NodeId string, including the
// multi-segment dotted tag that only readByNodeId() (not read()) can address
// directly.
TEST_F(OpcUaClientBatchTest, ReadByNodeIdBatchAndWriteByNodeIdBatchRoundTrip) {
    client->connect();

    const std::string dottedNodeId = "\"HMIinterface\".\"02-NG02\".\"TFT_Anzeige_NG2Ist1U\"";
    ASSERT_EQ(dottedNodeId, Client::quoteTagPath("HMIinterface.02-NG02.TFT_Anzeige_NG2Ist1U"));

    const std::unordered_map<std::string, UA_Int32> toWrite {
        {dottedNodeId, 4242},
    };
    client->writeByNodeIdBatch<UA_Int32>(toWrite);

    const auto values = client->readByNodeIdBatch<UA_Int32>({dottedNodeId});
    ASSERT_EQ(values.size(), 1u);
    EXPECT_EQ(values.at(dottedNodeId), 4242);

    client->writeByNodeIdBatch<UA_Int32>({{dottedNodeId, 777}});
}

TEST_F(OpcUaClientBatchTest, ReadAndWriteBatchFailWhenDisconnected) {
    EXPECT_FALSE(client->isConnected());

    EXPECT_THROW(client->readBatch<UA_Int16>({"A_OUT_0"}), Exception);
    EXPECT_THROW(client->writeBatch<UA_Int16>({{"A_OUT_0", 1}}), Exception);
}

// --- Username/Password Authentication Suite ---
//
// Credentials must match VALID_USERS in scripts/mock_server.py.

/**
 * @brief Fixture for Client's username/password identity token path,
 *        covering both the direct 4-argument constructor and
 *        ClientRegistry::getOrCreate(endpoint, user, password).
 */
class OpcUaClientAuthTest : public ::testing::Test {
protected:
    const std::string endpoint = "opc.tcp://127.0.0.1:4840";
    const std::string validUser = "testuser";
    const std::string validPassword = "testpass";
};

TEST_F(OpcUaClientAuthTest, ConnectWithValidCredentialsSucceeds) {
    Client client(endpoint, 3, validUser, validPassword);

    EXPECT_TRUE(client.usesCredentials());
    EXPECT_FALSE(client.isConnected());
    EXPECT_NO_THROW(client.connect());
    EXPECT_TRUE(client.isConnected());

    client.disconnect();
    EXPECT_FALSE(client.isConnected());
}

TEST_F(OpcUaClientAuthTest, DefaultConstructedClientDoesNotUseCredentials) {
    Client client(endpoint, 3);
    EXPECT_FALSE(client.usesCredentials());
}

TEST_F(OpcUaClientAuthTest, AuthenticatedClientCanReadAndWriteAfterConnect) {
    Client client(endpoint, 3, validUser, validPassword);
    client.connect();

    EXPECT_NO_THROW(client.write<UA_Int16>("A_OUT_0", 7));
    EXPECT_EQ(client.read<UA_Int16>("A_OUT_0"), 7);

    // Restore the value other tests rely on.
    client.write<UA_Int16>("A_OUT_0", -15000);
}

TEST_F(OpcUaClientAuthTest, ConnectWithWrongPasswordThrowsConnectionException) {
    Client client(endpoint, 3, validUser, "not-the-right-password");

    EXPECT_THROW(client.connect(), ConnectionException);
    EXPECT_FALSE(client.isConnected());
}

TEST_F(OpcUaClientAuthTest, ConnectWithUnknownUsernameThrowsConnectionException) {
    Client client(endpoint, 3, "no-such-user", "whatever");

    EXPECT_THROW(client.connect(), Exception);
    EXPECT_FALSE(client.isConnected());
}

TEST_F(OpcUaClientAuthTest, ReconnectAfterDisconnectReusesStoredCredentials) {
    Client client(endpoint, 3, validUser, validPassword);
    client.connect();
    EXPECT_TRUE(client.isConnected());

    client.disconnect();
    EXPECT_FALSE(client.isConnected());

    // connect() must re-apply the stored username/password, not fall back
    // to an anonymous identity token.
    EXPECT_NO_THROW(client.connect());
    EXPECT_TRUE(client.isConnected());
}

TEST_F(OpcUaClientAuthTest, RegistryGetOrCreateWithCredentialsConnects) {
    auto client = ClientRegistry::getInstance().getOrCreate(endpoint, validUser, validPassword);
    EXPECT_TRUE(client->isConnected());
    EXPECT_TRUE(client->usesCredentials());

    ClientRegistry::getInstance().releaseAll();
}

TEST_F(OpcUaClientAuthTest, RegistryGetOrCreateWithCredentialsReconnectsAfterDrop) {
    auto client = ClientRegistry::getInstance().getOrCreate(endpoint, validUser, validPassword);
    client->disconnect();
    ASSERT_FALSE(client->isConnected());

    auto sameClient = ClientRegistry::getInstance().getOrCreate(endpoint, validUser, validPassword);
    EXPECT_EQ(client, sameClient);
    EXPECT_TRUE(sameClient->isConnected());

    ClientRegistry::getInstance().releaseAll();
}

#ifdef UA_ENABLE_ENCRYPTION

// --- SecureChannel Signing/Encryption Suite ---
//
// Only compiled when the linked open62541 has encryption support
// (UA_ENABLE_ENCRYPTION) - see OpcUaClient.hpp's file-level doc comment.
// Certificates come from scripts/certs/ (generated by
// scripts/sslcert-create.sh); mock_server.py loads server_cert.der/
// server_key.pem and offers SecurityPolicy#Basic256Sha256 in both Sign and
// SignAndEncrypt modes alongside the existing SecurityPolicy#None endpoint.

/**
 * @brief Fixture for Client's SecureChannel signing/encryption support
 *        (SecurityCredentials / SecurityMode), combined with both anonymous
 *        and username/password identity.
 */
class OpcUaClientSecurityTest : public ::testing::Test {
protected:
    // A separate port from the plain (SecurityPolicy#None) endpoint - see
    // mock_server.py's module doc comment for why the two are kept on
    // separate servers rather than one server offering both.
    const std::string endpoint = "opc.tcp://127.0.0.1:4843";
    // OPCUA_FESA_SOURCE_DIR is injected by CMakeLists.txt so this resolves
    // regardless of the working directory the test binary is run from.
    const std::string certsDir = std::string(OPCUA_FESA_SOURCE_DIR) + "/scripts/certs/";

    SecurityCredentials clientCredentials(SecurityMode mode) const {
        SecurityCredentials security;
        security.certificateFile = certsDir + "client_cert.der";
        security.privateKeyFile = certsDir + "client_key.pem";
        security.trustedServerCertificateFile = certsDir + "server_cert.der";
        security.applicationUri = "urn:fesa:client"; // matches client_cert.der's URI SAN
        security.mode = mode;
        return security;
    }

    // Reads a file's raw bytes, for exercising SecurityCredentials'
    // *Bytes fields against the same real certs the *File tests use.
    static std::vector<UA_Byte> readFileBytes(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        std::ostringstream contents;
        contents << file.rdbuf();
        const std::string data = contents.str();
        return std::vector<UA_Byte>(data.begin(), data.end());
    }

    // Base64-encodes a file's raw bytes (via open62541's own encoder, the
    // mirror of the decoder SecurityCredentials' *Base64 fields use), for
    // exercising those fields against the same real certs the *File tests
    // use - and to model what a FESA instance file's
    // <opcUaClientCert><value>...</value></opcUaClientCert> carries at
    // runtime via device->opcUaClientCert.get().
    static std::string readFileBase64(const std::string& path) {
        const std::vector<UA_Byte> bytes = readFileBytes(path);
        UA_ByteString input;
        input.length = bytes.size();
        input.data = const_cast<UA_Byte*>(bytes.data());
        UA_String output;
        UA_String_init(&output);
        UA_ByteString_toBase64(&input, &output);
        std::string result(reinterpret_cast<const char*>(output.data), output.length);
        UA_String_clear(&output);
        return result;
    }
};

TEST_F(OpcUaClientSecurityTest, PlainClientDoesNotUseSecurity) {
    Client client(endpoint, 3);
    EXPECT_FALSE(client.usesSecurity());
}

TEST_F(OpcUaClientSecurityTest, AnonymousConnectWithSignAndEncryptSucceeds) {
    Client client(endpoint, 3, clientCredentials(SecurityMode::SignAndEncrypt));

    EXPECT_TRUE(client.usesSecurity());
    EXPECT_FALSE(client.usesCredentials());
    EXPECT_NO_THROW(client.connect());
    EXPECT_TRUE(client.isConnected());

    // Prove the encrypted channel actually carries application traffic, not
    // just that the SecureChannel handshake succeeded.
    client.write<UA_Int32>("TestInt32", 555);
    EXPECT_EQ(client.read<UA_Int32>("TestInt32"), 555);
    client.write<UA_Int32>("TestInt32", 123456789);

    client.disconnect();
    EXPECT_FALSE(client.isConnected());
}

TEST_F(OpcUaClientSecurityTest, AnonymousConnectWithSignOnlySucceeds) {
    Client client(endpoint, 3, clientCredentials(SecurityMode::Sign));

    EXPECT_TRUE(client.usesSecurity());
    EXPECT_NO_THROW(client.connect());
    EXPECT_TRUE(client.isConnected());
}

TEST_F(OpcUaClientSecurityTest, ReconnectAfterDisconnectReusesSecureChannelConfig) {
    Client client(endpoint, 3, clientCredentials(SecurityMode::SignAndEncrypt));
    client.connect();
    EXPECT_TRUE(client.isConnected());

    client.disconnect();
    EXPECT_FALSE(client.isConnected());

    // The SecureChannel security configuration is set up once, at
    // construction - unlike the username identity token, it is not
    // reapplied per connect(). Reconnecting must still work.
    EXPECT_NO_THROW(client.connect());
    EXPECT_TRUE(client.isConnected());
}

TEST_F(OpcUaClientSecurityTest, UsernamePasswordConnectWithSignAndEncryptSucceeds) {
    Client client(endpoint, 3, "testuser", "testpass", clientCredentials(SecurityMode::SignAndEncrypt));

    EXPECT_TRUE(client.usesSecurity());
    EXPECT_TRUE(client.usesCredentials());
    EXPECT_NO_THROW(client.connect());
    EXPECT_TRUE(client.isConnected());

    client.write<UA_Int16>("A_OUT_0", 321);
    EXPECT_EQ(client.read<UA_Int16>("A_OUT_0"), 321);
    client.write<UA_Int16>("A_OUT_0", -15000);
}

TEST_F(OpcUaClientSecurityTest, ConstructingWithMismatchedApplicationUriThrows) {
    SecurityCredentials security = clientCredentials(SecurityMode::SignAndEncrypt);
    security.applicationUri = "urn:this-does-not-match-the-certificate";

    EXPECT_THROW(Client(endpoint, 3, security), ConnectionException);
}

TEST_F(OpcUaClientSecurityTest, ConstructingWithMissingCertificateFileThrows) {
    SecurityCredentials security = clientCredentials(SecurityMode::SignAndEncrypt);
    security.certificateFile = certsDir + "does_not_exist.der";

    EXPECT_THROW(Client(endpoint, 3, security), ConnectionException);
}

// --- Base64/raw-bytes credential sources ---
//
// Covers SecurityCredentials' certificateBase64/privateKeyBase64/
// trustedServerCertificateBase64 and certificateBytes/privateKeyBytes/
// trustedServerCertificateBytes fields - alternatives to the *File fields
// for material that arrives as text or already-decoded bytes rather than a
// file on disk (e.g. a FESA device property injected via an instance file's
// <opcUaClientCert><value>{Base64}</value></opcUaClientCert>, read at
// runtime via device->opcUaClientCert.get()).

TEST_F(OpcUaClientSecurityTest, AnonymousConnectWithBase64EncodedCredentialsSucceeds) {
    SecurityCredentials security;
    security.certificateBase64 = readFileBase64(certsDir + "client_cert.der");
    security.privateKeyBase64 = readFileBase64(certsDir + "client_key.pem");
    security.trustedServerCertificateBase64 = readFileBase64(certsDir + "server_cert.der");
    security.applicationUri = "urn:fesa:client";
    security.mode = SecurityMode::SignAndEncrypt;

    Client client(endpoint, 3, security);
    EXPECT_TRUE(client.usesSecurity());
    EXPECT_NO_THROW(client.connect());
    EXPECT_TRUE(client.isConnected());

    // Prove the connection actually works, not just that construction succeeded.
    client.write<UA_Int32>("TestInt32", 4242);
    EXPECT_EQ(client.read<UA_Int32>("TestInt32"), 4242);
    client.write<UA_Int32>("TestInt32", 123456789);
}

TEST_F(OpcUaClientSecurityTest, AnonymousConnectWithRawByteCredentialsSucceeds) {
    SecurityCredentials security;
    security.certificateBytes = readFileBytes(certsDir + "client_cert.der");
    security.privateKeyBytes = readFileBytes(certsDir + "client_key.pem");
    security.trustedServerCertificateBytes = readFileBytes(certsDir + "server_cert.der");
    security.applicationUri = "urn:fesa:client";
    security.mode = SecurityMode::SignAndEncrypt;

    Client client(endpoint, 3, security);
    EXPECT_TRUE(client.usesSecurity());
    EXPECT_NO_THROW(client.connect());
    EXPECT_TRUE(client.isConnected());
}

TEST_F(OpcUaClientSecurityTest, EachMaterialResolvesItsSourceIndependently) {
    // One material via file, one via Base64, one via raw bytes, all in the
    // same client - proves the three *File/*Base64/*Bytes triplets are
    // resolved independently per material, not coupled to each other.
    SecurityCredentials security;
    security.certificateFile = certsDir + "client_cert.der";
    security.privateKeyBase64 = readFileBase64(certsDir + "client_key.pem");
    security.trustedServerCertificateBytes = readFileBytes(certsDir + "server_cert.der");
    security.applicationUri = "urn:fesa:client";
    security.mode = SecurityMode::SignAndEncrypt;

    Client client(endpoint, 3, security);
    EXPECT_NO_THROW(client.connect());
    EXPECT_TRUE(client.isConnected());
}

TEST_F(OpcUaClientSecurityTest, ConstructingWithNoCertificateSourceThrows) {
    SecurityCredentials security = clientCredentials(SecurityMode::SignAndEncrypt);
    security.certificateFile.clear(); // now zero of certificateFile/Base64/Bytes are set

    EXPECT_THROW(Client(endpoint, 3, security), ConnectionException);
}

TEST_F(OpcUaClientSecurityTest, ConstructingWithAmbiguousCertificateSourceThrows) {
    SecurityCredentials security = clientCredentials(SecurityMode::SignAndEncrypt);
    security.certificateBase64 = readFileBase64(certsDir + "client_cert.der"); // now both certificateFile and certificateBase64 are set

    EXPECT_THROW(Client(endpoint, 3, security), ConnectionException);
}

TEST_F(OpcUaClientSecurityTest, ConstructingWithMalformedBase64Throws) {
    SecurityCredentials security = clientCredentials(SecurityMode::SignAndEncrypt);
    security.certificateFile.clear();
    security.certificateBase64 = "not-valid-base64!!!???";

    EXPECT_THROW(Client(endpoint, 3, security), ConnectionException);
}

TEST_F(OpcUaClientSecurityTest, RegistryGetOrCreateWithSecurityConnects) {
    auto client = ClientRegistry::getInstance().getOrCreate(endpoint, clientCredentials(SecurityMode::SignAndEncrypt));
    EXPECT_TRUE(client->isConnected());
    EXPECT_TRUE(client->usesSecurity());

    ClientRegistry::getInstance().releaseAll();
}

TEST_F(OpcUaClientSecurityTest, RegistryGetOrCreateWithCredentialsAndSecurityConnects) {
    auto client = ClientRegistry::getInstance().getOrCreate(
        endpoint, std::string("testuser"), std::string("testpass"), clientCredentials(SecurityMode::SignAndEncrypt));
    EXPECT_TRUE(client->isConnected());
    EXPECT_TRUE(client->usesSecurity());
    EXPECT_TRUE(client->usesCredentials());

    ClientRegistry::getInstance().releaseAll();
}

#endif // UA_ENABLE_ENCRYPTION

// --- Connection Failure Suite ---

/**
 * @brief Fixture for connect() failures against an endpoint with no server
 *        listening (127.0.0.1:4841 - deliberately not the mock server's
 *        port, and nothing is expected to bind it).
 */
class OpcUaClientConnectionFailureTest : public ::testing::Test {
protected:
    const std::string unreachableEndpoint = "opc.tcp://127.0.0.1:4841";
};

TEST_F(OpcUaClientConnectionFailureTest, ConnectThrowsConnectionExceptionWhenServerUnreachable) {
    Client client(unreachableEndpoint, 3);

    EXPECT_THROW(client.connect(), ConnectionException);
    EXPECT_FALSE(client.isConnected());

    try {
        client.connect();
        FAIL() << "Expected ConnectionException to be thrown";
    } catch (const ConnectionException& e) {
        EXPECT_NE(e.code(), UA_STATUSCODE_GOOD);
    }
}

TEST_F(OpcUaClientConnectionFailureTest, ConnectFailureIsCatchableAsBaseOpcUaException) {
    Client client(unreachableEndpoint, 3);
    EXPECT_THROW(client.connect(), Exception);
}

// --- Registry Connection / Disconnection Suite ---

/**
 * @brief Fixture for ClientRegistry's anonymous get/getOrCreate/
 *        release/releaseAll behavior. TearDown() always calls releaseAll()
 *        so registry state (a process-wide singleton) never leaks between
 *        tests in this fixture or into other fixtures.
 */
class OpcUaClientRegistryTest : public ::testing::Test {
protected:
    void TearDown() override {
        ClientRegistry::getInstance().releaseAll();
    }

    const std::string endpoint = "opc.tcp://127.0.0.1:4840";
};

TEST_F(OpcUaClientRegistryTest, GetOrCreateReturnsConnectedClient) {
    auto client = ClientRegistry::getInstance().getOrCreate(endpoint);
    EXPECT_TRUE(client->isConnected());
}

TEST_F(OpcUaClientRegistryTest, GetOrCreateReturnsSameInstanceForSameEndpoint) {
    auto first = ClientRegistry::getInstance().getOrCreate(endpoint);
    auto second = ClientRegistry::getInstance().getOrCreate(endpoint);
    EXPECT_EQ(first, second);
}

TEST_F(OpcUaClientRegistryTest, GetOrCreateReconnectsADroppedClient) {
    auto client = ClientRegistry::getInstance().getOrCreate(endpoint);
    client->disconnect();
    ASSERT_FALSE(client->isConnected());

    auto sameClient = ClientRegistry::getInstance().getOrCreate(endpoint);
    EXPECT_EQ(client, sameClient);
    EXPECT_TRUE(sameClient->isConnected());
}

TEST_F(OpcUaClientRegistryTest, GetReturnsAlreadyRegisteredClient) {
    auto created = ClientRegistry::getInstance().getOrCreate(endpoint);
    auto fetched = ClientRegistry::getInstance().get(endpoint);
    EXPECT_EQ(created, fetched);
}

TEST_F(OpcUaClientRegistryTest, GetThrowsForUnregisteredEndpoint) {
    EXPECT_THROW(ClientRegistry::getInstance().get("opc.tcp://127.0.0.1:9999"), std::runtime_error);
}

TEST_F(OpcUaClientRegistryTest, ReleaseDisconnectsAndDeregisters) {
    auto client = ClientRegistry::getInstance().getOrCreate(endpoint);
    ASSERT_TRUE(client->isConnected());

    ClientRegistry::getInstance().release(endpoint);

    EXPECT_FALSE(client->isConnected());
    EXPECT_THROW(ClientRegistry::getInstance().get(endpoint), std::runtime_error);
}

TEST_F(OpcUaClientRegistryTest, ReleaseUnregisteredEndpointIsSafe) {
    EXPECT_NO_THROW(ClientRegistry::getInstance().release("opc.tcp://127.0.0.1:9999"));
}

TEST_F(OpcUaClientRegistryTest, ReleaseAllDisconnectsEveryRegisteredClient) {
    auto clientA = ClientRegistry::getInstance().getOrCreate(endpoint);
    auto clientB = ClientRegistry::getInstance().getOrCreate("opc.tcp://127.0.0.1:4840/");

    ClientRegistry::getInstance().releaseAll();

    EXPECT_FALSE(clientA->isConnected());
    EXPECT_FALSE(clientB->isConnected());
    EXPECT_THROW(ClientRegistry::getInstance().get(endpoint), std::runtime_error);
}