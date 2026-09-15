#include "WebRTCClientTestFixture.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace com {
namespace amazonaws {
namespace kinesis {
namespace video {
namespace webrtcclient {

namespace {

constexpr auto SEND_TEST_WAIT_TIMEOUT = std::chrono::seconds(5);
constexpr SIZE_T TEST_SEND_OFFSET = 16;
constexpr SIZE_T TEST_SEND_SIZE = TEST_SEND_OFFSET + 16;

struct SignalingSendLifetimeState {
    std::mutex lock;
    std::condition_variable condition;

    PSignalingClient pClient = NULL;
    PLwsCallInfo pCallInfo = NULL;

    waitConditionVariable savedConditionVariableWait = NULL;
    broadcastConditionVariable savedConditionVariableBroadcast = NULL;
    memFree savedMemFree = NULL;

    bool hooksInstalled = false;
    bool sendWaitEntered = false;
    bool sendWaitMayReturn = false;
    bool sendFailurePublished = false;
    bool senderReturned = false;
    bool listenerReturned = false;
    bool callInfoQuarantined = false;
    bool callInfoFreedAfterSenderReturned = false;
    UINT32 callInfoFreeCalls = 0;
    STATUS senderStatus = STATUS_INTERNAL_ERROR;

    std::thread senderThread;
    std::thread listenerThread;
};

SignalingSendLifetimeState* gSignalingSendLifetimeState = NULL;

template <typename Predicate> bool waitForSendState(SignalingSendLifetimeState& state, Predicate predicate)
{
    std::unique_lock<std::mutex> lock(state.lock);
    return state.condition.wait_for(lock, SEND_TEST_WAIT_TIMEOUT, predicate);
}

STATUS signalingSendLifetimeConditionVariableWait(CVAR conditionVariable, MUTEX mutex, UINT64 timeout)
{
    SignalingSendLifetimeState* pState = gSignalingSendLifetimeState;

    if (pState == NULL || pState->pClient == NULL || conditionVariable != pState->pClient->sendCvar) {
        return pState->savedConditionVariableWait(conditionVariable, mutex, timeout);
    }

    {
        std::lock_guard<std::mutex> lock(pState->lock);
        pState->sendWaitEntered = true;
        pState->condition.notify_all();
    }

    // Preserve the CVAR_WAIT contract: release the SDK mutex while blocked and
    // reacquire it before returning to writeLwsData.
    MUTEX_UNLOCK(mutex);
    {
        std::unique_lock<std::mutex> lock(pState->lock);
        pState->condition.wait(lock, [pState] { return pState->sendWaitMayReturn; });
    }
    MUTEX_LOCK(mutex);

    return STATUS_SUCCESS;
}

STATUS signalingSendLifetimeConditionVariableBroadcast(CVAR conditionVariable)
{
    SignalingSendLifetimeState* pState = gSignalingSendLifetimeState;

    if (pState != NULL && pState->pClient != NULL && conditionVariable == pState->pClient->sendCvar) {
        std::lock_guard<std::mutex> lock(pState->lock);
        pState->sendFailurePublished = true;
        pState->condition.notify_all();
    }

    return pState->savedConditionVariableBroadcast(conditionVariable);
}

VOID signalingSendLifetimeMemFree(PVOID allocation)
{
    SignalingSendLifetimeState* pState = gSignalingSendLifetimeState;

    if (pState != NULL && allocation == pState->pCallInfo) {
        std::lock_guard<std::mutex> lock(pState->lock);
        pState->callInfoFreeCalls++;
        pState->callInfoQuarantined = true;
        pState->callInfoFreedAfterSenderReturned = pState->senderReturned;
        pState->condition.notify_all();
        return;
    }

    pState->savedMemFree(allocation);
}

class SignalingSendLifetimeTest : public ::testing::Test {
  protected:
    SignalingSendLifetimeState state;

    void SetUp() override
    {
        ASSERT_EQ((SignalingSendLifetimeState*) NULL, gSignalingSendLifetimeState);
        gSignalingSendLifetimeState = &state;

        state.pClient = (PSignalingClient) MEMCALLOC(1, SIZEOF(SignalingClient));
        ASSERT_NE((PSignalingClient) NULL, state.pClient);
        state.pCallInfo = (PLwsCallInfo) MEMCALLOC(1, SIZEOF(LwsCallInfo));
        ASSERT_NE((PLwsCallInfo) NULL, state.pCallInfo);

        state.pClient->sendLock = MUTEX_CREATE(FALSE);
        ASSERT_TRUE(IS_VALID_MUTEX_VALUE(state.pClient->sendLock));
        state.pClient->sendCvar = CVAR_CREATE();
        ASSERT_TRUE(IS_VALID_CVAR_VALUE(state.pClient->sendCvar));
        state.pClient->receiveLock = MUTEX_CREATE(FALSE);
        ASSERT_TRUE(IS_VALID_MUTEX_VALUE(state.pClient->receiveLock));
        state.pClient->receiveCvar = CVAR_CREATE();
        ASSERT_TRUE(IS_VALID_CVAR_VALUE(state.pClient->receiveCvar));
        state.pClient->connectedLock = MUTEX_CREATE(FALSE);
        ASSERT_TRUE(IS_VALID_MUTEX_VALUE(state.pClient->connectedLock));
        state.pClient->outboundMessageLock = MUTEX_CREATE(FALSE);
        ASSERT_TRUE(IS_VALID_MUTEX_VALUE(state.pClient->outboundMessageLock));
        ASSERT_EQ(STATUS_SUCCESS, initializeThreadTracker(&state.pClient->listenerTracker));

        state.pClient->pOngoingCallInfo = state.pCallInfo;
        state.pCallInfo->pSignalingClient = state.pClient;
        ATOMIC_STORE_BOOL(&state.pClient->connected, TRUE);
        ATOMIC_STORE(&state.pCallInfo->sendOffset, TEST_SEND_OFFSET);
        ATOMIC_STORE(&state.pCallInfo->sendBufferSize, TEST_SEND_SIZE);

        state.savedConditionVariableWait = globalConditionVariableWait;
        state.savedConditionVariableBroadcast = globalConditionVariableBroadcast;
        state.savedMemFree = globalMemFree;
        globalConditionVariableWait = signalingSendLifetimeConditionVariableWait;
        globalConditionVariableBroadcast = signalingSendLifetimeConditionVariableBroadcast;
        globalMemFree = signalingSendLifetimeMemFree;
        state.hooksInstalled = true;
    }

    void startSender()
    {
        state.senderThread = std::thread([this] {
            MUTEX_LOCK(state.pClient->outboundMessageLock);
            STATUS status = writeLwsData(state.pClient, FALSE);
            {
                std::lock_guard<std::mutex> lock(state.lock);
                state.senderStatus = status;
                state.senderReturned = true;
                state.condition.notify_all();
            }
            MUTEX_UNLOCK(state.pClient->outboundMessageLock);
        });
    }

    void releaseSendWait()
    {
        std::lock_guard<std::mutex> lock(state.lock);
        state.sendWaitMayReturn = true;
        state.condition.notify_all();
    }

    void TearDown() override
    {
        releaseSendWait();

        if (state.senderThread.joinable()) {
            state.senderThread.join();
        }
        if (state.listenerThread.joinable()) {
            state.listenerThread.join();
        }

        if (state.hooksInstalled) {
            globalConditionVariableWait = state.savedConditionVariableWait;
            globalConditionVariableBroadcast = state.savedConditionVariableBroadcast;
            globalMemFree = state.savedMemFree;
            state.hooksInstalled = false;
        }

        if (state.pClient != NULL && state.pClient->pOngoingCallInfo != NULL) {
            freeLwsCallInfo(&state.pClient->pOngoingCallInfo);
        } else if (state.callInfoQuarantined && state.pCallInfo != NULL) {
            state.savedMemFree(state.pCallInfo);
        }

        if (state.pClient != NULL) {
            uninitializeThreadTracker(&state.pClient->listenerTracker);
            if (IS_VALID_MUTEX_VALUE(state.pClient->outboundMessageLock)) {
                MUTEX_FREE(state.pClient->outboundMessageLock);
            }
            if (IS_VALID_MUTEX_VALUE(state.pClient->connectedLock)) {
                MUTEX_FREE(state.pClient->connectedLock);
            }
            if (IS_VALID_CVAR_VALUE(state.pClient->receiveCvar)) {
                CVAR_FREE(state.pClient->receiveCvar);
            }
            if (IS_VALID_MUTEX_VALUE(state.pClient->receiveLock)) {
                MUTEX_FREE(state.pClient->receiveLock);
            }
            if (IS_VALID_CVAR_VALUE(state.pClient->sendCvar)) {
                CVAR_FREE(state.pClient->sendCvar);
            }
            if (IS_VALID_MUTEX_VALUE(state.pClient->sendLock)) {
                MUTEX_FREE(state.pClient->sendLock);
            }
            MEMFREE(state.pClient);
        }

        state.pCallInfo = NULL;
        state.pClient = NULL;
        gSignalingSendLifetimeState = NULL;
    }
};

TEST_F(SignalingSendLifetimeTest, IncompleteLocalWriteFailsWhenConnectionCloses)
{
    startSender();
    ASSERT_TRUE(waitForSendState(state, [this] { return state.sendWaitEntered; }));

    MUTEX_LOCK(state.pClient->sendLock);
    ATOMIC_STORE(&state.pClient->messageResult, (SIZE_T) SERVICE_CALL_UNKNOWN);
    MUTEX_UNLOCK(state.pClient->sendLock);
    releaseSendWait();

    ASSERT_TRUE(waitForSendState(state, [this] { return state.senderReturned; }));
    EXPECT_EQ(STATUS_SIGNALING_MESSAGE_DELIVERY_FAILED, state.senderStatus);
    // A terminal frame must also be withdrawn before releasing sendLock, so a
    // later writable callback cannot transmit stale signaling data.
    EXPECT_EQ((SIZE_T) 0, ATOMIC_LOAD(&state.pCallInfo->sendOffset));
    EXPECT_EQ((SIZE_T) 0, ATOMIC_LOAD(&state.pCallInfo->sendBufferSize));
}

TEST_F(SignalingSendLifetimeTest, ListenerRetainsCallInfoUntilBlockedSendReturns)
{
    startSender();
    ASSERT_TRUE(waitForSendState(state, [this] { return state.sendWaitEntered; }));

    state.listenerThread = std::thread([this] {
        lwsListenerHandler(state.pCallInfo);
        std::lock_guard<std::mutex> lock(state.lock);
        state.listenerReturned = true;
        state.condition.notify_all();
    });

    ASSERT_TRUE(waitForSendState(state, [this] { return state.sendFailurePublished; }));
    {
        std::lock_guard<std::mutex> lock(state.lock);
        EXPECT_FALSE(state.senderReturned);
        EXPECT_EQ(0U, state.callInfoFreeCalls);
    }
    EXPECT_EQ(state.pCallInfo, state.pClient->pOngoingCallInfo);

    releaseSendWait();
    ASSERT_TRUE(waitForSendState(state, [this] { return state.listenerReturned; }));

    EXPECT_EQ(STATUS_SIGNALING_MESSAGE_DELIVERY_FAILED, state.senderStatus);
    EXPECT_EQ(1U, state.callInfoFreeCalls);
    EXPECT_TRUE(state.callInfoFreedAfterSenderReturned);
    EXPECT_EQ((PLwsCallInfo) NULL, state.pClient->pOngoingCallInfo);
}

} // namespace

} // namespace webrtcclient
} // namespace video
} // namespace kinesis
} // namespace amazonaws
} // namespace com
