#include "WebRTCClientTestFixture.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#ifdef ENABLE_KVS_THREADPOOL
extern "C" PThreadPoolContext getThreadContextInstance();
#endif

namespace com {
namespace amazonaws {
namespace kinesis {
namespace video {
namespace webrtcclient {

namespace {

constexpr auto TEST_WAIT_TIMEOUT = std::chrono::seconds(5);

struct SignalingLifetimeState {
    std::mutex lock;
    std::condition_variable condition;

    PSignalingClient pClient = NULL;
    SIGNALING_CLIENT_HANDLE handle = INVALID_SIGNALING_CLIENT_HANDLE_VALUE;

    memFree savedMemFree = NULL;
    waitConditionVariable savedConditionVariableWait = NULL;
    createThread savedCreateThread = NULL;
    detachThread savedDetachThread = NULL;
    joinThread savedJoinThread = NULL;

    startRoutine receiveRoutine = NULL;
    PVOID receiveRoutineArgument = NULL;
    TID receiveThreadId = INVALID_TID_VALUE;

    bool createThreadHookInstalled = false;
    bool receiveThreadCreated = false;
    bool receiveThreadJoined = false;
    bool receiveThreadReady = false;
    bool receiveThreadMayProceed = false;
    bool receiveThreadFinished = false;
    bool detachObserved = false;
    bool reservationObservedBeforeCreate = false;
    bool failThreadCreate = false;

#ifdef ENABLE_KVS_THREADPOOL
    bool threadPoolCreated = false;
    bool threadPoolHooksInstalled = false;
    bool poolTasksMayProceed = false;
    UINT32 poolTaskCount = 0;
    UINT32 poolTasksEntered = 0;
    UINT32 poolTasksExited = 0;
    std::vector<TID> poolThreadIds;
#endif

    bool drainWaitObserved = false;
    bool freeFinished = false;
    bool globalHooksInstalled = false;
    bool clientAllocationQuarantined = false;
    UINT32 clientFreeCalls = 0;
    UINT32 callbackCalls = 0;
    bool callbackPayloadValid = true;
    STATUS freeStatus = STATUS_INTERNAL_ERROR;

    std::thread freeThread;
};

SignalingLifetimeState* gSignalingLifetimeState = NULL;

template <typename Predicate> bool waitForState(SignalingLifetimeState& state, Predicate predicate)
{
    std::unique_lock<std::mutex> lock(state.lock);
    return state.condition.wait_for(lock, TEST_WAIT_TIMEOUT, predicate);
}

VOID signalingLifetimeMemFree(PVOID allocation)
{
    SignalingLifetimeState* pState = gSignalingLifetimeState;

    if (pState != NULL && allocation == pState->pClient) {
        std::lock_guard<std::mutex> lock(pState->lock);
        pState->clientFreeCalls++;
        pState->clientAllocationQuarantined = true;
        pState->condition.notify_all();
        return;
    }

    pState->savedMemFree(allocation);
}

STATUS signalingLifetimeConditionVariableWait(CVAR conditionVariable, MUTEX mutex, UINT64 timeout)
{
    SignalingLifetimeState* pState = gSignalingLifetimeState;

    if (pState != NULL && pState->pClient != NULL && conditionVariable == pState->pClient->receiveWorkCvar) {
        std::lock_guard<std::mutex> lock(pState->lock);
        pState->drainWaitObserved = true;
        pState->condition.notify_all();
    }

    return pState->savedConditionVariableWait(conditionVariable, mutex, timeout);
}

PVOID heldReceiveThread(PVOID customData)
{
    SignalingLifetimeState* pState = (SignalingLifetimeState*) customData;
    startRoutine routine;
    PVOID routineArgument;

    {
        std::unique_lock<std::mutex> lock(pState->lock);
        pState->receiveThreadReady = true;
        pState->condition.notify_all();
        pState->condition.wait(lock, [pState] { return pState->receiveThreadMayProceed; });
        routine = pState->receiveRoutine;
        routineArgument = pState->receiveRoutineArgument;
    }

    PVOID result = routine(routineArgument);

    {
        std::lock_guard<std::mutex> lock(pState->lock);
        pState->receiveThreadFinished = true;
        pState->condition.notify_all();
    }

    return result;
}

STATUS heldCreateThread(PTID pThreadId, startRoutine routine, PVOID routineArgument)
{
    SignalingLifetimeState* pState = gSignalingLifetimeState;

    if (pState == NULL || pThreadId == NULL || routine == NULL) {
        return STATUS_THREAD_INVALID_ARG;
    }

    if (pState->failThreadCreate) {
        return STATUS_THREAD_NOT_ENOUGH_RESOURCES;
    }

    {
        std::lock_guard<std::mutex> lock(pState->lock);
        if (pState->receiveThreadCreated) {
            return STATUS_INVALID_OPERATION;
        }
        pState->receiveRoutine = routine;
        pState->receiveRoutineArgument = routineArgument;
        // The lifetime reservation must exist before the worker is published.
        pState->reservationObservedBeforeCreate = pState->pClient->receiveWorkCount == 1;
    }

    STATUS status = pState->savedCreateThread(pThreadId, heldReceiveThread, pState);
    if (STATUS_SUCCEEDED(status)) {
        std::lock_guard<std::mutex> lock(pState->lock);
        pState->receiveThreadId = *pThreadId;
        pState->receiveThreadCreated = true;
    }

    return status;
}

STATUS heldDetachThread(TID threadId)
{
    SignalingLifetimeState* pState = gSignalingLifetimeState;
    std::lock_guard<std::mutex> lock(pState->lock);

    if (!pState->receiveThreadCreated || threadId != pState->receiveThreadId) {
        return STATUS_THREAD_INVALID_ARG;
    }

    // Keep the thread joinable so the test can collect it deterministically.
    pState->detachObserved = true;
    return STATUS_SUCCESS;
}

#ifdef ENABLE_KVS_THREADPOOL
STATUS recordingPoolCreateThread(PTID pThreadId, startRoutine routine, PVOID routineArgument)
{
    SignalingLifetimeState* pState = gSignalingLifetimeState;
    STATUS status = pState->savedCreateThread(pThreadId, routine, routineArgument);

    if (STATUS_SUCCEEDED(status)) {
        std::lock_guard<std::mutex> lock(pState->lock);
        pState->poolThreadIds.push_back(*pThreadId);
    }

    return status;
}

STATUS recordingPoolDetachThread(TID threadId)
{
    UNUSED_PARAM(threadId);
    // The production pool detaches its actors. Keep them joinable in this test
    // so teardown can prove every actor has exited before destroying test state.
    return STATUS_SUCCESS;
}

PVOID heldThreadPoolTask(PVOID customData)
{
    SignalingLifetimeState* pState = (SignalingLifetimeState*) customData;
    std::unique_lock<std::mutex> lock(pState->lock);

    pState->poolTasksEntered++;
    pState->condition.notify_all();
    pState->condition.wait(lock, [pState] { return pState->poolTasksMayProceed; });
    pState->poolTasksExited++;
    pState->condition.notify_all();
    return NULL;
}
#endif

STATUS signalingLifetimeMessageReceived(UINT64 customData, PReceivedSignalingMessage pMessage)
{
    SignalingLifetimeState* pState = (SignalingLifetimeState*) (ULONG_PTR) customData;
    std::lock_guard<std::mutex> lock(pState->lock);

    pState->callbackCalls++;
    pState->callbackPayloadValid = pState->callbackPayloadValid && pMessage != NULL &&
        pMessage->signalingMessage.messageType == SIGNALING_MESSAGE_TYPE_ICE_CANDIDATE &&
        STRCMP(pMessage->signalingMessage.payload, (PCHAR) "Hello") == 0;
    pState->condition.notify_all();
    return STATUS_SUCCESS;
}

class SignalingLifetimeTest : public ::testing::Test {
  protected:
    SignalingLifetimeState state;

    void SetUp() override
    {
        ASSERT_EQ((SignalingLifetimeState*) NULL, gSignalingLifetimeState);
        gSignalingLifetimeState = &state;

        state.savedMemFree = globalMemFree;
        state.savedConditionVariableWait = globalConditionVariableWait;
        state.savedCreateThread = globalCreateThread;
        state.savedDetachThread = globalDetachThread;
        state.savedJoinThread = globalJoinThread;

#ifdef ENABLE_KVS_THREADPOOL
        globalCreateThread = recordingPoolCreateThread;
        globalDetachThread = recordingPoolDetachThread;
        state.threadPoolHooksInstalled = true;
        ASSERT_EQ(STATUS_SUCCESS, createThreadPoolContext());
        state.threadPoolCreated = true;
#endif

        state.pClient = (PSignalingClient) MEMCALLOC(1, SIZEOF(SignalingClient));
        ASSERT_NE((PSignalingClient) NULL, state.pClient);

        state.pClient->version = SIGNALING_CLIENT_CURRENT_VERSION;
        state.pClient->signalingClientCallbacks.version = SIGNALING_CLIENT_CALLBACKS_CURRENT_VERSION;
        state.pClient->signalingClientCallbacks.customData = (UINT64) (ULONG_PTR) &state;
        state.pClient->signalingClientCallbacks.messageReceivedFn = signalingLifetimeMessageReceived;

        ASSERT_EQ(STATUS_SUCCESS, initializeThreadTracker(&state.pClient->listenerTracker));
        ASSERT_EQ(STATUS_SUCCESS, initializeThreadTracker(&state.pClient->reconnecterTracker));

        state.pClient->receiveWorkLock = MUTEX_CREATE(FALSE);
        ASSERT_TRUE(IS_VALID_MUTEX_VALUE(state.pClient->receiveWorkLock));
        state.pClient->receiveWorkCvar = CVAR_CREATE();
        ASSERT_TRUE(IS_VALID_CVAR_VALUE(state.pClient->receiveWorkCvar));

        state.handle = TO_SIGNALING_CLIENT_HANDLE(state.pClient);

        globalMemFree = signalingLifetimeMemFree;
        globalConditionVariableWait = signalingLifetimeConditionVariableWait;
        state.globalHooksInstalled = true;
    }

    void installHeldThreadHooks()
    {
        globalCreateThread = heldCreateThread;
        globalDetachThread = heldDetachThread;
        state.createThreadHookInstalled = true;
    }

    void restoreHeldThreadHooks()
    {
        if (state.createThreadHookInstalled) {
            globalCreateThread = state.savedCreateThread;
            globalDetachThread = state.savedDetachThread;
            state.createThreadHookInstalled = false;
        }
    }

    UINT32 receiveWorkCount()
    {
        MUTEX_LOCK(state.pClient->receiveWorkLock);
        UINT32 count = state.pClient->receiveWorkCount;
        MUTEX_UNLOCK(state.pClient->receiveWorkLock);
        return count;
    }

    void startFree()
    {
        state.freeThread = std::thread([this] {
            STATUS status = freeSignalingClient(&state.handle);
            std::lock_guard<std::mutex> lock(state.lock);
            state.freeStatus = status;
            state.freeFinished = true;
            state.condition.notify_all();
        });
    }

    void releasePendingWork()
    {
        std::lock_guard<std::mutex> lock(state.lock);
#ifdef ENABLE_KVS_THREADPOOL
        state.poolTasksMayProceed = true;
#else
        state.receiveThreadMayProceed = true;
#endif
        state.condition.notify_all();
    }

    void joinHeldReceiveThread()
    {
#ifndef ENABLE_KVS_THREADPOOL
        if (state.receiveThreadCreated && !state.receiveThreadJoined) {
            EXPECT_EQ(STATUS_SUCCESS, state.savedJoinThread(state.receiveThreadId, NULL));
            state.receiveThreadJoined = true;
        }
#endif
    }

    void makeStuckFreeRecoverable()
    {
        bool freeFinished;
        {
            std::lock_guard<std::mutex> lock(state.lock);
            freeFinished = state.freeFinished;
        }

        if (!freeFinished && state.pClient != NULL) {
            MUTEX_LOCK(state.pClient->receiveWorkLock);
            state.pClient->receiveWorkCount = 0;
            CVAR_BROADCAST(state.pClient->receiveWorkCvar);
            MUTEX_UNLOCK(state.pClient->receiveWorkLock);
        }
    }

    void TearDown() override
    {
        releasePendingWork();
        restoreHeldThreadHooks();
        joinHeldReceiveThread();

        if (state.freeThread.joinable()) {
            if (!waitForState(state, [this] { return state.freeFinished; })) {
                makeStuckFreeRecoverable();
            }
            state.freeThread.join();
        }

        if (IS_VALID_SIGNALING_CLIENT_HANDLE(state.handle)) {
            EXPECT_EQ(STATUS_SUCCESS, freeSignalingClient(&state.handle));
        }

#ifdef ENABLE_KVS_THREADPOOL
        if (state.threadPoolCreated) {
            EXPECT_TRUE(waitForState(state, [this] { return state.poolTasksExited == state.poolTaskCount; }));
            EXPECT_EQ(STATUS_SUCCESS, destroyThreadPoolContext());
            state.threadPoolCreated = false;
        }
        if (state.threadPoolHooksInstalled) {
            for (TID threadId : state.poolThreadIds) {
                EXPECT_EQ(STATUS_SUCCESS, state.savedJoinThread(threadId, NULL));
            }
            globalCreateThread = state.savedCreateThread;
            globalDetachThread = state.savedDetachThread;
            state.threadPoolHooksInstalled = false;
        }
#endif

        if (state.globalHooksInstalled) {
            globalConditionVariableWait = state.savedConditionVariableWait;
            globalMemFree = state.savedMemFree;
            state.globalHooksInstalled = false;
        }

        if (state.clientAllocationQuarantined && state.savedMemFree != NULL) {
            state.savedMemFree(state.pClient);
        }

        state.pClient = NULL;
        gSignalingLifetimeState = NULL;
    }
};

TEST_F(SignalingLifetimeTest, publicFreeDrainsPendingReceiveWorker)
{
    static const CHAR message[] = "{\"messageType\":\"ICE_CANDIDATE\",\"senderClientId\":\"offline-peer\",\"messagePayload\":\"SGVsbG8=\"}";

#ifdef ENABLE_KVS_THREADPOOL
    PThreadPoolContext pThreadPoolContext = getThreadContextInstance();
    ASSERT_NE((PThreadPoolContext) NULL, pThreadPoolContext);
    ASSERT_NE((PThreadpool) NULL, pThreadPoolContext->pThreadpool);
    state.poolTaskCount = pThreadPoolContext->pThreadpool->maxThreads;
    ASSERT_GT(state.poolTaskCount, 0U);

    for (UINT32 i = 0; i < state.poolTaskCount; ++i) {
        ASSERT_EQ(STATUS_SUCCESS, threadpoolContextPush(heldThreadPoolTask, &state));
        ASSERT_TRUE(waitForState(state, [this, i] { return state.poolTasksEntered == i + 1; }));
    }
#else
    installHeldThreadHooks();
#endif

    ASSERT_EQ(STATUS_SUCCESS, receiveLwsMessage(state.pClient, (PCHAR) message, (UINT32) (SIZEOF(message) - 1)));

#ifndef ENABLE_KVS_THREADPOOL
    ASSERT_TRUE(waitForState(state, [this] { return state.receiveThreadReady; }));
    EXPECT_TRUE(state.detachObserved);
    EXPECT_TRUE(state.reservationObservedBeforeCreate);
    restoreHeldThreadHooks();
#endif

    ASSERT_EQ(1U, receiveWorkCount());
    startFree();

    ASSERT_TRUE(waitForState(state, [this] { return state.drainWaitObserved || state.freeFinished; }));
    EXPECT_TRUE(state.drainWaitObserved);

    if (state.drainWaitObserved) {
        // The wait hook runs while free holds receiveWorkLock. Acquiring it here
        // proves that CVAR_WAIT has released the lock and free is actually in
        // the drain loop, rather than merely scheduled to enter it.
        MUTEX_LOCK(state.pClient->receiveWorkLock);
        MUTEX_UNLOCK(state.pClient->receiveWorkLock);

        std::lock_guard<std::mutex> lock(state.lock);
        EXPECT_FALSE(state.freeFinished);
        EXPECT_EQ(0U, state.clientFreeCalls);
    }

    releasePendingWork();
    joinHeldReceiveThread();

    ASSERT_TRUE(waitForState(state, [this] { return state.freeFinished; }));
    state.freeThread.join();

    EXPECT_EQ(STATUS_SUCCESS, state.freeStatus);
    EXPECT_EQ(INVALID_SIGNALING_CLIENT_HANDLE_VALUE, state.handle);
    EXPECT_EQ(1U, state.clientFreeCalls);
    // Shutdown policy may either finish an already-admitted callback or skip
    // it. The lifetime contract only requires the wrapper to drain safely.
    EXPECT_LE(state.callbackCalls, 1U);
    EXPECT_TRUE(state.callbackPayloadValid);

#ifdef ENABLE_KVS_THREADPOOL
    EXPECT_TRUE(waitForState(state, [this] { return state.poolTasksExited == state.poolTaskCount; }));
#else
    EXPECT_TRUE(state.receiveThreadFinished);
#endif
}

TEST_F(SignalingLifetimeTest, failedReceiveDispatchRollsBackReservation)
{
    static const CHAR message[] = "{\"messageType\":\"ICE_CANDIDATE\",\"senderClientId\":\"offline-peer\",\"messagePayload\":\"SGVsbG8=\"}";
    STATUS status;

#ifdef ENABLE_KVS_THREADPOOL
    PThreadPoolContext pThreadPoolContext = getThreadContextInstance();
    ASSERT_NE((PThreadPoolContext) NULL, pThreadPoolContext);
    ASSERT_TRUE(pThreadPoolContext->isInitialized);

    MUTEX_LOCK(pThreadPoolContext->threadpoolContextLock);
    pThreadPoolContext->isInitialized = FALSE;
    MUTEX_UNLOCK(pThreadPoolContext->threadpoolContextLock);

    status = receiveLwsMessage(state.pClient, (PCHAR) message, (UINT32) (SIZEOF(message) - 1));

    MUTEX_LOCK(pThreadPoolContext->threadpoolContextLock);
    pThreadPoolContext->isInitialized = TRUE;
    MUTEX_UNLOCK(pThreadPoolContext->threadpoolContextLock);
#else
    state.failThreadCreate = true;
    installHeldThreadHooks();
    status = receiveLwsMessage(state.pClient, (PCHAR) message, (UINT32) (SIZEOF(message) - 1));
    restoreHeldThreadHooks();
#endif

    EXPECT_TRUE(STATUS_FAILED(status));
    EXPECT_EQ(0U, receiveWorkCount());
    EXPECT_EQ(0U, state.callbackCalls);

    EXPECT_EQ(STATUS_SUCCESS, freeSignalingClient(&state.handle));
    EXPECT_EQ(INVALID_SIGNALING_CLIENT_HANDLE_VALUE, state.handle);
    EXPECT_EQ(1U, state.clientFreeCalls);
    EXPECT_FALSE(state.drainWaitObserved);
}

} // namespace

} // namespace webrtcclient
} // namespace video
} // namespace kinesis
} // namespace amazonaws
} // namespace com
