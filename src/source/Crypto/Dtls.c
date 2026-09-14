#define LOG_CLASS "DTLS"
#include "../Include_i.h"

STATUS dtlsSessionOnOutBoundData(PDtlsSession pDtlsSession, UINT64 customData, DtlsSessionOutboundPacketFunc callbackFn)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pDtlsSession != NULL && callbackFn != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pDtlsSession->sslLock);
    pDtlsSession->dtlsSessionCallbacks.outboundPacketFn = callbackFn;
    pDtlsSession->dtlsSessionCallbacks.outBoundPacketFnCustomData = customData;
    MUTEX_UNLOCK(pDtlsSession->sslLock);

CleanUp:
    return retStatus;
}

STATUS dtlsSessionOnStateChange(PDtlsSession pDtlsSession, UINT64 customData, DtlsSessionOnStateChange callbackFn)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pDtlsSession != NULL && callbackFn != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pDtlsSession->sslLock);
    pDtlsSession->dtlsSessionCallbacks.stateChangeFn = callbackFn;
    pDtlsSession->dtlsSessionCallbacks.stateChangeFnCustomData = customData;
    MUTEX_UNLOCK(pDtlsSession->sslLock);

CleanUp:
    LEAVES();
    return retStatus;
}

STATUS dtlsValidateRtcCertificates(PRtcCertificate pRtcCertificates, PUINT32 pCount)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i = 0;

    CHK(pCount != NULL, STATUS_NULL_ARG);

    // No certs have been specified
    CHK(pRtcCertificates != NULL, retStatus);

    for (i = 0, *pCount = 0; i < MAX_RTCCONFIGURATION_CERTIFICATES && pRtcCertificates[i].pCertificate != NULL; i++) {
        CHK(pRtcCertificates[i].privateKeySize == 0 || pRtcCertificates[i].pPrivateKey != NULL, STATUS_SSL_INVALID_CERTIFICATE_BITS);
    }

CleanUp:

    // If pRtcCertificates is NULL, default pCount to 0
    if (pCount != NULL) {
        *pCount = i;
    }

    LEAVES();
    return retStatus;
}

STATUS dtlsSessionChangeState(PDtlsSession pDtlsSession, RTC_DTLS_TRANSPORT_STATE newState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pDtlsSession != NULL, STATUS_NULL_ARG);
    CHK(pDtlsSession->state != newState, retStatus);

    if (pDtlsSession->state == RTC_DTLS_TRANSPORT_STATE_CONNECTING && newState == RTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        // Need to set this so that we do not calculate the time taken again. We set the new state in 2 different places
        if (pDtlsSession->dtlsSessionStartTime != 0) {
            PROFILE_WITH_START_TIME_OBJ(pDtlsSession->dtlsSessionStartTime, pDtlsSession->dtlsSessionSetupTime, "DTLS initialization completion");
            pDtlsSession->dtlsSessionStartTime = 0;
        }
    }
    pDtlsSession->state = newState;
    if (pDtlsSession->dtlsSessionCallbacks.stateChangeFn != NULL) {
        pDtlsSession->dtlsSessionCallbacks.stateChangeFn(pDtlsSession->dtlsSessionCallbacks.stateChangeFnCustomData, newState);
    }

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS dtlsSessionCopyOptions(PDtlsSession pDtlsSession, PDtlsSessionOptions pDtlsSessionOptions)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 hostnameLen = 0;

    CHK(pDtlsSession != NULL, STATUS_NULL_ARG);

    pDtlsSession->validationMode = DTLS_SESSION_VALIDATION_MODE_RELAXED;
    pDtlsSession->pExpectedServerHostname = NULL;

    CHK(pDtlsSessionOptions != NULL, retStatus);

    if (pDtlsSessionOptions->pDtlsOptions != NULL) {
        const RtcDtlsOptions* pOptions = pDtlsSessionOptions->pDtlsOptions;
        CHK(pOptions->structSize == SIZEOF(RtcDtlsOptions), STATUS_INVALID_ARG);
        CHK(pDtlsSessionOptions->pDtlsConfiguration != NULL, STATUS_NULL_ARG);
        CHK((UINT32) pOptions->resumption <= RTC_DTLS_OPTION_ENABLED && (UINT32) pOptions->tickets <= RTC_DTLS_OPTION_ENABLED &&
                (UINT32) pOptions->earlyData <= RTC_DTLS_OPTION_ENABLED,
            STATUS_INVALID_ARG);
        CHK(pOptions->pCipherSuites == NULL || pOptions->pCipherSuites[0] != '\0', STATUS_INVALID_ARG);
        // Session transfer/server continuity and early-data I/O are not provided by this SDK boundary.
        CHK(pOptions->resumption != RTC_DTLS_OPTION_ENABLED && pOptions->tickets != RTC_DTLS_OPTION_ENABLED &&
                pOptions->earlyData != RTC_DTLS_OPTION_ENABLED,
            STATUS_NOT_IMPLEMENTED);
    }

    if (pDtlsSessionOptions->pDtlsConfiguration != NULL) {
#if !defined(KVS_USE_OPENSSL) || !defined(DTLS1_3_VERSION) || defined(OPENSSL_NO_DTLS1_3)
        CHK(FALSE, STATUS_NOT_IMPLEMENTED);
#else
        CHK(pDtlsSessionOptions->pDtlsConfiguration->pGroups != NULL && pDtlsSessionOptions->pDtlsConfiguration->pGroups[0] != '\0' &&
                pDtlsSessionOptions->pDtlsConfiguration->pSignatureAlgorithms != NULL &&
                pDtlsSessionOptions->pDtlsConfiguration->pSignatureAlgorithms[0] != '\0',
            STATUS_INVALID_ARG);
#endif
    }

    pDtlsSession->validationMode = pDtlsSessionOptions->validationMode;
    if (pDtlsSession->validationMode == DTLS_SESSION_VALIDATION_MODE_STRICT_SERVER) {
        CHK(pDtlsSessionOptions->pExpectedServerHostname != NULL && pDtlsSessionOptions->pExpectedServerHostname[0] != '\0', STATUS_INVALID_ARG);
        hostnameLen = (UINT32) STRLEN(pDtlsSessionOptions->pExpectedServerHostname);
#ifdef KVS_USE_MBEDTLS
        CHK(hostnameLen <= MBEDTLS_SSL_MAX_HOST_NAME_LEN, STATUS_INVALID_ARG_LEN);
#endif
        pDtlsSession->pExpectedServerHostname = MEMCALLOC(hostnameLen + 1, SIZEOF(CHAR));
        CHK(pDtlsSession->pExpectedServerHostname != NULL, STATUS_NOT_ENOUGH_MEMORY);
        STRNCPY(pDtlsSession->pExpectedServerHostname, pDtlsSessionOptions->pExpectedServerHostname, hostnameLen);
    }

CleanUp:
    CHK_LOG_ERR(retStatus);
    LEAVES();
    return retStatus;
}

#if defined(KVS_USE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x30200000L || (defined(SSL_get0_signature_name) && defined(SSL_get0_peer_signature_name)))
static STATUS dtlsCopyAlgorithmName(const CHAR* pName, PCHAR pDestination, UINT32 validField, PRtcDtlsInfo pInfo)
{
    SIZE_T length;
    if (pName == NULL || pName[0] == '\0') {
        return STATUS_SUCCESS;
    }
    length = STRNLEN(pName, RTC_DTLS_ALGORITHM_NAME_MAX_LEN + 1);
    if (length > RTC_DTLS_ALGORITHM_NAME_MAX_LEN) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    MEMCPY(pDestination, pName, length + 1);
    pInfo->validFields |= validField;
    return STATUS_SUCCESS;
}
#endif

STATUS dtlsSessionGetInfo(PDtlsSession pDtlsSession, PRtcDtlsInfo pInfo)
{
#ifdef KVS_USE_OPENSSL
    STATUS retStatus = STATUS_SUCCESS;
    const SSL_CIPHER* pCipher = NULL;
    BOOL locked = FALSE;

    CHK(pDtlsSession != NULL && pInfo != NULL, STATUS_NULL_ARG);
    MUTEX_LOCK(pDtlsSession->sslLock);
    locked = TRUE;
    CHK(!ATOMIC_LOAD_BOOL(&pDtlsSession->isShutdown) && !ATOMIC_LOAD_BOOL(&pDtlsSession->isCleanUp) &&
            pDtlsSession->state != RTC_DTLS_TRANSPORT_STATE_CLOSED && pDtlsSession->state != RTC_DTLS_TRANSPORT_STATE_FAILED &&
            SSL_is_init_finished(pDtlsSession->pSsl),
        STATUS_INVALID_OPERATION);

    pInfo->protocolVersion = (UINT16) SSL_version(pDtlsSession->pSsl);
    pInfo->sessionResumed = SSL_session_reused(pDtlsSession->pSsl) != 0;
    pInfo->validFields |= RTC_DTLS_INFO_PROTOCOL | RTC_DTLS_INFO_SESSION_REUSED;
    pCipher = SSL_get_current_cipher(pDtlsSession->pSsl);
    if (pCipher != NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
        pInfo->cipherSuite = SSL_CIPHER_get_protocol_id(pCipher);
#else
        pInfo->cipherSuite = (UINT16) (SSL_CIPHER_get_id(pCipher) & 0xffff);
#endif
        pInfo->validFields |= RTC_DTLS_INFO_CIPHER;
    }
    if (!pInfo->sessionResumed) {
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
        CHK_STATUS(dtlsCopyAlgorithmName(SSL_get0_group_name(pDtlsSession->pSsl), pInfo->group, RTC_DTLS_INFO_GROUP, pInfo));
#endif
#if defined(SSL_get0_signature_name) && defined(SSL_get0_peer_signature_name)
        const CHAR* pName = NULL;
        if (SSL_get0_signature_name(pDtlsSession->pSsl, &pName) == 1) {
            CHK_STATUS(dtlsCopyAlgorithmName(pName, pInfo->localSignatureAlgorithm, RTC_DTLS_INFO_LOCAL_SIGNATURE, pInfo));
        }
        pName = NULL;
        if (SSL_get0_peer_signature_name(pDtlsSession->pSsl, &pName) == 1) {
            CHK_STATUS(dtlsCopyAlgorithmName(pName, pInfo->remoteSignatureAlgorithm, RTC_DTLS_INFO_REMOTE_SIGNATURE, pInfo));
        }
#endif
    }
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    switch (SSL_get_early_data_status(pDtlsSession->pSsl)) {
        case SSL_EARLY_DATA_NOT_SENT:
            pInfo->earlyDataStatus = RTC_DTLS_EARLY_DATA_NOT_SENT;
            break;
        case SSL_EARLY_DATA_REJECTED:
            pInfo->earlyDataStatus = RTC_DTLS_EARLY_DATA_REJECTED;
            break;
        case SSL_EARLY_DATA_ACCEPTED:
            pInfo->earlyDataStatus = RTC_DTLS_EARLY_DATA_ACCEPTED;
            break;
    }
    if (pInfo->earlyDataStatus != RTC_DTLS_EARLY_DATA_UNKNOWN) {
        pInfo->validFields |= RTC_DTLS_INFO_EARLY_DATA;
    }
#endif

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->sslLock);
    }
    return retStatus;
#else
    UNUSED_PARAM(pDtlsSession);
    UNUSED_PARAM(pInfo);
    return STATUS_NOT_IMPLEMENTED;
#endif
}

STATUS dtlsFillPseudoRandomBits(PBYTE pBuf, UINT32 bufSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i;

    CHK(pBuf != NULL, STATUS_NULL_ARG);
    CHK(bufSize >= DTLS_CERT_MIN_SERIAL_NUM_SIZE && bufSize <= DTLS_CERT_MAX_SERIAL_NUM_SIZE, retStatus);

    for (i = 0; i < bufSize; i++) {
        *pBuf++ = (BYTE) (RAND() & 0xFF);
    }

CleanUp:

    LEAVES();
    return retStatus;
}
