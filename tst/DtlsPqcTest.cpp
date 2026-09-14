#include "WebRTCClientTestFixture.h"

namespace com {
namespace amazonaws {
namespace kinesis {
namespace video {
namespace webrtcclient {

class DtlsPqcTest : public WebRtcClientTestBase {};

#if defined(KVS_USE_OPENSSL) && defined(DTLS1_3_VERSION) && !defined(OPENSSL_NO_DTLS1_3)

class DtlsPqcConnectionTest : public WebRtcClientTestBase {
  protected:
    struct PeerState {
        std::mutex mutex;
        std::queue<std::string> candidates;
        std::atomic<int> state{RTC_PEER_CONNECTION_STATE_NEW};
#ifdef ENABLE_DATA_CHANNEL
        std::atomic<PRtcDataChannel> channel{nullptr};
        std::atomic<bool> open{false};
        std::atomic<UINT32> messages{0};
#endif
    };

    PRtcPeerConnection peers[2] = {nullptr, nullptr};
    PeerState peerStates[2];

    void TearDown() override
    {
        for (auto& peer : peers) {
            if (peer != nullptr) {
                EXPECT_EQ(STATUS_SUCCESS, closePeerConnection(peer));
                EXPECT_EQ(STATUS_SUCCESS, freePeerConnection(&peer));
            }
        }
        WebRtcClientTestBase::TearDown();
    }

    // Applications provide native OpenSSL certificate/key objects using the existing certificate API.
    void createPeer(UINT32 index, PRtcDtlsConfiguration dtls, bool pqcCertificate, const RtcDtlsOptions* options = nullptr)
    {
        RtcConfiguration config{};
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(nullptr, EVP_PKEY_free);
        std::unique_ptr<X509, decltype(&X509_free)> certificate(nullptr, X509_free);
        if (pqcCertificate) {
            key.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-DSA-65"));
            ASSERT_NE(nullptr, key.get());
            certificate.reset(X509_new());
            ASSERT_NE(nullptr, certificate.get());
            ASSERT_EQ(1, X509_set_version(certificate.get(), 2));
            ASSERT_EQ(1, ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), index + 1));
            ASSERT_NE(nullptr, X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60));
            ASSERT_NE(nullptr, X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600));
            ASSERT_EQ(1, X509_set_pubkey(certificate.get(), key.get()));
            std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name(X509_NAME_new(), X509_NAME_free);
            ASSERT_NE(nullptr, name.get());
            ASSERT_EQ(1, X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC, (const unsigned char*) "PQC test", -1, -1, 0));
            ASSERT_EQ(1, X509_set_subject_name(certificate.get(), name.get()));
            ASSERT_EQ(1, X509_set_issuer_name(certificate.get(), name.get()));
            ASSERT_GT(X509_sign(certificate.get(), key.get(), nullptr), 0);
            config.certificates[0].pCertificate = (PBYTE) certificate.get();
            config.certificates[0].pPrivateKey = (PBYTE) key.get();
        }
        ASSERT_EQ(STATUS_SUCCESS, createPeerConnectionWithDtlsOptions(&config, dtls, options, &peers[index]));
        // The caller's references are released on return, before the handshake begins.
    }

    STATUS exchangeDescriptions()
    {
        STATUS retStatus = STATUS_SUCCESS;
        RtcSessionDescriptionInit sdp{};
        for (UINT32 i = 0; i < 2; ++i) {
            CHK_STATUS(peerConnectionOnIceCandidate(peers[i], (UINT64) &peerStates[i], [](UINT64 data, PCHAR candidate) {
                if (candidate != nullptr) {
                    auto* state = (PeerState*) data;
                    std::lock_guard<std::mutex> lock(state->mutex);
                    state->candidates.push(candidate);
                }
            }));
            CHK_STATUS(peerConnectionOnConnectionStateChange(peers[i], (UINT64) &peerStates[i],
                                                            [](UINT64 data, RTC_PEER_CONNECTION_STATE state) {
                                                                ((PeerState*) data)->state.store(state);
                                                            }));
        }
        CHK_STATUS(createOffer(peers[0], &sdp));
        CHK_STATUS(setLocalDescription(peers[0], &sdp));
        CHK_STATUS(setRemoteDescription(peers[1], &sdp));
        CHK_STATUS(createAnswer(peers[1], &sdp));
        CHK_STATUS(setLocalDescription(peers[1], &sdp));
        CHK_STATUS(setRemoteDescription(peers[0], &sdp));

    CleanUp:
        return retStatus;
    }

    STATUS connectPeers()
    {
        STATUS retStatus = exchangeDescriptions();
        if (STATUS_FAILED(retStatus)) {
            return retStatus;
        }
        const UINT64 deadline = GETTIME() + 10 * HUNDREDS_OF_NANOS_IN_A_SECOND;
        while (GETTIME() < deadline) {
            for (UINT32 i = 0; i < 2; ++i) {
                std::queue<std::string> candidates;
                {
                    std::lock_guard<std::mutex> lock(peerStates[i].mutex);
                    candidates.swap(peerStates[i].candidates);
                }
                while (!candidates.empty()) {
                    RtcIceCandidateInit candidate{};
                    CHK_STATUS(deserializeRtcIceCandidateInit((PCHAR) candidates.front().c_str(), candidates.front().size(), &candidate));
                    CHK_STATUS(addIceCandidate(peers[1 - i], candidate.candidate));
                    candidates.pop();
                }
            }
            if (peerStates[0].state.load() == RTC_PEER_CONNECTION_STATE_CONNECTED &&
                peerStates[1].state.load() == RTC_PEER_CONNECTION_STATE_CONNECTED) {
                return STATUS_SUCCESS;
            }
            CHK(peerStates[0].state.load() != RTC_PEER_CONNECTION_STATE_FAILED && peerStates[1].state.load() != RTC_PEER_CONNECTION_STATE_FAILED,
                STATUS_INTERNAL_ERROR);
            THREAD_SLEEP(10 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
        }
        retStatus = STATUS_OPERATION_TIMED_OUT;

    CleanUp:
        return retStatus;
    }

#ifdef ENABLE_DATA_CHANNEL
    static void onMessage(UINT64 data, PRtcDataChannel, BOOL binary, PBYTE message, UINT32 length)
    {
        BYTE expected[4096];
        MEMSET(expected, 0x5a, SIZEOF(expected));
        EXPECT_FALSE(binary);
        EXPECT_EQ(SIZEOF(expected), length);
        if (length == SIZEOF(expected) && MEMCMP(expected, message, length) == 0) {
            ((PeerState*) data)->messages.fetch_add(1);
        }
    }

    void prepareDataChannel()
    {
        ASSERT_EQ(STATUS_SUCCESS, peerConnectionOnDataChannel(peers[1], (UINT64) &peerStates[1], [](UINT64 data, PRtcDataChannel channel) {
                      auto* state = (PeerState*) data;
                      EXPECT_EQ(STATUS_SUCCESS, dataChannelOnMessage(channel, data, onMessage));
                      state->channel.store(channel);
                      state->open.store(true);
                  }));
        PRtcDataChannel channel = nullptr;
        ASSERT_EQ(STATUS_SUCCESS, createDataChannel(peers[0], (PCHAR) "PQC test", nullptr, &channel));
        peerStates[0].channel.store(channel);
        ASSERT_EQ(STATUS_SUCCESS, dataChannelOnMessage(channel, (UINT64) &peerStates[0], onMessage));
        ASSERT_EQ(STATUS_SUCCESS, dataChannelOnOpen(channel, (UINT64) &peerStates[0], [](UINT64 data, PRtcDataChannel) {
                      ((PeerState*) data)->open.store(true);
                  }));
    }

    void exchangeDataChannelMessages()
    {
        const UINT64 deadline = GETTIME() + 5 * HUNDREDS_OF_NANOS_IN_A_SECOND;
        while (GETTIME() < deadline && (!peerStates[0].open.load() || !peerStates[1].open.load())) {
            THREAD_SLEEP(10 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
        }
        ASSERT_TRUE(peerStates[0].open.load());
        ASSERT_TRUE(peerStates[1].open.load());
        BYTE message[4096];
        MEMSET(message, 0x5a, SIZEOF(message));
        for (auto& state : peerStates) {
            ASSERT_EQ(STATUS_SUCCESS, dataChannelSend(state.channel.load(), FALSE, (PBYTE) message, SIZEOF(message)));
        }
        while (GETTIME() < deadline && (peerStates[0].messages.load() != 1 || peerStates[1].messages.load() != 1)) {
            THREAD_SLEEP(10 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
        }
        EXPECT_EQ(1u, peerStates[0].messages.load());
        EXPECT_EQ(1u, peerStates[1].messages.load());
    }
#endif

    void verifyProfile(const CHAR* group, const CHAR* signature, bool pqcCertificate, const RtcDtlsOptions* options = nullptr)
    {
        RtcDtlsConfiguration dtls{group, signature};
        createPeer(0, &dtls, pqcCertificate, options);
        ASSERT_FALSE(HasFatalFailure());
        createPeer(1, &dtls, pqcCertificate, options);
        ASSERT_FALSE(HasFatalFailure());
        // Include media so both SRTP and SCTP use the negotiated DTLS transport.
        for (auto peer : peers) {
            RtcMediaStreamTrack track{};
            PRtcRtpTransceiver transceiver = nullptr;
            addTrackToPeerConnection(peer, &track, &transceiver, RTC_CODEC_OPUS, MEDIA_STREAM_TRACK_KIND_AUDIO);
        }
#ifdef ENABLE_DATA_CHANNEL
        prepareDataChannel();
        ASSERT_FALSE(HasFatalFailure());
#endif
        ASSERT_EQ(STATUS_SUCCESS, connectPeers());

        DtlsKeyingMaterial material[2]{};
        for (UINT32 i = 0; i < 2; ++i) {
            RtcDtlsInfo info{};
            info.structSize = SIZEOF(info);
            ASSERT_EQ(STATUS_SUCCESS, getPeerConnectionDtlsInfo(peers[i], &info));
            const UINT32 required = RTC_DTLS_INFO_PROTOCOL | RTC_DTLS_INFO_CIPHER | RTC_DTLS_INFO_GROUP |
                RTC_DTLS_INFO_LOCAL_SIGNATURE | RTC_DTLS_INFO_REMOTE_SIGNATURE | RTC_DTLS_INFO_SESSION_REUSED | RTC_DTLS_INFO_EARLY_DATA;
            EXPECT_EQ(required, info.validFields & required);
            EXPECT_EQ(DTLS1_3_VERSION, info.protocolVersion);
            EXPECT_EQ(0, STRCMPI(group, info.group));
            EXPECT_STREQ(signature, info.localSignatureAlgorithm);
            EXPECT_STREQ(signature, info.remoteSignatureAlgorithm);
            EXPECT_FALSE(info.sessionResumed);
            EXPECT_EQ(RTC_DTLS_EARLY_DATA_NOT_SENT, info.earlyDataStatus);
            if (options != nullptr && options->pCipherSuites != nullptr && STRCMP(options->pCipherSuites, "TLS_AES_256_GCM_SHA384") == 0) {
                EXPECT_EQ(0x1302, info.cipherSuite);
            }
            PDtlsSession session = ((PKvsPeerConnection) peers[i])->pDtlsSession;
            const CHAR* peerSignature = nullptr;
            // The peer transport remains live on other threads while these OpenSSL fields are inspected.
            MUTEX_LOCK(session->sslLock);
            EXPECT_EQ(DTLS1_3_VERSION, SSL_version(session->pSsl));
            const CHAR* negotiatedGroup = SSL_group_to_name(session->pSsl, SSL_get_negotiated_group(session->pSsl));
            EXPECT_NE(nullptr, negotiatedGroup);
            if (negotiatedGroup != nullptr) {
                EXPECT_EQ(0, STRCMPI(group, negotiatedGroup));
            }
            EXPECT_EQ(1, SSL_get0_peer_signature_name(session->pSsl, &peerSignature));
            EXPECT_STREQ(signature, peerSignature);
            std::unique_ptr<X509, decltype(&X509_free)> peerCertificate(SSL_get1_peer_certificate(session->pSsl), X509_free);
            EXPECT_NE(nullptr, peerCertificate.get());
            if (peerCertificate) {
                EXPECT_EQ(1, EVP_PKEY_is_a(X509_get0_pubkey(peerCertificate.get()), pqcCertificate ? "ML-DSA-65" : "EC"));
            }
            MUTEX_UNLOCK(session->sslLock);
            ASSERT_EQ(STATUS_SUCCESS, dtlsSessionPopulateKeyingMaterial(session, &material[i]));
        }
        EXPECT_EQ(material[0].srtpProfile, material[1].srtpProfile);
        EXPECT_EQ(material[0].key_length, material[1].key_length);
        EXPECT_EQ(0, MEMCMP(material[0].clientWriteKey, material[1].clientWriteKey, SIZEOF(material[0].clientWriteKey)));
        EXPECT_EQ(0, MEMCMP(material[0].serverWriteKey, material[1].serverWriteKey, SIZEOF(material[0].serverWriteKey)));
        for (UINT32 i = 0; i < 2; ++i) {
            // Exercise the SRTP contexts that the peer connection created from the DTLS exporter.
            const BYTE plain[] = {0x80, 111, 0, 1, 0, 0, 0, 1, 0x12, 0x34, 0x56, 0x78, 0xf8, 0xff, 0xfe};
            BYTE packet[SIZEOF(plain) + SRTP_MAX_TRAILER_LEN];
            MEMCPY(packet, plain, SIZEOF(plain));
            INT32 length = SIZEOF(plain);
            auto* sender = (PKvsPeerConnection) peers[i];
            auto* receiver = (PKvsPeerConnection) peers[1 - i];
            ASSERT_NE(nullptr, sender->pSrtpSession);
            ASSERT_NE(nullptr, receiver->pSrtpSession);
            MUTEX_LOCK(sender->pSrtpSessionLock);
            STATUS encrypted = encryptRtpPacket(sender->pSrtpSession, packet, &length);
            MUTEX_UNLOCK(sender->pSrtpSessionLock);
            ASSERT_EQ(STATUS_SUCCESS, encrypted);
            ASSERT_GT(length, SIZEOF(plain));
            EXPECT_NE(0, MEMCMP(packet + 12, plain + 12, SIZEOF(plain) - 12));
            MUTEX_LOCK(receiver->pSrtpSessionLock);
            STATUS decrypted = decryptSrtpPacket(receiver->pSrtpSession, packet, &length);
            MUTEX_UNLOCK(receiver->pSrtpSessionLock);
            ASSERT_EQ(STATUS_SUCCESS, decrypted);
            ASSERT_EQ(SIZEOF(plain), length);
            EXPECT_EQ(0, MEMCMP(packet, plain, SIZEOF(plain)));
        }
#ifdef ENABLE_DATA_CHANNEL
        exchangeDataChannelMessages();
#endif
    }
};

TEST_F(DtlsPqcConnectionTest, modernClassicKeyExchangeAndAuthentication)
{
    verifyProfile("X25519", "ecdsa_secp256r1_sha256", false);
}

TEST_F(DtlsPqcConnectionTest, hybridKeyExchangeAndModernClassicAuthentication)
{
    verifyProfile("X25519MLKEM768", "ecdsa_secp256r1_sha256", false);
}

TEST_F(DtlsPqcConnectionTest, purePqcKeyExchangeAndAuthentication)
{
    verifyProfile("MLKEM768", "mldsa65", true);
}

TEST_F(DtlsPqcConnectionTest, invalidSelectorsFailDuringCreation)
{
    RtcConfiguration config{};
    RtcDtlsConfiguration invalid[] = {{nullptr, "ecdsa_secp256r1_sha256"},
                                      {"", "ecdsa_secp256r1_sha256"},
                                      {"X25519", nullptr},
                                      {"X25519", ""},
                                      {"not-a-group", "ecdsa_secp256r1_sha256"},
                                      {"X25519", "not-a-signature"}};
    for (auto& dtls : invalid) {
        EXPECT_NE(STATUS_SUCCESS, createPeerConnectionWithDtlsConfiguration(&config, &dtls, &peers[0]));
        ASSERT_EQ(nullptr, peers[0]);
    }
}

TEST_F(DtlsPqcConnectionTest, existingEntryPointKeepsDtls12)
{
    RtcConfiguration config{};
    ASSERT_EQ(STATUS_SUCCESS, createPeerConnection(&config, &peers[0]));
    ASSERT_EQ(STATUS_SUCCESS, createPeerConnectionWithDtlsConfiguration(&config, nullptr, &peers[1]));
    for (auto peer : peers) {
        SSL_CTX* context = ((PKvsPeerConnection) peer)->pDtlsSession->pSslCtx;
        EXPECT_EQ(DTLS1_2_VERSION, SSL_CTX_get_max_proto_version(context));
    }
}

TEST_F(DtlsPqcConnectionTest, optionsRejectMalformedInputsWithoutPublishingPeer)
{
    RtcConfiguration config{};
    RtcDtlsConfiguration dtls{"X25519", "ecdsa_secp256r1_sha256"};
    RtcDtlsOptions options{};
    options.structSize = SIZEOF(options);
    auto rejected = [&](PRtcConfiguration configuration, PRtcDtlsConfiguration selectors, STATUS expected) {
        PRtcPeerConnection out = reinterpret_cast<PRtcPeerConnection>(static_cast<uintptr_t>(1));
        EXPECT_EQ(expected, createPeerConnectionWithDtlsOptions(configuration, selectors, &options, &out));
        EXPECT_EQ(nullptr, out);
        if (out != nullptr && out != reinterpret_cast<PRtcPeerConnection>(static_cast<uintptr_t>(1))) {
            freePeerConnection(&out);
        }
    };
    rejected(nullptr, &dtls, STATUS_NULL_ARG);
    rejected(&config, nullptr, STATUS_NULL_ARG);
    EXPECT_EQ(STATUS_NULL_ARG, createPeerConnectionWithDtlsOptions(&config, &dtls, &options, nullptr));
    for (UINT32 size : {0u, static_cast<UINT32>(SIZEOF(options) - 1), static_cast<UINT32>(SIZEOF(options) + 1)}) {
        options.structSize = size;
        rejected(&config, &dtls, STATUS_INVALID_ARG);
    }
    options.structSize = SIZEOF(options);
    for (RTC_DTLS_OPTION* field : {&options.resumption, &options.tickets, &options.earlyData}) {
        *field = static_cast<RTC_DTLS_OPTION>(3);
        rejected(&config, &dtls, STATUS_INVALID_ARG);
        *field = static_cast<RTC_DTLS_OPTION>(-1);
        rejected(&config, &dtls, STATUS_INVALID_ARG);
        *field = RTC_DTLS_OPTION_DEFAULT;
    }
    for (const CHAR* cipher : {"", "not-a-cipher-suite"}) {
        options.pCipherSuites = cipher;
        rejected(&config, &dtls, STATUS_INVALID_ARG);
    }
}

TEST_F(DtlsPqcConnectionTest, unsupportedPositiveSessionOptionsFailExplicitly)
{
    RtcConfiguration config{};
    RtcDtlsConfiguration dtls{"X25519", "ecdsa_secp256r1_sha256"};
    RtcDtlsOptions options{};
    options.structSize = SIZEOF(options);
    for (RTC_DTLS_OPTION* field : {&options.resumption, &options.tickets, &options.earlyData}) {
        *field = RTC_DTLS_OPTION_ENABLED;
        EXPECT_EQ(STATUS_NOT_IMPLEMENTED, createPeerConnectionWithDtlsOptions(&config, &dtls, &options, &peers[0]));
        ASSERT_EQ(nullptr, peers[0]);
        *field = RTC_DTLS_OPTION_DEFAULT;
    }
}

TEST_F(DtlsPqcConnectionTest, nullAndDefaultOptionsPreserveExistingCreationBehavior)
{
    RtcConfiguration config{};
    RtcDtlsConfiguration dtls{"X25519", "ecdsa_secp256r1_sha256"};
    RtcDtlsOptions options{};
    options.structSize = SIZEOF(options);
    ASSERT_EQ(STATUS_SUCCESS, createPeerConnection(&config, &peers[0]));
    ASSERT_EQ(STATUS_SUCCESS, createPeerConnectionWithDtlsOptions(&config, nullptr, nullptr, &peers[1]));
    for (auto peer : peers) {
        EXPECT_EQ(DTLS1_2_VERSION, SSL_get_max_proto_version(((PKvsPeerConnection) peer)->pDtlsSession->pSsl));
    }
    for (auto& peer : peers) {
        ASSERT_EQ(STATUS_SUCCESS, freePeerConnection(&peer));
    }
    ASSERT_EQ(STATUS_SUCCESS, createPeerConnectionWithDtlsConfiguration(&config, &dtls, &peers[0]));
    ASSERT_EQ(STATUS_SUCCESS, createPeerConnectionWithDtlsOptions(&config, &dtls, &options, &peers[1]));
    auto* original = ((PKvsPeerConnection) peers[0])->pDtlsSession;
    auto* withDefaults = ((PKvsPeerConnection) peers[1])->pDtlsSession;
    EXPECT_EQ(DTLS1_3_VERSION, SSL_get_min_proto_version(withDefaults->pSsl));
    EXPECT_EQ(DTLS1_3_VERSION, SSL_get_max_proto_version(withDefaults->pSsl));
    EXPECT_EQ(SSL_get_options(original->pSsl), SSL_get_options(withDefaults->pSsl));
    EXPECT_EQ(SSL_CTX_get_session_cache_mode(original->pSslCtx), SSL_CTX_get_session_cache_mode(withDefaults->pSslCtx));
    EXPECT_EQ(SSL_get_num_tickets(original->pSsl), SSL_get_num_tickets(withDefaults->pSsl));
    EXPECT_EQ(SSL_get_max_early_data(original->pSsl), SSL_get_max_early_data(withDefaults->pSsl));
    EXPECT_EQ(SSL_get_recv_max_early_data(original->pSsl), SSL_get_recv_max_early_data(withDefaults->pSsl));
}

TEST_F(DtlsPqcConnectionTest, getterClearsUnavailableFactsAndRejectsIncompatibleSize)
{
    RtcDtlsConfiguration dtls{"X25519", "ecdsa_secp256r1_sha256"};
    createPeer(0, &dtls, false);
    ASSERT_FALSE(HasFatalFailure());
    EXPECT_EQ(STATUS_NULL_ARG, getPeerConnectionDtlsInfo(peers[0], nullptr));
    RtcDtlsInfo cleared{};
    cleared.structSize = SIZEOF(cleared);
    RtcDtlsInfo info;
    MEMSET(&info, 0xa5, SIZEOF(info));
    info.structSize = SIZEOF(info);
    EXPECT_EQ(STATUS_INVALID_OPERATION, getPeerConnectionDtlsInfo(peers[0], &info));
    EXPECT_EQ(0, MEMCMP(&cleared, &info, SIZEOF(info)));
    MEMSET(&info, 0xa5, SIZEOF(info));
    info.structSize = SIZEOF(info);
    EXPECT_EQ(STATUS_NULL_ARG, getPeerConnectionDtlsInfo(nullptr, &info));
    EXPECT_EQ(0, MEMCMP(&cleared, &info, SIZEOF(info)));
    MEMSET(&info, 0xa5, SIZEOF(info));
    info.structSize = SIZEOF(info) - 1;
    RtcDtlsInfo unchanged = info;
    EXPECT_EQ(STATUS_INVALID_ARG, getPeerConnectionDtlsInfo(peers[0], &info));
    EXPECT_EQ(0, MEMCMP(&unchanged, &info, SIZEOF(info)));
}

TEST_F(DtlsPqcConnectionTest, cipherSelectionConsumesInputsAndCopiesActualNegotiation)
{
    {
        CHAR group[] = "X25519";
        CHAR signature[] = "ecdsa_secp256r1_sha256";
        CHAR offered[] = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256";
        CHAR accepted[] = "TLS_AES_128_GCM_SHA256";
        RtcDtlsConfiguration dtls{group, signature};
        RtcDtlsOptions options{};
        options.structSize = SIZEOF(options);
        options.pCipherSuites = offered;
        createPeer(0, &dtls, false, &options);
        ASSERT_FALSE(HasFatalFailure());
        options.pCipherSuites = accepted;
        createPeer(1, &dtls, false, &options);
        ASSERT_FALSE(HasFatalFailure());
        // The SDK must have consumed both independent configurations before returning.
        MEMSET(group, 'x', SIZEOF(group) - 1);
        MEMSET(signature, 'x', SIZEOF(signature) - 1);
        MEMSET(offered, 'x', SIZEOF(offered) - 1);
        MEMSET(accepted, 'x', SIZEOF(accepted) - 1);
    }
#ifdef ENABLE_DATA_CHANNEL
    prepareDataChannel();
    ASSERT_FALSE(HasFatalFailure());
#endif
    ASSERT_EQ(STATUS_SUCCESS, connectPeers());
    RtcDtlsInfo copies[2]{};
    for (UINT32 i = 0; i < 2; ++i) {
        copies[i].structSize = SIZEOF(copies[i]);
        ASSERT_EQ(STATUS_SUCCESS, getPeerConnectionDtlsInfo(peers[i], &copies[i]));
        EXPECT_EQ(RTC_DTLS_INFO_CIPHER, copies[i].validFields & RTC_DTLS_INFO_CIPHER);
        EXPECT_EQ(0x1301, copies[i].cipherSuite); // Selected AES-128, not the client's first offer.
        EXPECT_EQ(RTC_DTLS_INFO_GROUP, copies[i].validFields & RTC_DTLS_INFO_GROUP);
        EXPECT_EQ(0, STRCMPI("X25519", copies[i].group));
    }
    RtcDtlsInfo saved = copies[0];
    RtcDtlsInfo another{};
    another.structSize = SIZEOF(another);
    ASSERT_EQ(STATUS_SUCCESS, getPeerConnectionDtlsInfo(peers[0], &another));
    EXPECT_EQ(0, MEMCMP(&saved, &copies[0], SIZEOF(saved)));
    ASSERT_EQ(STATUS_SUCCESS, closePeerConnection(peers[0]));
    MEMSET(&another, 0xa5, SIZEOF(another));
    another.structSize = SIZEOF(another);
    EXPECT_EQ(STATUS_INVALID_OPERATION, getPeerConnectionDtlsInfo(peers[0], &another));
    RtcDtlsInfo cleared{};
    cleared.structSize = SIZEOF(cleared);
    EXPECT_EQ(0, MEMCMP(&cleared, &another, SIZEOF(another)));
    ASSERT_EQ(STATUS_SUCCESS, freePeerConnection(&peers[0]));
    EXPECT_EQ(0, MEMCMP(&saved, &copies[0], SIZEOF(saved)));
}

TEST_F(DtlsPqcConnectionTest, explicitDisablesConstrainBackendAndCompleteFullHandshake)
{
    RtcDtlsOptions options{};
    options.structSize = SIZEOF(options);
    options.pCipherSuites = "TLS_AES_256_GCM_SHA384";
    options.resumption = RTC_DTLS_OPTION_DISABLED;
    options.tickets = RTC_DTLS_OPTION_DISABLED;
    options.earlyData = RTC_DTLS_OPTION_DISABLED;
    verifyProfile("X25519", "ecdsa_secp256r1_sha256", false, &options);
    ASSERT_FALSE(HasFatalFailure());
    for (auto peer : peers) {
        auto* session = ((PKvsPeerConnection) peer)->pDtlsSession;
        MUTEX_LOCK(session->sslLock);
        const long cacheMode = SSL_CTX_get_session_cache_mode(session->pSslCtx);
        EXPECT_EQ(0, cacheMode & SSL_SESS_CACHE_SERVER);
        EXPECT_NE(0, cacheMode & SSL_SESS_CACHE_NO_INTERNAL_STORE);
        EXPECT_EQ(0u, SSL_get_num_tickets(session->pSsl));
        EXPECT_EQ(0u, SSL_get_max_early_data(session->pSsl));
        EXPECT_EQ(0u, SSL_get_recv_max_early_data(session->pSsl));
        SSL_SESSION* negotiated = SSL_get_session(session->pSsl);
        EXPECT_NE(nullptr, negotiated);
        if (negotiated != nullptr) {
            EXPECT_EQ(0, SSL_SESSION_has_ticket(negotiated));
            EXPECT_EQ(0, SSL_SESSION_is_resumable(negotiated));
        }
        MUTEX_UNLOCK(session->sslLock);
    }
}

class DtlsPqcRejectionTest : public WebRtcClientTestBase {
  protected:
    struct PacketQueue {
        std::mutex mutex;
        std::queue<std::vector<BYTE>> packets;
        bool dropNext = false;
        UINT32 dropped = 0;
    };
    PacketQueue inbound[2];
    PDtlsSession sessions[2] = {nullptr, nullptr};
    std::atomic<UINT32> receivedTickets[2]{{0}, {0}};
    TIMER_QUEUE_HANDLE timer = INVALID_TIMER_QUEUE_HANDLE_VALUE;

    void TearDown() override
    {
        for (auto& session : sessions) {
            EXPECT_EQ(STATUS_SUCCESS, freeDtlsSession(&session));
        }
        if (IS_VALID_TIMER_QUEUE_HANDLE(timer)) {
            EXPECT_EQ(STATUS_SUCCESS, timerQueueFree(&timer));
        }
        WebRtcClientTestBase::TearDown();
    }

    void handshake(PRtcDtlsConfiguration clientConfig, PRtcDtlsConfiguration serverConfig, bool expectConnection = false,
                   bool dropServerPacket = false, bool stopBeforeFinalAck = false,
                   const RtcDtlsOptions* clientOptions = nullptr, const RtcDtlsOptions* serverOptions = nullptr,
                   bool issueServerTickets = false)
    {
        ASSERT_EQ(STATUS_SUCCESS, timerQueueCreate(&timer));
        inbound[0].dropNext = dropServerPacket;
        PRtcDtlsConfiguration configs[] = {clientConfig, serverConfig};
        const RtcDtlsOptions* dtlsOptions[] = {clientOptions, serverOptions};
        for (UINT32 i = 0; i < 2; ++i) {
            DtlsSessionOptions options{};
            options.pDtlsConfiguration = configs[i];
            options.pDtlsOptions = dtlsOptions[i];
            DtlsSessionCallbacks callbacks{};
            callbacks.outBoundPacketFnCustomData = (UINT64) &inbound[1 - i];
            callbacks.outboundPacketFn = [](UINT64 data, PBYTE packet, UINT32 length) {
                auto* queue = (PacketQueue*) data;
                std::lock_guard<std::mutex> lock(queue->mutex);
                if (queue->dropNext) {
                    queue->dropNext = false;
                    ++queue->dropped;
                    return;
                }
                queue->packets.emplace(packet, packet + length);
            };
            ASSERT_EQ(STATUS_SUCCESS, createDtlsSessionWithOptions(&callbacks, timer, 0, FALSE, nullptr, &options, &sessions[i]));
            SSL_set_msg_callback_arg(sessions[i]->pSsl, &receivedTickets[i]);
            SSL_set_msg_callback(sessions[i]->pSsl,
                                 [](int write, int, int contentType, const void* buffer, size_t length, SSL*, void* data) {
                                     if (!write && contentType == SSL3_RT_HANDSHAKE && length != 0 &&
                                         ((const BYTE*) buffer)[0] == SSL3_MT_NEWSESSION_TICKET) {
                                         ((std::atomic<UINT32>*) data)->fetch_add(1);
                                     }
                                 });
        }
        if (issueServerTickets) {
            // OpenSSL suppresses tickets with client-certificate verification and no session-ID context.
            // Configure only the controlled remote issuer; retain every disabled-client setting.
            const BYTE context[] = "test-ticket-issuer";
            ASSERT_EQ(1, SSL_set_session_id_context(sessions[1]->pSsl, context, SIZEOF(context) - 1));
            ASSERT_EQ(1, SSL_set_num_tickets(sessions[1]->pSsl, 2));
        }
        ASSERT_EQ(STATUS_SUCCESS, dtlsSessionStart(sessions[1], TRUE));
        ASSERT_EQ(STATUS_SUCCESS, dtlsSessionStart(sessions[0], FALSE));
        const UINT64 deadline = GETTIME() + (expectConnection ? 10 : 2) * HUNDREDS_OF_NANOS_IN_A_SECOND;
        UINT32 connectedCount = 0;
        while (GETTIME() < deadline) {
            connectedCount = 0;
            for (UINT32 i = 0; i < 2; ++i) {
                std::queue<std::vector<BYTE>> packets;
                {
                    std::lock_guard<std::mutex> lock(inbound[i].mutex);
                    packets.swap(inbound[i].packets);
                }
                while (!packets.empty()) {
                    INT32 length = packets.front().size();
                    STATUS processed = dtlsSessionProcessPacket(sessions[i], packets.front().data(), &length);
                    if (expectConnection) {
                        ASSERT_EQ(STATUS_SUCCESS, processed);
                    }
                    packets.pop();
                }
                BOOL connected = FALSE;
                ASSERT_EQ(STATUS_SUCCESS, dtlsSessionIsInitFinished(sessions[i], &connected));
                if (stopBeforeFinalAck && i == 1 && connected) {
                    return;
                }
                connectedCount += connected ? 1 : 0;
                if (!expectConnection) {
                    ASSERT_FALSE(connected);
                }
            }
            if (connectedCount == 2) {
                break;
            }
            THREAD_SLEEP(10 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
        }
        EXPECT_EQ(expectConnection ? 2u : 0u, connectedCount);
        EXPECT_EQ(dropServerPacket ? 1u : 0u, inbound[0].dropped);
    }
};

TEST_F(DtlsPqcRejectionTest, incompatibleGroupsCannotFallBackToClassic)
{
    RtcDtlsConfiguration client{"MLKEM768", "ecdsa_secp256r1_sha256"};
    RtcDtlsConfiguration server{"X25519", "ecdsa_secp256r1_sha256"};
    handshake(&client, &server);
}

TEST_F(DtlsPqcRejectionTest, incompatibleAuthenticationCannotUseDefaultClassicCertificate)
{
    RtcDtlsConfiguration dtls{"MLKEM768", "mldsa65"};
    handshake(&dtls, &dtls);
}

TEST_F(DtlsPqcRejectionTest, explicitDtls13CannotDowngradeToDtls12)
{
    RtcDtlsConfiguration dtls{"X25519", "ecdsa_secp256r1_sha256"};
    handshake(&dtls, nullptr);
}

TEST_F(DtlsPqcRejectionTest, disjointCipherSuitesCannotUseBackendDefaults)
{
    RtcDtlsConfiguration dtls{"X25519", "ecdsa_secp256r1_sha256"};
    RtcDtlsOptions client{};
    client.structSize = SIZEOF(client);
    client.pCipherSuites = "TLS_AES_128_GCM_SHA256";
    RtcDtlsOptions server{};
    server.structSize = SIZEOF(server);
    server.pCipherSuites = "TLS_AES_256_GCM_SHA384";
    handshake(&dtls, &dtls, false, false, false, &client, &server);
}

TEST_F(DtlsPqcRejectionTest, disabledTicketsCannotRetainAnUnsolicitedTicketForReuse)
{
    RtcDtlsConfiguration dtls{"X25519", "ecdsa_secp256r1_sha256"};
    RtcDtlsOptions client{};
    client.structSize = SIZEOF(client);
    client.tickets = RTC_DTLS_OPTION_DISABLED;
    // The controlled remote has the session-ID context required to actually issue tickets.
    handshake(&dtls, &dtls, true, false, false, &client, nullptr, true);
    ASSERT_FALSE(HasFatalFailure());
    const UINT64 deadline = GETTIME() + 2 * HUNDREDS_OF_NANOS_IN_A_SECOND;
    while (GETTIME() < deadline && receivedTickets[0].load() == 0) {
        for (UINT32 i = 0; i < 2; ++i) {
            std::queue<std::vector<BYTE>> packets;
            {
                std::lock_guard<std::mutex> lock(inbound[i].mutex);
                packets.swap(inbound[i].packets);
            }
            while (!packets.empty()) {
                INT32 length = packets.front().size();
                ASSERT_EQ(STATUS_SUCCESS, dtlsSessionProcessPacket(sessions[i], packets.front().data(), &length));
                packets.pop();
            }
        }
        THREAD_SLEEP(10 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
    }
    ASSERT_GT(receivedTickets[0].load(), 0u) << "The test must deliver an actual unsolicited NewSessionTicket";
    MUTEX_LOCK(sessions[0]->sslLock);
    SSL_SESSION* current = SSL_get_session(sessions[0]->pSsl);
    EXPECT_NE(nullptr, current);
    if (current != nullptr) {
        EXPECT_EQ(0, SSL_SESSION_is_resumable(current));
    }
    EXPECT_EQ(0, SSL_CTX_sess_number(sessions[0]->pSslCtx));
    MUTEX_UNLOCK(sessions[0]->sslLock);
}

TEST_F(DtlsPqcRejectionTest, hybridHandshakeRetransmitsDroppedServerDatagram)
{
    RtcDtlsConfiguration dtls{"X25519MLKEM768", "ecdsa_secp256r1_sha256"};
    handshake(&dtls, &dtls, true, true);
}

TEST_F(DtlsPqcRejectionTest, applicationRecordsRemainIntactBeforeFinalHandshakeAck)
{
    RtcDtlsConfiguration dtls{"X25519MLKEM768", "ecdsa_secp256r1_sha256"};
    handshake(&dtls, &dtls, true, false, true);
    ASSERT_FALSE(HasFatalFailure());
    BOOL clientConnected = FALSE;
    ASSERT_EQ(STATUS_SUCCESS, dtlsSessionIsInitFinished(sessions[0], &clientConnected));
    ASSERT_FALSE(clientConnected);
    const UINT32 messageSize = 1024;
    BYTE message[messageSize];
    for (BYTE i = 1; i <= 3; ++i) {
        MEMSET(message, i, SIZEOF(message));
        ASSERT_EQ(STATUS_SUCCESS, dtlsSessionPutApplicationData(sessions[1], message, SIZEOF(message)));
    }
    UINT32 received[3] = {0, 0, 0};
    UINT32 messageCount = 0;
    bool releasedBySmallAck = false;
    const UINT64 deadline = GETTIME() + 2 * HUNDREDS_OF_NANOS_IN_A_SECOND;
    while (GETTIME() < deadline && messageCount < 3) {
        std::vector<std::vector<BYTE>> packets;
        {
            std::lock_guard<std::mutex> lock(inbound[0].mutex);
            while (!inbound[0].packets.empty()) {
                packets.push_back(std::move(inbound[0].packets.front()));
                inbound[0].packets.pop();
            }
        }
        // Deliver application records before the small final handshake ACK queued ahead of them.
        for (auto packet = packets.rbegin(); packet != packets.rend(); ++packet) {
            BYTE output[MAX_UDP_PACKET_SIZE];
            INT32 length = SIZEOF(output);
            ASSERT_EQ(STATUS_SUCCESS,
                      dtlsSessionProcessPacketWithBuffer(sessions[0], packet->data(), packet->size(), output, &length));
            if (packet->size() > messageSize) {
                EXPECT_EQ(0, length) << "Application data must remain buffered until the final ACK arrives";
            }
            if (length > 0 && packet->size() < messageSize) {
                releasedBySmallAck = true;
            }
            while (length > 0) {
                ASSERT_EQ(messageSize, length);
                ASSERT_GE(output[0], 1);
                ASSERT_LE(output[0], 3);
                ++received[output[0] - 1];
                ++messageCount;
                MEMSET(message, output[0], SIZEOF(message));
                EXPECT_EQ(0, MEMCMP(message, output, SIZEOF(message)));
                // More records can become readable without another UDP datagram arriving.
                length = SIZEOF(output);
                ASSERT_EQ(STATUS_SUCCESS, dtlsSessionProcessPacketWithBuffer(sessions[0], nullptr, 0, output, &length));
            }
        }
        THREAD_SLEEP(10 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
    }
    EXPECT_EQ(3u, messageCount);
    EXPECT_TRUE(releasedBySmallAck);
    for (auto count : received) {
        EXPECT_EQ(1u, count);
    }
}

#else

TEST_F(DtlsPqcTest, unsupportedBackendRejectsExplicitDtlsConfiguration)
{
    RtcConfiguration config{};
    RtcDtlsConfiguration dtls{"X25519", "ecdsa_secp256r1_sha256"};
    PRtcPeerConnection peer = nullptr;
    EXPECT_EQ(STATUS_NOT_IMPLEMENTED, createPeerConnectionWithDtlsConfiguration(&config, &dtls, &peer));
    if (peer != nullptr) {
        freePeerConnection(&peer);
        FAIL() << "An unsupported DTLS configuration created a peer";
    }
}

TEST_F(DtlsPqcTest, unsupportedBackendRejectsExplicitDtlsOptions)
{
    RtcConfiguration config{};
    RtcDtlsConfiguration dtls{"X25519", "ecdsa_secp256r1_sha256"};
    RtcDtlsOptions options{};
    options.structSize = SIZEOF(options);
    PRtcPeerConnection peer = nullptr;
    EXPECT_EQ(STATUS_NOT_IMPLEMENTED, createPeerConnectionWithDtlsOptions(&config, &dtls, &options, &peer));
    if (peer != nullptr) {
        freePeerConnection(&peer);
        FAIL() << "An unsupported DTLS options request created a peer";
    }
}

#endif

} // namespace webrtcclient
} // namespace video
} // namespace kinesis
} // namespace amazonaws
} // namespace com
