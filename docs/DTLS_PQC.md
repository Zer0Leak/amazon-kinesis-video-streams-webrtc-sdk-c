# DTLS 1.3 and post-quantum key exchange

The OpenSSL backend requires **OpenSSL 4.1 or newer**. The source build is
pinned to **OpenSSL 4.1.0-alpha1**. This is the published
4.1 alpha release; OpenSSL labels it for testing only. It includes DTLS 1.3,
ML-KEM key exchange, hybrid groups, and ML-DSA authentication in the default
provider. No liboqs or oqs-provider is required. See the
[OpenSSL release announcement](https://openssl-library.org/post/2026-09-09-openssl-4.1-alpha/)
and [algorithm capabilities for this exact release](https://github.com/openssl/openssl/blob/openssl-4.1.0-alpha1/providers/common/capabilities.c).

## Build

Run from this SDK directory, using a fresh build and dependency prefix:

```sh
CMAKE_BUILD_PARALLEL_LEVEL=8 cmake -S . -B build-openssl41 \
  -DOPEN_SRC_INSTALL_PREFIX="$PWD/open-source-openssl41" \
  -DBUILD_DEPENDENCIES=ON -DUSE_OPENSSL=ON \
  -DBUILD_TEST=ON -DENABLE_AWS_SDK_IN_TESTS=OFF
cmake --build build-openssl41 -j8
```

If CMake 4 rejects the older minimum version in usrsctp, prefix the configure
command with `CMAKE_POLICY_VERSION_MINIMUM=3.5` so nested dependency builds
use its compatibility mode.

For OpenSSL 4, the build also selects libwebsockets 5.0.0 and libsrtp 2.7.0
to replace their uses of removed OpenSSL APIs. Rebuild dependent libraries
against the same OpenSSL installation. Existing dependency prefixes with a
different OpenSSL version are rejected rather than reused.

With `BUILD_DEPENDENCIES=OFF`, the SDK uses the installed OpenSSL selected by
CMake, which must be 4.1 or newer. Use `OPENSSL_ROOT_DIR` to select a custom
installation. The mbedTLS backend remains a separate alternative; the new API
returns `STATUS_NOT_IMPLEMENTED` when DTLS 1.3 is unavailable, including
mbedTLS builds.

## Application API

`createPeerConnection()` retains DTLS 1.2 behavior using the same OpenSSL 4.1
library. DTLS protocol versions do not require separate OpenSSL versions.
To require DTLS 1.3, use one additional function with two algorithm selectors:

```c
RtcConfiguration config = {0};
RtcDtlsConfiguration dtls = {
    .pGroups = "X25519MLKEM768",
    .pSignatureAlgorithms = "ecdsa_secp256r1_sha256",
};
PRtcPeerConnection peer = NULL;

/* Initialize the SDK with initKvsWebRtc() as usual. */
STATUS status = createPeerConnectionWithDtlsConfiguration(&config, &dtls, &peer);
/* Check status before continuing with the usual ICE, SDP, and media APIs. */
```

Configure both peers with compatible selections:

| Key exchange + authentication | `pGroups` | `pSignatureAlgorithms` | Local certificate/key |
| --- | --- | --- | --- |
| Modern classic + modern classic | `X25519` | `ecdsa_secp256r1_sha256` | Default generated ECDSA P-256 |
| Hybrid + modern classic | `X25519MLKEM768` | `ecdsa_secp256r1_sha256` | Default generated ECDSA P-256 |
| PQC + PQC | `MLKEM768` | `mldsa65` | Application-supplied ML-DSA-65 |

Both strings must be nonempty. They use OpenSSL's groups/signature list syntax;
colon-separated alternatives are allowed. Only include alternatives your
application is willing to negotiate. Adding a classical group to a PQC list
allows classical negotiation. The explicit API fixes both minimum and maximum
protocol versions to DTLS 1.3, with no DTLS 1.2 fallback. A NULL DTLS configuration
is equivalent to calling the existing creation function.

Invalid names fail creation. Valid but incompatible algorithm selections or
certificate types fail the handshake. Signature selection controls both local
and peer handshake authentication; choosing `mldsa65` does not generate an
ML-DSA certificate automatically.

Existing public configuration structures are unchanged, and no OpenSSL types
are added to public function signatures. The configuration and strings are
consumed during creation and can then be released.

### Additional options and negotiated results

`createPeerConnectionWithDtlsOptions()` reuses the same configuration and adds
a cipher-suite list and explicit session controls:

```c
RtcDtlsOptions options = {0};
options.structSize = sizeof(options);
options.pCipherSuites = "TLS_AES_256_GCM_SHA384";
options.resumption = RTC_DTLS_OPTION_DISABLED;
options.tickets = RTC_DTLS_OPTION_DISABLED;
options.earlyData = RTC_DTLS_OPTION_DISABLED;
status = createPeerConnectionWithDtlsOptions(&config, &dtls, &options, &peer);
```

NULL options preserve the existing creation behavior. Non-NULL options require
a DTLS configuration. Each control accepts DEFAULT, DISABLED or ENABLED;
DEFAULT preserves backend behavior and DISABLED enforces the prohibition.
All three ENABLED settings currently return `STATUS_NOT_IMPLEMENTED`: session
transfer and early application-data integration are not provided by this API.
Disabling tickets/resumption suppresses issuance and makes received sessions
unusable for reuse; live session metadata can remain until peer destruction.
An explicit prohibition can constrain related DEFAULT mechanisms.

After handshake completion, an application worker can call
`getPeerConnectionDtlsInfo()` with `RtcDtlsInfo.structSize = sizeof(RtcDtlsInfo)`.
It copies the actual protocol/cipher wire values, group and handshake signature
names, session-reuse flag and early-data outcome. Check `validFields` before
using any observation. The result contains no backend pointers and survives
peer destruction. Missing observations have no validity bit; oversized names
fail without truncation. A successful query does not establish peer trust.

Call the getter outside SDK callbacks and serialize it with close/free. Before
completion or after close it returns `STATUS_INVALID_OPERATION`. Errors clear
a correctly sized result while preserving its size; invalid sizes leave the
record untouched. The existing public structures and constructors retain their
layouts and signatures. Profile selection, credential policy and application
admission belong to the application layer.

## Supplying an ML-DSA certificate

Use the existing `RtcConfiguration.certificates` field. In the OpenSSL backend,
its pointers represent native `X509` and `EVP_PKEY` objects, **not PEM/DER bytes**.
For example, generate a fresh self-signed certificate with the selected OpenSSL:

```sh
LD_LIBRARY_PATH="$PWD/open-source-openssl41/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  open-source-openssl41/bin/openssl req -x509 -newkey ML-DSA-65 -noenc \
  -keyout peer-key.pem -out peer-cert.pem -days 30 -subj /CN=webrtc-peer
```

Load it in the application before peer creation:

```c
#include <openssl/pem.h>

/* config is the zero-initialized RtcConfiguration used above. */
BIO* certBio = BIO_new_file("peer-cert.pem", "r");
BIO* keyBio = BIO_new_file("peer-key.pem", "r");
X509* cert = certBio ? PEM_read_bio_X509(certBio, NULL, NULL, NULL) : NULL;
EVP_PKEY* key = keyBio ? PEM_read_bio_PrivateKey(keyBio, NULL, NULL, NULL) : NULL;
BIO_free(certBio);
BIO_free(keyBio);

if (cert != NULL && key != NULL) {
    config.certificates[0].pCertificate = (PBYTE) cert;
    config.certificates[0].pPrivateKey = (PBYTE) key;
    RtcDtlsConfiguration pqc = {"MLKEM768", "mldsa65"};
    status = createPeerConnectionWithDtlsConfiguration(&config, &pqc, &peer);
} else {
    status = STATUS_CERTIFICATE_GENERATION_FAILED;
}
X509_free(cert);
EVP_PKEY_free(key);
/* Check status. SDK retains its own references on successful creation. */
```

Use one certificate/key pair per explicit DTLS 1.3 configuration; the SDK's
existing SDP path advertises one certificate fingerprint. SDP SHA-256
fingerprint verification remains required before SRTP or SCTP is enabled.

## Scope and interoperability

This selects the peer DTLS key exchange and authentication. Media continues
to use the existing SRTP profiles (AES-128-CTR with HMAC-SHA1); data channels
continue to use SCTP over DTLS. Signaling HTTPS/WSS and STUN/TURN server TLS/DTLS
are configured separately. Thus “PQC + PQC” refers to the peer handshake's
asymmetric algorithms, not to every cryptographic operation in the application.

Both endpoints must implement DTLS 1.3 and the selected algorithms. A browser
or service that supports only DTLS 1.2 cannot connect to the explicit mode.
Use the existing API for such peers. This upgrade alone does not establish
browser or Kinesis service interoperability for DTLS 1.3.

The transport preserves datagram boundaries for fragmented PQC handshakes and
continues servicing DTLS 1.3 acknowledgements/retransmissions after connection.
See the [OpenSSL DTLS 1.3 guide](https://github.com/openssl/openssl/blob/openssl-4.1.0-alpha1/doc/man7/ossl-guide-dtlsv13.pod).

Run the local integration and regression tests without AWS credentials:

```sh
build-openssl41/tst/webrtc_client_test \
  --gtest_filter='DtlsPqc*.*:DtlsApiTest.*:DtlsFunctionalityTest.*:PeerConnectionApiTest.*:SrtpApiTest.*:DataChannelApiTest.*:DataChannelFunctionalityTest.*'
```

Validated on Linux with OpenSSL 4.1.0-alpha1: **54 selected tests pass**, including
18 native DTLS cases and 36 existing DTLS, peer API, SRTP and DataChannel cases.
The native cases cover algorithm negotiation over local ICE, bidirectional
4096-byte messages, SRTP, packet loss, final-ACK handling, incompatible offers,
DTLS 1.2 downgrade rejection, typed options, copied results and actual received
ticket invalidation. The installed public SDK also passes 14 application-layer
fixture cases and C11/C++11 consumer checks, including an old-header C consumer
against the new shared library. See the [execution record](../outputs/minimal-dtls-options-20260914T230219Z/implementation.md)
for exact commands, retained failed attempts and limits. This is shared,
statistics-OFF integration evidence; production trust policy and experiment
treatments remain unqualified.
