#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "partially_blind_rsa.h"

static void
test_default(void)
{
    // Context
    PBRSAContext context;
    pbrsa_context_init_default(&context);

    // [SERVER]: Generate a PBRSA-2048 key pair
    // Regular RSA and BRSA keys must not be used, as PBRSA has additional requirements.
    PBRSASecretKey sk;
    PBRSAPublicKey pk;
    assert(pbrsa_keypair_generate(&sk, &pk, 2048) == 0);

    // Metadata
    PBRSAMetadata metadata;
    metadata.metadata     = (uint8_t *) "metadata";
    metadata.metadata_len = strlen((const char *) metadata.metadata);

    // Derive key pair for metadata
    // The client can derive the public key on its own using `pbrsa_derive_publickey_for_metadata()`
    PBRSASecretKey dsk;
    PBRSAPublicKey dpk;
    assert(pbrsa_derive_keypair_for_metadata(&context, &dsk, &dpk, &sk, &pk, &metadata) == 0);

    // [CLIENT]: create a random message and blind it for the server whose public key is `dpk`.
    // The client must store the message and the blinding result.
    uint8_t            msg[32];
    const size_t       msg_len = sizeof msg;
    PBRSABlindingResult blinding_result;
    assert(pbrsa_blind_message_generate(&context, &blinding_result, msg, msg_len, &dpk,
                                        &metadata) == 0);

    // [SERVER]: compute a signature for a blind message, to be sent to the client.
    // The client secret should not be sent to the server.
    PBRSABlindSignature blind_sig;
    assert(pbrsa_blind_sign(&context, &blind_sig, &dsk, &blinding_result.blind_message) == 0);

    // [CLIENT]: later, when the client wants to redeem a signed blind message,
    // using the blinding secret, it can locally compute the signature of the
    // original message.
    // The client then owns a new valid (message, signature) pair, and the
    // server cannot link it to a previous(blinded message, blind signature) pair.
    // Note that the finalization function also verifies that the signature is
    // correct for the server public key.
    PBRSASignature sig;
    assert(pbrsa_finalize(&context, &sig, &blind_sig, &blinding_result, &dpk, msg, msg_len,
                          &metadata) == 0);
    pbrsa_blind_signature_deinit(&blind_sig);

    // [SERVER]: a non-blind signature can be verified using the server's public key.
    assert(pbrsa_verify(&context, &sig, &dpk, blinding_result.msg_randomizer, msg, msg_len,
                        &metadata) == 0);
    pbrsa_signature_deinit(&sig);

    pbrsa_blinding_result_deinit(&blinding_result);
    pbrsa_secretkey_deinit(&dsk);
    pbrsa_publickey_deinit(&dpk);
    pbrsa_secretkey_deinit(&sk);
    pbrsa_publickey_deinit(&pk);
}

int
main(void)
{
    test_default();

    return 0;
}
