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

static void
test_verifier_enforces_prepare_mode(void)
{
    PBRSASecretKey sk;
    PBRSAPublicKey pk;
    assert(pbrsa_keypair_generate(&sk, &pk, 2048) == 0);

    PBRSAMetadata metadata;
    metadata.metadata     = (uint8_t *) "metadata";
    metadata.metadata_len = strlen((const char *) metadata.metadata);

    const uint8_t msg[]   = "Hello, World!";
    const size_t  msg_len = sizeof msg - 1;

    PBRSAContext randomized_ctx;
    pbrsa_context_init_default(&randomized_ctx);
    PBRSASecretKey rand_dsk;
    PBRSAPublicKey rand_dpk;
    assert(pbrsa_derive_keypair_for_metadata(&randomized_ctx, &rand_dsk, &rand_dpk, &sk, &pk,
                                             &metadata) == 0);
    PBRSABlindingResult randomized_br;
    assert(pbrsa_blind(&randomized_ctx, &randomized_br, &rand_dpk, msg, msg_len, &metadata) == 0);
    assert(randomized_br.msg_randomizer != NULL);
    PBRSABlindSignature randomized_blind_sig;
    assert(pbrsa_blind_sign(&randomized_ctx, &randomized_blind_sig, &rand_dsk,
                            &randomized_br.blind_message) == 0);
    PBRSASignature randomized_sig;
    assert(pbrsa_finalize(&randomized_ctx, &randomized_sig, &randomized_blind_sig, &randomized_br,
                          &rand_dpk, msg, msg_len, &metadata) == 0);
    pbrsa_blind_signature_deinit(&randomized_blind_sig);

    PBRSAContext deterministic_ctx;
    pbrsa_context_init_deterministic(&deterministic_ctx);
    PBRSASecretKey det_dsk;
    PBRSAPublicKey det_dpk;
    assert(pbrsa_derive_keypair_for_metadata(&deterministic_ctx, &det_dsk, &det_dpk, &sk, &pk,
                                             &metadata) == 0);
    PBRSABlindingResult deterministic_br;
    assert(pbrsa_blind(&deterministic_ctx, &deterministic_br, &det_dpk, msg, msg_len, &metadata) ==
           0);
    assert(deterministic_br.msg_randomizer == NULL);
    PBRSABlindSignature deterministic_blind_sig;
    assert(pbrsa_blind_sign(&deterministic_ctx, &deterministic_blind_sig, &det_dsk,
                            &deterministic_br.blind_message) == 0);
    PBRSASignature deterministic_sig;
    assert(pbrsa_finalize(&deterministic_ctx, &deterministic_sig, &deterministic_blind_sig,
                          &deterministic_br, &det_dpk, msg, msg_len, &metadata) == 0);
    pbrsa_blind_signature_deinit(&deterministic_blind_sig);

    // A deterministic verifier must reject a randomized-mode signature, even when handed the
    // matching randomizer.
    assert(pbrsa_verify(&deterministic_ctx, &randomized_sig, &rand_dpk, randomized_br.msg_randomizer,
                        msg, msg_len, &metadata) == -1);

    // A randomized verifier must reject a deterministic-mode signature when no randomizer is
    // supplied — without the mode check, this would fail open.
    assert(pbrsa_verify(&randomized_ctx, &deterministic_sig, &det_dpk, NULL, msg, msg_len,
                        &metadata) == -1);

    // Sanity: each signature still verifies under its own mode with the matching randomizer.
    assert(pbrsa_verify(&randomized_ctx, &randomized_sig, &rand_dpk, randomized_br.msg_randomizer,
                        msg, msg_len, &metadata) == 0);
    assert(pbrsa_verify(&deterministic_ctx, &deterministic_sig, &det_dpk, NULL, msg, msg_len,
                        &metadata) == 0);

    pbrsa_signature_deinit(&randomized_sig);
    pbrsa_signature_deinit(&deterministic_sig);
    pbrsa_blinding_result_deinit(&randomized_br);
    pbrsa_blinding_result_deinit(&deterministic_br);
    pbrsa_secretkey_deinit(&rand_dsk);
    pbrsa_publickey_deinit(&rand_dpk);
    pbrsa_secretkey_deinit(&det_dsk);
    pbrsa_publickey_deinit(&det_dpk);
    pbrsa_secretkey_deinit(&sk);
    pbrsa_publickey_deinit(&pk);
}

int
main(void)
{
    test_default();
    test_verifier_enforces_prepare_mode();

    return 0;
}
