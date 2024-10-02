# Partially blind RSA signatures

This is an implementation of the [RSA Blind Signatures with Public Metadata](https://eprint.iacr.org/2023/1199) paper and [draft](https://datatracker.ietf.org/doc/draft-amjad-cfrg-partially-blind-rsa/), mechanically ported from [the Zig implementation](https://github.com/jedisct1/zig-rsa-blind-signatures).

## Protocol overview

A server creates a key pair `(sk, pk)`. Additional, metadata-specific key pairs `(dsk, dpk)` can be derived from that data and metadata.

A client asks a server to sign a message. This requires `dpk`, that the client can compute using `pk` and the metadata. The server receives the message, and returns the signature.

Using that `(message, signature, metadata)` tuple, the client can locally compute a second, valid `(message', signature', metadata)` tuple.

Anyone can verify that `(message', signature', metadata)` is valid for the server's public key and the metadata, even though the server didn't see that pair before.
But no one besides the client can link `(message', signature', metadata)` to `(message, signature, metadata)`.

Using that scheme, a server can issue a token and verify that a client has a valid token, without being able to link both actions to the same client.

1. The client creates a random message, and blinds it with a random, secret factor.
2. The server receives the blind message, signs it and returns a blind signature.
3. From the blind signature, and knowing the secret factor, the client can locally compute a `(message, signature, metadata)` tuple that can be verified using the server's public key.
4. Anyone, including the server, can thus later verify that `(message, signature, metadata)` is valid, without knowing when step 2 occurred.

Random noise must be added to messages that don't include enough entropy. An optional "Message Randomizer" can be used for that purpose.

The scheme was designed by Ghous Amjad, Kevin Yeo and Moti Yung.

## Dependencies

This implementation requires OpenSSL (1.1.x or 3.x.y) or BoringSSL.

## Usage

```c
    #include <blind_rsa.h>

    // Initialize a context with the default parameters
    PBRSAContext context;
    pbrsa_context_init_default(&context);

    // [SERVER]: Generate a PBRSA-2048 key pair
    // Regular RSA and BRSA keys must not be used, as PBRSA has additional requirements.
    PBRSASecretKey sk;
    PBRSAPublicKey pk;
    assert(pbrsa_keypair_generate(&sk, &pk, 2048) == 0);

    // Noise is not required if the message is random.
    // If it is not NULL, it will be automatically filled by brsa_blind_sign().
    PBRSAMessageRandomizer *msg_randomizer = NULL;

    // Metadata
    PBRSAMetadata metadata;
    metadata.metadata     = (uint8_t *) "metadata";
    metadata.metadata_len = strlen((const char *) metadata.metadata);    

    // Derive a key pair for the metadata
    // The client can derive the public key on its own using `pbrsa_derive_publickey_for_metadata()`
    PBRSASecretKey dsk;
    PBRSAPublicKey dpk;
    assert(pbrsa_derive_keypair_for_metadata(&context, &dsk, &dpk, &sk, &pk, &metadata) == 0);    

    // [CLIENT]: create a random message and blind it for the server whose public key is `pk`.
    // The client must store the message and the secret.
    uint8_t             msg[32];
    const size_t        msg_len = sizeof msg;
    PBRSABlindMessage   blind_msg;
    PBRSABlindingSecret client_secret;
    assert(pbrsa_blind_message_generate(&context, &blind_msg, msg, msg_len, &client_secret, &dpk,
                                        &metadata) == 0);

    // [SERVER]: compute a signature for a blind message, to be sent to the client.
    // The client secret should not be sent to the server.
    PBRSABlindSignature blind_sig;
    assert(pbrsa_blind_sign(&context, &blind_sig, &dsk, &blind_msg) == 0);
    pbrsa_blind_message_deinit(&blind_msg);

    // [CLIENT]: later, when the client wants to redeem a signed blind message,
    // using the blinding secret, it can locally compute the signature of the
    // original message.
    // The client then owns a new valid (message, signature) pair, and the
    // server cannot link it to a previous(blinded message, blind signature) pair.
    // Note that the finalization function also verifies that the signature is
    // correct for the server public key.
    PBRSASignature sig;
    assert(pbrsa_finalize(&context, &sig, &blind_sig, &client_secret, msg_randomizer, &dpk, msg,
                          msg_len, &metadata) == 0);
    pbrsa_blind_signature_deinit(&blind_sig);
    pbrsa_blinding_secret_deinit(&client_secret);

    // [SERVER]: a non-blind signature can be verified using the server's public key.
    assert(pbrsa_verify(&context, &sig, &dpk, msg_randomizer, msg, msg_len, &metadata) == 0);
    pbrsa_signature_deinit(&sig);

    pbrsa_secretkey_deinit(&dsk);
    pbrsa_publickey_deinit(&dpk);
    pbrsa_secretkey_deinit(&sk);
    pbrsa_publickey_deinit(&pk);
```

Deterministic padding is also supported, by creating a context with `pbrsa_context_init_deterministic()`:

```c
    // Initialize a context to use deterministic padding
    PBRSAContext context;
    pbrsa_context_init_deterministic(&context);
```

Most applications should use the default (probabilistic) mode instead.

A custom hash function and salt length can also be specified with `pbrsa_context_init_custom()`:

```c
    // Initialize a context with SHA-256 as a Hash and MGF function,
    // and a 48 byte salt.
    PBRSAContext context;
    pbrsa_context_init_custom(&context, PBRSA_SHA256, 48);
```

Some additional helper functions for key management are included:

```c
    // Get a key identifier
    uint8_t key_id[4];
    assert(pbrsa_publickey_id(&context, key_id, sizeof key_id, &pk) == 0);

    // Key serialization
    PBRSASerializedKey sk_der, pk_der;
    assert(pbrsa_secretkey_export(&sk_der, &sk) == 0);
    assert(pbrsa_publickey_export(&pk_der, &pk) == 0);

    // Store the SubjectPublicKeyInfo in DER format
    PBRSASerializedKey spki_der;
    assert(pbrsa_publickey_export_spki(&context, &spki_der, &pk) == 0);

    // Free key resources
    pbrsa_secretkey_deinit(&sk);
    pbrsa_publickey_deinit(&pk);

    // Key deserialization
    assert(pbrsa_secretkey_import(&sk, sk_der.bytes, sk_der.bytes_len) == 0);
    assert(pbrsa_publickey_import(&pk, pk_der.bytes, pk_der.bytes_len) == 0);
    pbrsa_serializedkey_deinit(&sk_der);
    pbrsa_serializedkey_deinit(&pk_der);
```

All these functions return `0` on success and `-1` on error.

## For other languages

* [Zig](https://github.com/jedisct1/zig-blind-rsa-signatures)

## Disclaimer

This is just a proof of concept. Error handling may not be great. Using the original Zig implementation is recommended.

This is slow, prone to DoS and side-channel attacks. This protocol should only be used if key pairs need to be generated on demand.

Using OpenSSL is recommended over BoringSSL, as it provides better performance for these operations.
