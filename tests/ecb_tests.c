#include <stdlib.h>

#include "blowfish.h"
#include "test-lib.h"

static uint8_t const key[] = {0xbc, 0xf8, 0xa2, 0x60, 0x19, 0x96, 0x62, 0xd5,
                              0xba, 0x73, 0x03, 0x64, 0x86, 0xef, 0x1c, 0x9c,
                              0xc9, 0xcf, 0xf2, 0xa1, 0xb5, 0x00, 0xc8, 0x19,
                              0x36, 0xb2, 0xf0, 0x15, 0x8d, 0xb2, 0x28, 0x66,
                              0x76, 0xc0, 0xcd, 0xad, 0x56};

/* plaintext = "message that is a multiple of block size bytes in length" */
static uint8_t const plaintext[] = {
    0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x74, 0x68, 0x61, 0x74,
    0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x70,
    0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x20,
    0x73, 0x69, 0x7a, 0x65, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 0x69,
    0x6e, 0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68};
static uint8_t const ciphertext[] = {
    0x4c, 0x8d, 0xa5, 0xd0, 0xe0, 0xa6, 0x9b, 0x16, 0x0f, 0xc3, 0x1f, 0xe2,
    0x5d, 0xcc, 0x71, 0x97, 0x2a, 0x3b, 0x04, 0x42, 0x18, 0x49, 0xc6, 0xde,
    0x25, 0x9a, 0xc2, 0x8c, 0xd0, 0xf9, 0x1e, 0xcb, 0x17, 0x71, 0x36, 0xbb,
    0x6c, 0xf7, 0xde, 0x74, 0x89, 0x23, 0xf8, 0xf3, 0xec, 0x73, 0x40, 0x21,
    0x59, 0x1f, 0x65, 0x10, 0x58, 0xc7, 0x93, 0x85};

static void
test_ecb_parameter_checking()
{
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), NULL, 0, MODE_ECB,
                              0, &on_error, HERE),
                "blowfish_init failed unexpectedly for ECB");
    assert_false(blowfish_init(&state, &key[0], sizeof(key), &key[0],
                               sizeof(key), MODE_ECB, 0, NULL, NULL),
                 "ECB mode should not accept an initialization vector");
}

static void
test_ecb_encryption()
{
    uint8_t *cipher;
    size_t cipher_len;
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), NULL, 0, MODE_ECB,
                              0, &on_error, HERE),
                "blowfish_init failed unexpectedly for ECB");

    cipher = blowfish_encrypt(&state, NULL, 0, &cipher_len, &on_error, HERE);
    assert_true(cipher == NULL, "encrypting zero length message returns NULL");
    assert_true(cipher_len == 0, "encrypt should set cipher length to zero");

    blowfish_reset(&state);
    cipher = blowfish_encrypt(&state, &plaintext[0], sizeof(plaintext),
                              &cipher_len, &on_error, HERE);
    assert_true(cipher != NULL, "encrypt failed unexpectedly");
    assert_true(cipher_len == sizeof(ciphertext),
                "encrypt produced the wrong number of bytes");
    assert_bytes_equal(cipher, &ciphertext[0], sizeof(ciphertext),
                       "encryption produced unexpected result", __FILE__,
                       __LINE__);

    blowfish_reset(&state);
    state.pkcs7padding = false;
    cipher = blowfish_encrypt(&state, &plaintext[0], sizeof(plaintext) - 1,
                              &cipher_len, NULL, NULL);
    assert_true(cipher == NULL, "encrypting non-blocksize message should fail");
    assert_true(cipher_len == 0,
                "encrypting non-blocksize message should fail");

    free(cipher);
}

static void
test_ecb_decryption()
{
    uint8_t *decrypted;
    size_t decrypted_len;
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), NULL, 0, MODE_ECB,
                              0, &on_error, HERE),
                "blowfish_init failed unexpectedly for ECB");

    decrypted =
        blowfish_decrypt(&state, NULL, 0, &decrypted_len, &on_error, HERE);
    assert_true(decrypted == NULL,
                "decrypting zero length message returns NULL");
    assert_true(decrypted_len == 0, "decrypt should set cipher length to zero");

    blowfish_reset(&state);
    decrypted = blowfish_decrypt(&state, &ciphertext[0], sizeof(ciphertext),
                                 &decrypted_len, &on_error, HERE);
    assert_true(decrypted != NULL, "decrypt failed unexpectedly");
    assert_true(decrypted_len == sizeof(plaintext),
                "decrypt produced the wrong number of bytes");
    assert_bytes_equal(decrypted, &plaintext[0], sizeof(plaintext),
                       "decryption produced unexpected result", __FILE__,
                       __LINE__);

    blowfish_reset(&state);
    state.pkcs7padding = false;
    decrypted = blowfish_decrypt(&state, &ciphertext[0], 13, &decrypted_len,
                                 NULL, NULL);
    assert_true(decrypted == NULL, "decrypting non-blocksize message fails");

    free(decrypted);
}

int
main(__attribute__((unused)) int argc, __attribute__((unused)) char *argv[])
{
    test_ecb_parameter_checking();
    test_ecb_encryption();
    test_ecb_decryption();
    return error_counter;
}
