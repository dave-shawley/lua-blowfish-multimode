#include <stdlib.h>

#include "blowfish.h"
#include "test-lib.h"

static uint8_t const key[] = {188, 248, 162, 96,  25,  150, 98,  213, 186, 115,
                              3,   100, 134, 239, 28,  156, 201, 207, 242, 161,
                              181, 0,   200, 25,  54,  178, 240, 21,  141, 178,
                              40,  102, 118, 192, 205, 173, 86};

/* plaintext = "message that is a multiple of block size bytes in length" */
static uint8_t const plaintext[] = {
    109, 101, 115, 115, 97,  103, 101, 32,  116, 104, 97,  116, 32,  105,
    115, 32,  97,  32,  109, 117, 108, 116, 105, 112, 108, 101, 32,  111,
    102, 32,  98,  108, 111, 99,  107, 32,  115, 105, 122, 101, 32,  98,
    121, 116, 101, 115, 32,  105, 110, 32,  108, 101, 110, 103, 116, 104};
static uint8_t const ciphertext[] = {
    76,  141, 165, 208, 224, 166, 155, 22,  15,  195, 31,  226, 93,  204,
    113, 151, 42,  59,  4,   66,  24,  73,  198, 222, 37,  154, 194, 140,
    208, 249, 30,  203, 23,  113, 54,  187, 108, 247, 222, 116, 137, 35,
    248, 243, 236, 115, 64,  33,  89,  31,  101, 16,  88,  199, 147, 133};

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
