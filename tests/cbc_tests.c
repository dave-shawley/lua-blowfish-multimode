#include <stdlib.h>
#include <string.h>

#include "blowfish.h"
#include "test-lib.h"

static uint8_t const key[] = {0xd9, 0x6b, 0x1d, 0x59, 0xa4, 0x3a, 0xb6, 0x9d,
                              0x1d, 0x05, 0x29, 0xbb, 0xd9, 0xc2, 0x66, 0xa0,
                              0xb4, 0x31, 0xec, 0x8a, 0xc5, 0x94, 0x07, 0x73,
                              0x77, 0x2b, 0xfc, 0xb3, 0xdc, 0x1f, 0x22};
static uint8_t const init_vector[] = {0xbd, 0x9b, 0x7e, 0xb3,
                                      0x1f, 0x57, 0xb2, 0xdb};

/* plaintext = "message that is a multiple of block size bytes in length" */
static uint8_t const plaintext[] = {
    0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x74, 0x68, 0x61, 0x74,
    0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x70,
    0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x20,
    0x73, 0x69, 0x7a, 0x65, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 0x69,
    0x6e, 0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68};
static uint8_t const ciphertext[] = {
    0x0c, 0x14, 0xd5, 0x90, 0x52, 0x3d, 0x68, 0xd6, 0xe4, 0xa6, 0x68,
    0x9f, 0x6a, 0x37, 0x76, 0xa2, 0xa7, 0xdf, 0x48, 0x6f, 0x47, 0x0a,
    0xcb, 0x2c, 0x10, 0x36, 0x1b, 0x09, 0x38, 0x9a, 0xd1, 0x6f, 0xe4,
    0x1c, 0xa4, 0xb1, 0x39, 0x9b, 0xe6, 0x9c, 0x3a, 0x5e, 0xf3, 0xdf,
    0xa2, 0x1b, 0x65, 0x86, 0x54, 0x7a, 0x91, 0xdf, 0x69, 0xa4, 0xfa,
    0xb9, 0x57, 0x1e, 0x11, 0xc9, 0x1d, 0x78, 0x46, 0x2e};

/* plaintext = "random length text" */
static uint8_t const pkcs_plaintext[] = {0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d,
                                         0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74,
                                         0x68, 0x20, 0x74, 0x65, 0x78, 0x74};
static uint8_t const pkcs_ciphertext[] = {
    0x8a, 0x88, 0x64, 0x44, 0x41, 0x2f, 0x92, 0xf3, 0x8c, 0xfa, 0xc2, 0x81,
    0xf0, 0xc5, 0x08, 0xa3, 0xae, 0x1b, 0x72, 0x27, 0xc1, 0x72, 0x8a, 0x0e};

static void
test_cbc_parameter_checking()
{
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), &init_vector[0],
                              sizeof(init_vector), MODE_CBC, 0, &on_error,
                              HERE),
                "blowfish_init failed unexpectedly for CBC");

    assert_false(blowfish_init(&state, &key[0], sizeof(key), NULL, 0, MODE_CBC,
                               0, NULL, NULL),
                 "CBC mode requires an initialization vector");

    assert_false(blowfish_init(&state, &key[0], sizeof(key), &init_vector[0],
                               sizeof(init_vector) - 1, MODE_CBC, 0, NULL,
                               NULL),
                 "CBC mode requires an 8 byte initialization vector");
}

static void
test_cbc_encryption()
{
    uint8_t *cipher;
    size_t cipher_len;
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), &init_vector[0],
                              sizeof(init_vector), MODE_CBC, 0, &on_error,
                              HERE),
                "blowfish_init failed unexpectedly for CBC");

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
    cipher =
        blowfish_encrypt(&state, &pkcs_plaintext[0], sizeof(pkcs_plaintext),
                         &cipher_len, &on_error, HERE);
    assert_true(cipher != NULL, "encrypt failed unexpectedly for PKCS sample");
    assert_true(cipher_len == sizeof(pkcs_ciphertext),
                "encrypt produced the wrong number of bytes for PKCS sample");
    assert_bytes_equal(cipher, &pkcs_ciphertext[0], sizeof(pkcs_ciphertext),
                       "encryption produced unexpected result for PKCS sample",
                       __FILE__, __LINE__);

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
test_cbc_decryption()
{
    uint8_t incorrectly_padded[sizeof(plaintext) + BLOWFISH_BLOCK_SIZE];
    uint8_t *decrypted;
    size_t decrypted_len;
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), &init_vector[0],
                              sizeof(init_vector), MODE_CBC, 0, &on_error,
                              HERE),
                "blowfish_init failed unexpectedly for CBC");

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
    decrypted =
        blowfish_decrypt(&state, &pkcs_ciphertext[0], sizeof(pkcs_ciphertext),
                         &decrypted_len, &on_error, HERE);
    assert_true(decrypted != NULL, "decrypt failed unexpectedly");
    assert_true(decrypted_len == sizeof(pkcs_plaintext),
                "decrypt produced the wrong number of bytes");
    assert_bytes_equal(decrypted, &pkcs_plaintext[0], sizeof(pkcs_plaintext),
                       "decryption produced unexpected result", __FILE__,
                       __LINE__);

    memcpy(&incorrectly_padded, &plaintext, sizeof(plaintext));
    for (size_t i = 0; i < BLOWFISH_BLOCK_SIZE; ++i) {
        incorrectly_padded[sizeof(plaintext) + i] = i;
    }
    blowfish_reset(&state);
    decrypted = blowfish_decrypt(&state, &incorrectly_padded[0],
                                 sizeof(incorrectly_padded), &decrypted_len,
                                 NULL, NULL);
    assert_true(decrypted == NULL,
                "decrypting incorrectly padded message fails");

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
    test_cbc_parameter_checking();
    test_cbc_encryption();
    test_cbc_decryption();
    return error_counter;
}
