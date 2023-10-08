#include <stdlib.h>

#include "blowfish.h"
#include "test-lib.h"

static uint8_t const key[] = {
    0xf5, 0xfe, 0x5b, 0x58, 0x3e, 0x42, 0x1c, 0xca, 0x48, 0x6f, 0xa2,
    0x13, 0x01, 0x9b, 0xee, 0x6b, 0x63, 0x44, 0xbd, 0x19, 0xbc, 0xc9,
    0x16, 0xdd, 0x49, 0x9c, 0x1c, 0x97, 0xe3, 0x97, 0x9d, 0x4b, 0x3d,
    0xc2, 0x08, 0x7d, 0x18, 0x4e, 0x60, 0x80, 0x1c, 0x94, 0x42, 0xa6,
    0x8e, 0x6a, 0x47, 0x72, 0xa3, 0xfa, 0xd2};
static uint8_t const init_vector[] = {0x3f, 0x65, 0xae, 0xdd,
                                      0x85, 0xdb, 0x7e, 0x67};

/* plaintext = "this message can be any length that you want" */
static uint8_t const plaintext[] = {
    0x74, 0x68, 0x69, 0x73, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
    0x65, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x20, 0x61, 0x6e,
    0x79, 0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x20, 0x74, 0x68,
    0x61, 0x74, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x77, 0x61, 0x6e, 0x74};
static uint8_t const ciphertext[] = {
    0xcf, 0x0c, 0x80, 0x64, 0x2f, 0xf8, 0xd1, 0xf6, 0xee, 0x15, 0xe3,
    0x71, 0xc1, 0xb7, 0x1f, 0x48, 0xad, 0x29, 0xbf, 0x18, 0xde, 0x98,
    0xb8, 0x9d, 0x5d, 0x55, 0xa7, 0x0b, 0xbb, 0x6a, 0xe8, 0x31, 0x71,
    0xe3, 0xc2, 0xc8, 0x4e, 0xa2, 0x7c, 0xfc, 0x84, 0x3e, 0x0c, 0x9b};

static void
test_ofb_parameter_checking()
{
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), &init_vector[0],
                              sizeof(init_vector), MODE_OFB, 0, &on_error,
                              HERE),
                "blowfish_init failed unexpectedly for OFB");

    assert_false(blowfish_init(&state, &key[0], sizeof(key), NULL, 0, MODE_OFB,
                               0, NULL, NULL),
                 "OFB mode requires an initialization vector");

    assert_false(blowfish_init(&state, &key[0], sizeof(key), &init_vector[0],
                               sizeof(init_vector) - 1, MODE_OFB, 0, NULL,
                               NULL),
                 "OFB mode requires an 8 byte initialization vector");
}

static void
test_ofb_encryption()
{
    uint8_t *cipher;
    size_t cipher_len;
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), &init_vector[0],
                              sizeof(init_vector), MODE_OFB, 0, &on_error,
                              HERE),
                "blowfish_init failed unexpectedly for OFB");

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
    free(cipher);
}

static void
test_ofb_decryption()
{
    uint8_t *decrypted;
    size_t decrypted_len;
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), &init_vector[0],
                              sizeof(init_vector), MODE_OFB, 0, &on_error,
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
    free(decrypted);
}

int
main(__attribute__((unused)) int argc, __attribute__((unused)) char *argv[])
{
    test_ofb_parameter_checking();
    test_ofb_encryption();
    test_ofb_decryption();
    return error_counter;
}
