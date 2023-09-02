#include <stdlib.h>

#include "blowfish.h"
#include "test-lib.h"

static uint8_t const key[] = {0x07, 0xa1, 0xb8, 0xb8, 0x32, 0xe9, 0x5b, 0x2d,
                              0x64, 0xe2, 0xf5, 0xc1, 0x62, 0x3b, 0x54, 0x3d,
                              0x29, 0xe3, 0xed, 0x78, 0x00, 0xfb, 0x7f};
static uint8_t const init_vector[] = {0xB0, 0x0D, 0xB2, 0x31,
                                      0xc6, 0x7c, 0x82, 0x12};

/* plaintext = "multiple of segment size bits in length" */
static uint8_t const plaintext[] = {
    109, 117, 108, 116, 105, 112, 108, 101, 32,  111, 102, 32,  115,
    101, 103, 109, 101, 110, 116, 32,  115, 105, 122, 101, 32,  98,
    105, 116, 115, 32,  105, 110, 32,  108, 101, 110, 103, 116, 104};
static uint8_t const ciphertext[] = {
    211, 197, 60,  68, 163, 132, 23,  116, 142, 180, 33,  211, 120,
    15,  178, 142, 14, 175, 154, 188, 145, 122, 85,  115, 77,  120,
    101, 37,  145, 81, 116, 168, 131, 89,  99,  29,  71,  149, 130};
static int const segment_size = 24;

static void
test_cfb_parameter_checking()
{
    blowfish_state state;

    assert_true(blowfish_init(&state, &EIGHT_BYTES[0], sizeof(EIGHT_BYTES),
                              &EIGHT_BYTES[0], sizeof(EIGHT_BYTES), MODE_CFB, 0,
                              &on_error, HERE),
                "blowfish_init failed unexpectedly for CFB");
    assert_true(state.segment_size == 8, "CFB defaults to 8 bit feedback");

    assert_false(blowfish_init(&state, &EIGHT_BYTES[0], sizeof(EIGHT_BYTES),
                               NULL, 0, MODE_CFB, 0, NULL, NULL),
                 "CFB mode requires an initialization vector");

    assert_false(blowfish_init(&state, &EIGHT_BYTES[0], sizeof(EIGHT_BYTES),
                               &EIGHT_BYTES[0], sizeof(EIGHT_BYTES) - 1,
                               MODE_CFB, 0, NULL, NULL),
                 "CFB mode requires an 8 byte initialization vector");
}

static void
test_cfb_encryption()
{
    uint8_t *cipher;
    size_t cipher_len;
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), &init_vector[0],
                              sizeof(init_vector), MODE_CFB, segment_size,
                              &on_error, HERE),
                "blowfish_init failed unexpectedly for CFB");

    cipher = blowfish_encrypt(&state, NULL, 0, &cipher_len, &on_error, HERE);
    assert_true(cipher == NULL, "encrypting zero length message returns NULL");
    assert_true(cipher_len == 0, "encrypt should set cipher length to zero");

    blowfish_reset(&state);
    cipher = blowfish_encrypt(&state, &plaintext[0], sizeof(plaintext) - 1,
                              &cipher_len, NULL, NULL);
    assert_true(cipher == NULL,
                "encrypting message of non segment size length should fail");
    assert_true(cipher_len == 0,
                "encrypting message of non segment size length should fail");

    blowfish_reset(&state);
    cipher = blowfish_encrypt(&state, &plaintext[0], sizeof(plaintext),
                              &cipher_len, &on_error, HERE);
    assert_true(cipher != NULL, "encrypt failed unexpectedly");
    assert_true(cipher_len == sizeof(ciphertext),
                "encrypt produced the wrong number of bytes");
    assert_bytes_equal(cipher, &ciphertext[0], sizeof(ciphertext),
                       "encryption produced unexpected result", __FILE_NAME__,
                       __LINE__);
    free(cipher);
}

static void
test_cfb_decryption()
{
    uint8_t *decrypted;
    size_t decrypted_len;
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), &init_vector[0],
                              sizeof(init_vector), MODE_CFB, segment_size,
                              &on_error, HERE),
                "blowfish_init failed unexpectedly for CFB");

    decrypted =
        blowfish_decrypt(&state, NULL, 0, &decrypted_len, &on_error, HERE);
    assert_true(decrypted == NULL,
                "decrypting zero length message returns NULL");
    assert_true(decrypted_len == 0, "decrypt should set cipher length to zero");

    decrypted = blowfish_decrypt(&state, &ciphertext[0], 13, &decrypted_len,
                                 NULL, NULL);
    assert_true(decrypted == NULL,
                "decrypting non-segment size aligned message fails");

    blowfish_reset(&state);
    decrypted = blowfish_decrypt(&state, &ciphertext[0], sizeof(ciphertext),
                                 &decrypted_len, &on_error, HERE);
    assert_true(decrypted != NULL, "decrypt failed unexpectedly");
    assert_true(decrypted_len == sizeof(plaintext),
                "decrypt produced the wrong number of bytes");
    assert_bytes_equal(decrypted, &plaintext[0], sizeof(plaintext),
                       "decryption produced unexpected result", __FILE_NAME__,
                       __LINE__);
    free(decrypted);
}

int
main(__attribute__((unused)) int argc, __attribute__((unused)) char *argv[])
{
    test_cfb_parameter_checking();
    test_cfb_encryption();
    test_cfb_decryption();
    return error_counter;
}
