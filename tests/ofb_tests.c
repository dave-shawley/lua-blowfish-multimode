#include <stdlib.h>

#include "blowfish.h"
#include "test-lib.h"

static uint8_t const key[] = {
    245, 254, 91,  88,  62,  66,  28,  202, 72,  111, 162, 19, 1,
    155, 238, 107, 99,  68,  189, 25,  188, 201, 22,  221, 73, 156,
    28,  151, 227, 151, 157, 75,  61,  194, 8,   125, 24,  78, 96,
    128, 28,  148, 66,  166, 142, 106, 71,  114, 163, 250, 210};
static uint8_t const init_vector[] = {63, 101, 174, 221, 133, 219, 126, 103};

/* plaintext = "this message can be any length that you want" */
static uint8_t const plaintext[] = {
    116, 104, 105, 115, 32,  109, 101, 115, 115, 97,  103, 101, 32,  99,  97,
    110, 32,  98,  101, 32,  97,  110, 121, 32,  108, 101, 110, 103, 116, 104,
    32,  116, 104, 97,  116, 32,  121, 111, 117, 32,  119, 97,  110, 116};
static uint8_t const ciphertext[] = {
    207, 12,  128, 100, 47,  248, 209, 246, 238, 21,  227, 113, 193, 183, 31,
    72,  173, 41,  191, 24,  222, 152, 184, 157, 93,  85,  167, 11,  187, 106,
    232, 49,  113, 227, 194, 200, 78,  162, 124, 252, 132, 62,  12,  155};

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
