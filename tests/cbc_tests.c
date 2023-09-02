#include <stdlib.h>

#include "blowfish.h"
#include "test-lib.h"

static uint8_t const key[] = {217, 107, 29,  89,  164, 58,  182, 157,
                              29,  5,   41,  187, 217, 194, 102, 160,
                              180, 49,  236, 138, 197, 148, 7,   115,
                              119, 43,  252, 179, 220, 31,  34};
static uint8_t const init_vector[] = {189, 155, 126, 179, 31, 87, 178, 219};

/* plaintext = "message that is a multiple of block size bytes in length" */
static uint8_t const plaintext[] = {
    109, 101, 115, 115, 97,  103, 101, 32,  116, 104, 97,  116, 32,  105,
    115, 32,  97,  32,  109, 117, 108, 116, 105, 112, 108, 101, 32,  111,
    102, 32,  98,  108, 111, 99,  107, 32,  115, 105, 122, 101, 32,  98,
    121, 116, 101, 115, 32,  105, 110, 32,  108, 101, 110, 103, 116, 104};
static uint8_t const ciphertext[] = {
    12,  20,  213, 144, 82,  61,  104, 214, 228, 166, 104, 159, 106, 55,
    118, 162, 167, 223, 72,  111, 71,  10,  203, 44,  16,  54,  27,  9,
    56,  154, 209, 111, 228, 28,  164, 177, 57,  155, 230, 156, 58,  94,
    243, 223, 162, 27,  101, 134, 84,  122, 145, 223, 105, 164, 250, 185};

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
    cipher = blowfish_encrypt(&state, &plaintext[0], sizeof(plaintext) - 1,
                              &cipher_len, NULL, NULL);
    assert_true(cipher == NULL, "encrypting non-blocksize message should fail");
    assert_true(cipher_len == 0,
                "encrypting non-blocksize message should fail");

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
test_cbc_decryption()
{
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

    decrypted = blowfish_decrypt(&state, &ciphertext[0], 13, &decrypted_len,
                                 NULL, NULL);
    assert_true(decrypted == NULL, "decrypting non-blocksize message fails");

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
    test_cbc_parameter_checking();
    test_cbc_encryption();
    test_cbc_decryption();
    return error_counter;
}
