#include <stdlib.h>

#include "blowfish.h"
#include "test-lib.h"

static uint8_t const key[] = {0x07, 0xa1, 0xb8, 0xb8, 0x32, 0xe9, 0x5b, 0x2d,
                              0x64, 0xe2, 0xf5, 0xc1, 0x62, 0x3b, 0x54, 0x3d,
                              0x29, 0xe3, 0xed, 0x78, 0x00, 0xfb, 0x7f};
static uint8_t const init_vector[] = {0xB0, 0x0D, 0xB2, 0x31,
                                      0xc6, 0x7c, 0x82, 0x12};

/*
 * plaintext = "multiple of segment size bits in length"
 * encrypting 39 plain text bytes with a segment size of 24 bits
 * should generate 42 bytes
 */
static uint8_t const plaintext[] = {
    0x6d, 0x75, 0x6c, 0x74, 0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f,
    0x66, 0x20, 0x73, 0x65, 0x67, 0x6d, 0x65, 0x6e, 0x74, 0x20,
    0x73, 0x69, 0x7a, 0x65, 0x20, 0x62, 0x69, 0x74, 0x73, 0x20,
    0x69, 0x6e, 0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68};
static uint8_t const ciphertext[] = {
    0xd3, 0xc5, 0x3c, 0x44, 0xa3, 0x84, 0x17, 0x74, 0x8e, 0xb4, 0x21,
    0xd3, 0x78, 0x0f, 0xb2, 0x8e, 0x0e, 0xaf, 0x9a, 0xbc, 0x91, 0x7a,
    0x55, 0x73, 0x4d, 0x78, 0x65, 0x25, 0x91, 0x51, 0x74, 0xa8, 0x83,
    0x59, 0x63, 0x1d, 0x47, 0x95, 0x82, 0xa8, 0xad, 0x8c};

/*
 * plaintext = "longer string with an odd byte length"
 * encrypting 37 plain text bytes with a segment size of 24 bytes
 * should generate 39 bytes
 */
static uint8_t const pkcs_plaintext[] = {
    0x6c, 0x6f, 0x6e, 0x67, 0x65, 0x72, 0x20, 0x73, 0x74, 0x72,
    0x69, 0x6e, 0x67, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x61,
    0x6e, 0x20, 0x6f, 0x64, 0x64, 0x20, 0x62, 0x79, 0x74, 0x65,
    0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68};
static uint8_t const pkcs_ciphertext[] = {
    0xd2, 0xdf, 0x3e, 0x72, 0xd3, 0x5b, 0x63, 0x33, 0xef, 0x80,
    0x00, 0x29, 0x2d, 0xb2, 0xca, 0x4f, 0xbe, 0x8d, 0xa9, 0xfa,
    0xbc, 0xa2, 0x88, 0x5e, 0xe4, 0x32, 0x3b, 0x4d, 0xee, 0x8c,
    0xf8, 0x79, 0x1b, 0x55, 0xea, 0x34, 0x03, 0xfd, 0xb9,
};

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
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), &init_vector[0],
                              sizeof(init_vector), MODE_CFB, segment_size,
                              &on_error, HERE),
                "blowfish_init failed unexpectedly for CFB");

    assert_encrypted_value(&state, NULL, 0, NULL, 0, HERE);
    assert_encrypted_value(&state, &plaintext[0], sizeof(plaintext),
                           &ciphertext[0], sizeof(ciphertext), HERE);
    assert_encrypted_value(&state, &pkcs_plaintext[0], sizeof(pkcs_plaintext),
                           &pkcs_ciphertext[0], sizeof(pkcs_ciphertext), HERE);

    state.pkcs7padding = false;
    assert_encryption_fails(&state, &plaintext[0], sizeof(plaintext) - 1, HERE);
}

static void
test_cfb_decryption()
{
    blowfish_state state;

    assert_true(blowfish_init(&state, &key[0], sizeof(key), &init_vector[0],
                              sizeof(init_vector), MODE_CFB, segment_size,
                              &on_error, HERE),
                "blowfish_init failed unexpectedly for CFB");

    assert_decrypted_value(&state, NULL, 0, NULL, 0, HERE);
    assert_decrypted_value(&state, &ciphertext[0], sizeof(ciphertext),
                           &plaintext[0], sizeof(plaintext), HERE);
    assert_decrypted_value(&state, &pkcs_ciphertext[0], sizeof(pkcs_ciphertext),
                           &pkcs_plaintext[0], sizeof(pkcs_plaintext), HERE);

    state.pkcs7padding = false;
    assert_decryption_fails(&state, &ciphertext[0], 13, HERE);
}

int
main(__attribute__((unused)) int argc, __attribute__((unused)) char *argv[])
{
    test_cfb_parameter_checking();
    test_cfb_encryption();
    test_cfb_decryption();
    return error_counter;
}
