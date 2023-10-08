#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "test-lib.h"

uint8_t const EIGHT_BYTES[] = {0, 1, 2, 3, 4, 5, 6, 7};
uint8_t const SIXTY_FOUR_BYTES[] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
};
int error_counter = 0;

void
on_error(void *context, char const *fmt, ...)
{
    va_list ap;
    struct error_context *loc = context;

    fprintf(stderr, "ERROR: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, " (%s:%d)\n", loc->file, loc->line_no);

    ++error_counter;
}

void
assert_condition(bool condition, char const *msg, char const *file, int line_no)
{
    if (!condition) {
        on_error(&(struct error_context){file, line_no}, "%s", msg);
        exit(EXIT_FAILURE);
    }
}

void
assert_bytes_equal(uint8_t const *actual, uint8_t const *expected, size_t len,
                   char const *msg, char const *file, int line_no)
{
    int mismatches = 0;
    for (size_t offset = 0; offset < len; ++offset) {
        if (actual[offset] != expected[offset]) {
            ++mismatches;
            fprintf(stderr, "%04zx: %02x != %02x\n", offset, actual[offset],
                    expected[offset]);
        }
    }
    if (mismatches) {
        on_error(&(struct error_context){file, line_no}, "%s", msg);
        exit(EXIT_FAILURE);
    }
}

void
assert_encrypted_value(blowfish_state *state, uint8_t const *plaintext,
                       size_t plain_len, uint8_t const *ciphertext,
                       size_t cipher_len, struct error_context *context)
{
    uint8_t *actual;
    size_t actual_len;

    blowfish_reset(state);
    actual = blowfish_encrypt(state, plaintext, plain_len, &actual_len,
                              &on_error, context);
    if (ciphertext == NULL) {
        assert_condition(actual == NULL,
                         "encrypting zero length message returns NULL",
                         context->file, context->line_no);
        assert_condition(actual_len == 0,
                         "encrypting zero length messages produces zero bytes",
                         context->file, context->line_no);
    } else {
        assert_condition(actual != NULL, "encryption failed unexpectedly",
                         context->file, context->line_no);
        assert_condition(actual_len == cipher_len,
                         "encrypt produced the wrong number of bytes",
                         context->file, context->line_no);
        assert_bytes_equal(actual, ciphertext, cipher_len,
                           "encryption produced unexpected result",
                           context->file, context->line_no);
        free(actual);
    }
}

void
assert_encryption_fails(blowfish_state *state, uint8_t const *plaintext,
                        size_t plain_len, struct error_context *context)
{
    uint8_t *actual;
    size_t actual_len;

    blowfish_reset(state);
    actual =
        blowfish_encrypt(state, plaintext, plain_len, &actual_len, NULL, NULL);
    assert_condition(actual == NULL, "encryption should have failed",
                     context->file, context->line_no);
    assert_condition(actual_len == 0, "encryption should have failed",
                     context->file, context->line_no);
}

void
assert_decrypted_value(blowfish_state *state, uint8_t const *ciphertext,
                       size_t cipher_len, uint8_t const *plaintext,
                       size_t plain_len, struct error_context *context)
{
    uint8_t *actual;
    size_t actual_len;

    blowfish_reset(state);
    actual = blowfish_decrypt(state, ciphertext, cipher_len, &actual_len,
                              &on_error, context);
    if (plaintext == NULL) {
        assert_condition(actual == NULL,
                         "decrypting zero length message returns NULL",
                         context->file, context->line_no);
        assert_condition(actual_len == 0,
                         "decrypting zero length messages produces zero bytes",
                         context->file, context->line_no);
    } else {
        assert_condition(actual != NULL, "decryption failed unexpectedly",
                         context->file, context->line_no);
        assert_condition(actual_len == plain_len,
                         "decrypt produced the wrong number of bytes",
                         context->file, context->line_no);
        assert_bytes_equal(actual, plaintext, plain_len,
                           "decryption produced unexpected result",
                           context->file, context->line_no);
        free(actual);
    }
}

void
assert_decryption_fails(blowfish_state *state, uint8_t const *ciphertext,
                        size_t cipher_len, struct error_context *context)
{
    uint8_t *actual;
    size_t actual_len;

    blowfish_reset(state);
    actual = blowfish_decrypt(state, ciphertext, cipher_len, &actual_len, NULL,
                              NULL);
    assert_condition(actual == NULL, "decryption should have failed",
                     context->file, context->line_no);
    assert_condition(actual_len == 0, "decryption should have failed",
                     context->file, context->line_no);
}
