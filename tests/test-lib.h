#ifndef BLOWFISH_TEST_LIB_H
#define BLOWFISH_TEST_LIB_H

#include <stdbool.h>
#include <stdint.h>

#include "blowfish.h"

extern int error_counter;

extern uint8_t const EIGHT_BYTES[8];
extern uint8_t const SIXTY_FOUR_BYTES[64];

struct error_context {
    char const *file;
    int line_no;
};
#define HERE (&(struct error_context){__FILE__, __LINE__})
extern void on_error(void *, char const *, ...);

extern void assert_condition(bool, char const *, char const *, int);
#define assert_true(c, m) assert_condition((c), m, __FILE__, __LINE__)
#define assert_false(c, m) assert_condition(!(c), m, __FILE__, __LINE__)

extern void assert_bytes_equal(uint8_t const *actual, uint8_t const *expected,
                               size_t, char const *, char const *, int);
extern void assert_encrypted_value(blowfish_state *state,
                                   uint8_t const *plaintext, size_t plain_len,
                                   uint8_t const *ciphertext, size_t cipher_len,
                                   struct error_context *context);
extern void assert_encryption_fails(blowfish_state *state,
                                    uint8_t const *plaintext, size_t plain_len,
                                    struct error_context *context);
extern void assert_decrypted_value(blowfish_state *state,
                                   uint8_t const *ciphertext, size_t cipher_len,
                                   uint8_t const *plaintext, size_t plain_len,
                                   struct error_context *context);
extern void assert_decryption_fails(blowfish_state *state,
                                    uint8_t const *ciphertext,
                                    size_t cipher_len,
                                    struct error_context *context);

#endif /*!BLOWFISH_TEST_LIB_H*/
