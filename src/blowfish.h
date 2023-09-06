#ifndef BLOWFISH_8BIT_BLOWFISH_H
#define BLOWFISH_8BIT_BLOWFISH_H

#include <stdbool.h>
#include <stdint.h>

#define BLOWFISH_BLOCK_SIZE 8

typedef enum {
    MODE_CBC, /* implemented */
    MODE_CFB, /* implemented */
    MODE_CTR,
    MODE_ECB, /* implemented */
    MODE_OFB, /* implemented */
} blowfish_mode;

typedef struct {
    blowfish_mode mode;
    unsigned int segment_size;
    unsigned int count;
    uint8_t iv[BLOWFISH_BLOCK_SIZE];
    uint8_t old_cipher[BLOWFISH_BLOCK_SIZE];
    uint8_t initial_iv[BLOWFISH_BLOCK_SIZE];
    uint32_t P[18];
    uint32_t S1[256];
    uint32_t S2[256];
    uint32_t S3[256];
    uint32_t S4[256];
} blowfish_state;

typedef void (*error_function)(void *, char const *, ...);

extern blowfish_state *blowfish_new(uint8_t const *key, size_t key_len,
                                    uint8_t const *iv, size_t iv_len,
                                    blowfish_mode mode, int segment_size,
                                    error_function on_error, void *err_context);
extern void blowfish_free(blowfish_state *self);

extern bool blowfish_init(blowfish_state *self, uint8_t const *key,
                          size_t key_len, uint8_t const *iv, size_t iv_len,
                          blowfish_mode mode, int segment_size,
                          error_function on_error, void *err_context);
extern void blowfish_reset(blowfish_state *self);

extern uint8_t *blowfish_encrypt(blowfish_state *self, uint8_t const *msg,
                                 size_t msg_len, size_t *out_len,
                                 error_function on_error, void *err_context);
extern uint8_t *blowfish_decrypt(blowfish_state *self, uint8_t const *msg,
                                 size_t msg_len, size_t *out_len,
                                 error_function on_error, void *err_context);

#endif /* !BLOWFISH_8BIT_BLOWFISH_H */
