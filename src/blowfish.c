/*
 * Based on pycrypto implementation of blowfish algorithm with support
 * for multiple modes.
 */
/*
 *  Blowfish.c : Blowfish implementation
 *
 * Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
 *
 * =======================================================================
 * The contents of this file are dedicated to the public domain.  To the extent
 * that dedication to the public domain is not available, everyone is granted a
 * worldwide, perpetual, royalty-free, non-exclusive license to exercise all
 * rights associated with the contents of this file for any purpose whatsoever.
 * No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =======================================================================
 *
 * Country of origin: Canada
 *
 * The Blowfish algorithm is documented at
 * http://www.schneier.com/paper-blowfish-fse.html
 */
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "blowfish-tables.h"
#include "blowfish.h"

#define F(a, b, c, d) ((((a) + (b)) ^ (c)) + (d))
#define SWAP(a, b)                                                             \
    do {                                                                       \
        uint32_t tmp = a;                                                      \
        a = b;                                                                 \
        b = tmp;                                                               \
    } while (0)
#define NUM_ELEMENTS(ary) (sizeof(ary) / sizeof(ary[0]))

char const *MODE_STRING[] = {
    "CBC", "CFB", "CTR", "ECB", "OFB",
};

static void
default_error_func(void *context, char const *fmt, ...)
{
    (void)context;
    (void)fmt;
}

static inline uint32_t
bytes_to_word(uint8_t const *in)
{
    return (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
}

static inline void
word_to_bytes(uint32_t word, uint8_t *out)
{
    *out++ = (word >> 24) & 0xFF;
    *out++ = (word >> 16) & 0xFF;
    *out++ = (word >> 8) & 0xFF;
    *out++ = word & 0xFF;
}

static inline void
inline_encrypt(blowfish_state *self, uint32_t *pxL, uint32_t *pxR)
{
    uint32_t xL = *pxL;
    uint32_t xR = *pxR;

    for (int i = 0; i < 16; ++i) {
        xL ^= self->P[i];
        xR ^= F(self->S1[(xL >> 24) & 0xFF], self->S2[(xL >> 16) & 0xFF],
                self->S3[(xL >> 8) & 0xFF], self->S4[xL & 0xFF]);
        SWAP(xL, xR);
    }
    SWAP(xL, xR);
    xR ^= self->P[16];
    xL ^= self->P[17];
    *pxL = xL;
    *pxR = xR;
}

static inline void
inline_decrypt(blowfish_state *self, uint32_t *pxL, uint32_t *pxR)
{
    uint32_t xL = *pxL;
    uint32_t xR = *pxR;

    xL ^= self->P[17];
    xR ^= self->P[16];
    SWAP(xL, xR);

    for (int i = 15; i >= 0; --i) {
        SWAP(xL, xR);
        xR ^= F(self->S1[(xL >> 24) & 0xFF], self->S2[(xL >> 16) & 0xFF],
                self->S3[(xL >> 8) & 0xFF], self->S4[xL & 0xFF]);
        xL ^= self->P[i];
    }
    *pxL = xL;
    *pxR = xR;
}

static void
block_encrypt(blowfish_state *self, uint8_t const *in, uint8_t *out)
{
    uint32_t xL = bytes_to_word(in);
    uint32_t xR = bytes_to_word(in + 4);
    inline_encrypt(self, &xL, &xR);
    word_to_bytes(xL, out);
    word_to_bytes(xR, out + 4);
}

static void
block_decrypt(blowfish_state *self, uint8_t const *in, uint8_t *out)
{
    uint32_t xL = bytes_to_word(in);
    uint32_t xR = bytes_to_word(in + 4);
    inline_decrypt(self, &xL, &xR);
    word_to_bytes(xL, out);
    word_to_bytes(xR, out + 4);
}

/*
 * Verify and remove PKCS#7 padding from a plaintext blob.
 *
 * @param self - blowfish decryption state
 * @param plaintext - pointer to the decrypted plaintext buffer, unchanged
 *                    if padding is correct; DEALLOCATED and set to NULL
 *                    when padding is not correct
 * @param plaintext_len - the length of the padded buffer on input,
 *                        the unpadded length upon return
 * @param on_error - function to call to report an error
 * @param error_context - error context to pass along
 */
static void
unpad(blowfish_state const *self, uint8_t **plaintext, size_t *plaintext_len,
      error_function on_error, void *error_context)
{
    if (self->pkcs7padding) {
        uint8_t *cipher = *plaintext;
        size_t cipher_len = *plaintext_len;
        uint8_t padding_length = cipher[cipher_len - 1];
        if (padding_length >= cipher_len) {
            free(cipher);
            *plaintext = NULL;
            *plaintext_len = 0;
            on_error(error_context, "Invalid PKCS padding value %02x",
                     padding_length);
        } else {
            *plaintext_len -= padding_length;
            for (uint8_t *byte_ptr = &cipher[cipher_len - padding_length],
                         *end_ptr = &cipher[cipher_len - 1];
                 byte_ptr != end_ptr; ++byte_ptr)
            {
                if (*byte_ptr != padding_length) {
                    uint8_t wrong_byte = *byte_ptr;
                    size_t offset = byte_ptr - cipher;
                    free(cipher);
                    *plaintext = NULL;
                    *plaintext_len = 0;
                    on_error(error_context,
                             "Invalid PKCS padding value at offset %u, "
                             "expected %02x, found %02x",
                             offset, padding_length, wrong_byte);
                    break;
                }
            }
        }
    }
}

static bool
verify_params(uint8_t const *key, size_t key_len, uint8_t const *iv,
              size_t iv_len, blowfish_mode mode, int *segment_size,
              error_function err, void *err_context)
{
    if (!key_len || !key) {
        err(err_context, "key must be specified");
        return false;
    }
    if (key_len < 4 || key_len > 56) {
        err(err_context, "key length must be between 4 and 56 bytes");
        return false;
    }

    switch (mode) {
    case MODE_CBC:
        if (iv == NULL || iv_len != BLOWFISH_BLOCK_SIZE) {
            err(err_context,
                "initialization vector required to be %d bytes in "
                "length, "
                "parameter is %d bytes",
                BLOWFISH_BLOCK_SIZE, iv_len);
            return false;
        }
        break;
    case MODE_CFB:
        if (iv == NULL || iv_len != BLOWFISH_BLOCK_SIZE) {
            err(err_context,
                "initialization vector required to be %d bytes in "
                "length, "
                "parameter is %d bytes",
                BLOWFISH_BLOCK_SIZE, iv_len);
            return false;
        }
        if (*segment_size == 0) {
            *segment_size = 8;
        }
        if (*segment_size < 1 || *segment_size > (BLOWFISH_BLOCK_SIZE * 8)
            || (*segment_size & 7))
        {
            err(err_context,
                "segment size must be a multiple of 8 bits between "
                "1 and %d",
                BLOWFISH_BLOCK_SIZE * 8);
            return false;
        }
        break;
    case MODE_CTR: /* supporting counter mode is going to take some work */
        err(err_context, "CTR mode is not implemented");
        return false;
    case MODE_ECB:
        if (iv != NULL || iv_len != 0) {
            err(err_context, "ECB does not use an initialization vector");
            return false;
        }
        break;
    case MODE_OFB:
        if (iv == NULL || iv_len != BLOWFISH_BLOCK_SIZE) {
            err(err_context,
                "initialization vector required to be %d bytes in "
                "length, "
                "parameter is %d bytes",
                BLOWFISH_BLOCK_SIZE, iv_len);
            return false;
        }
        break;
    default:
        err(err_context, "mode %d is not implemented", mode);
        return false;
    }

    return true;
}

blowfish_state *
blowfish_new(uint8_t const *key, size_t key_len, uint8_t const *iv,
             size_t iv_len, blowfish_mode mode, int segment_size,
             error_function on_error, void *error_context)
{
    blowfish_state *self;

    if (on_error == NULL) {
        on_error = &default_error_func;
    }
    self = (blowfish_state *)malloc(sizeof(*self));
    if (self != NULL) {
        if (!blowfish_init(self, key, key_len, iv, iv_len, mode, segment_size,
                           on_error, error_context))
        {
            free(self);
            self = NULL;
        }
    }

    return self;
}

void
blowfish_free(blowfish_state *self)
{
    if (self != NULL) {
        free(self);
    }
}

bool
blowfish_init(blowfish_state *self, uint8_t const *key, size_t key_len,
              uint8_t const *iv, size_t iv_len, blowfish_mode mode,
              int segment_size, error_function on_error, void *error_context)
{
    uint32_t word = 0;
    uint32_t xL, xR;

    if (on_error == NULL) {
        on_error = &default_error_func;
    }
    if (!verify_params(key, key_len, iv, iv_len, mode, &segment_size, on_error,
                       error_context))
    {
        return false;
    }

    self->mode = mode;
    self->pkcs7padding = true;
    self->segment_size = segment_size;
    self->count = BLOWFISH_BLOCK_SIZE;
    if (iv) {
        memcpy(&self->iv[0], iv, sizeof(self->iv));
        memcpy(&self->initial_iv[0], iv, sizeof(self->initial_iv));
    }
    memset(&self->old_cipher, 0, BLOWFISH_BLOCK_SIZE);

    for (int i = 0; i < (18 * 4); ++i) {
        word = (word << 8) | key[i % key_len];
        if ((i & 3) == 3) {
            self->P[i >> 2] = initial_P[i >> 2] ^ word;
            word = 0;
        }
    }

    memcpy(&self->S1[0], initial_S1, 256 * sizeof(uint32_t));
    memcpy(&self->S2[0], initial_S2, 256 * sizeof(uint32_t));
    memcpy(&self->S3[0], initial_S3, 256 * sizeof(uint32_t));
    memcpy(&self->S4[0], initial_S4, 256 * sizeof(uint32_t));

    xL = xR = 0;
#define initialize(ary)                                                        \
    do {                                                                       \
        for (size_t i = 0; i < NUM_ELEMENTS(ary); i += 2) {                    \
            inline_encrypt(self, &xL, &xR);                                    \
            ary[i] = xL;                                                       \
            ary[i + 1] = xR;                                                   \
        }                                                                      \
    } while (0)

    initialize(self->P);
    initialize(self->S1);
    initialize(self->S2);
    initialize(self->S3);
    initialize(self->S4);

    return true;
}

void
blowfish_reset(blowfish_state *self)
{
    memcpy(&self->iv, &self->initial_iv, sizeof(self->iv));
    self->count = BLOWFISH_BLOCK_SIZE;
}

uint8_t *
blowfish_encrypt(blowfish_state *self, uint8_t const *msg, size_t msg_len,
                 size_t *out_len, error_function on_error, void *error_context)
{
    uint8_t temp[BLOWFISH_BLOCK_SIZE];
    size_t i, j;
    uint8_t *out_buf;
    uint8_t padding_byte = 0; /* no padding */

    if (on_error == NULL) {
        on_error = &default_error_func;
    }

    *out_len = 0;
    if (msg_len == 0) {
        return NULL;
    }

    if (self->pkcs7padding) {
        if (self->mode == MODE_CBC) {
            padding_byte =
                BLOWFISH_BLOCK_SIZE - (msg_len % BLOWFISH_BLOCK_SIZE);
        }
    } else {
        if ((self->mode == MODE_CBC || self->mode == MODE_ECB)
            && (msg_len % BLOWFISH_BLOCK_SIZE))
        {
            on_error(error_context,
                     "%s mode requires input multiple of %d bytes",
                     MODE_STRING[self->mode], BLOWFISH_BLOCK_SIZE);
            return NULL;
        }
        if (self->mode == MODE_CFB && (msg_len % (self->segment_size / 8))) {
            on_error(error_context,
                     "CFB mode requires input strings multiple of %d bytes",
                     self->segment_size / 8);
            return NULL;
        }
    }

    out_buf = (uint8_t *)malloc(msg_len + padding_byte);
    if (out_buf == NULL) {
        on_error(error_context, "failed to allocate buffer of %d bytes",
                 msg_len + padding_byte);
        return NULL;
    }
    *out_len = msg_len + padding_byte;

    switch (self->mode) {
    case MODE_CBC:
        for (i = 0; i < msg_len + padding_byte; i += BLOWFISH_BLOCK_SIZE) {
            for (j = 0; j < BLOWFISH_BLOCK_SIZE; ++j) {
                uint8_t byte = (i + j) < msg_len ? msg[i + j] : padding_byte;
                temp[j] = byte ^ self->iv[j];
            }
            block_encrypt(self, temp, out_buf + i);
            memcpy(self->iv, out_buf + i, BLOWFISH_BLOCK_SIZE);
        }
        break;
    case MODE_CFB:
        for (i = 0; i < msg_len; i += self->segment_size / 8) {
            block_encrypt(self, self->iv, temp);
            for (j = 0; j < self->segment_size / 8; j++) {
                out_buf[i + j] = msg[i + j] ^ temp[j];
            }
            if (self->segment_size == (BLOWFISH_BLOCK_SIZE * 8)) {
                memcpy(self->iv, out_buf + i, BLOWFISH_BLOCK_SIZE);
            } else if ((self->segment_size % 8) == 0) {
                size_t sz = self->segment_size / 8;
                memmove(self->iv, self->iv + sz, BLOWFISH_BLOCK_SIZE - sz);
                memcpy(self->iv + BLOWFISH_BLOCK_SIZE - sz, out_buf + i, sz);
            } else {
                /* should not happen! */
            }
        }
        break;
    case MODE_ECB:
        for (i = 0; i < msg_len; i += BLOWFISH_BLOCK_SIZE) {
            block_encrypt(self, msg + i, out_buf + i);
        }
        break;
    case MODE_OFB:
        i = 0;
        while (i < msg_len) {
            if ((msg_len - i) <= (BLOWFISH_BLOCK_SIZE - self->count)) {
                for (j = 0; j < (msg_len - i); ++j) {
                    out_buf[i + j] = self->iv[self->count + j] ^ msg[i + j];
                }
                self->count += msg_len - i;
                i = msg_len;
                continue;
            }

            for (j = 0; j < BLOWFISH_BLOCK_SIZE - self->count; ++j) {
                out_buf[i + j] = self->iv[self->count + j] ^ msg[i + j];
            }
            i += BLOWFISH_BLOCK_SIZE - self->count;
            self->count = BLOWFISH_BLOCK_SIZE;

            block_encrypt(self, self->iv, temp);
            memcpy(self->iv, temp, BLOWFISH_BLOCK_SIZE);
            self->count = 0;
        }
        break;
    case MODE_CTR:
    default:
        on_error(error_context, "mode %d is not implemented", self->mode);
        free(out_buf);
        *out_len = 0;
        return NULL;
    }
    return out_buf;
}

uint8_t *
blowfish_decrypt(blowfish_state *self, uint8_t const *msg, size_t msg_len,
                 size_t *out_len, error_function on_error, void *error_context)
{
    uint8_t *out_buf = NULL;
    size_t i, j;
    uint8_t temp[BLOWFISH_BLOCK_SIZE];

    if (on_error == NULL) {
        on_error = &default_error_func;
    }

    *out_len = 0;
    if (msg_len == 0) {
        return NULL;
    }

    if (self->mode == MODE_CTR || self->mode == MODE_OFB) {
        /* these are symmetric so reuse the encryption bits */
        return blowfish_encrypt(self, msg, msg_len, out_len, on_error,
                                error_context);
    }

    if (!self->pkcs7padding) {
        if ((self->mode == MODE_CBC || self->mode == MODE_ECB)
            && (msg_len % BLOWFISH_BLOCK_SIZE))
        {
            on_error(error_context,
                     "Ciphertext must be a multiple of block size");
            return NULL;
        }

        if (self->mode == MODE_CFB && (msg_len % (self->segment_size / 8))) {
            on_error(error_context,
                     "Ciphertext must be a multiple of segment "
                     "size %d in length",
                     (self->segment_size / 8));
            return NULL;
        }
    }

    if (!(out_buf = (uint8_t *)malloc(msg_len))) {
        return NULL;
    }
    *out_len = msg_len;

    switch (self->mode) {
    case MODE_CBC:
        for (i = 0; i < msg_len; i += BLOWFISH_BLOCK_SIZE) {
            memcpy(self->old_cipher, self->iv, BLOWFISH_BLOCK_SIZE);
            block_decrypt(self, msg + i, &temp[0]);
            for (j = 0; j < BLOWFISH_BLOCK_SIZE; ++j) {
                out_buf[i + j] = temp[j] ^ self->iv[j];
                self->iv[j] = msg[i + j];
            }
        }
        unpad(self, &out_buf, out_len, on_error, error_context);
        break;

    case MODE_CFB:
        for (i = 0; i < msg_len; i += (self->segment_size / 8)) {
            block_encrypt(self, &self->iv[0], &temp[0]);
            for (j = 0; j < self->segment_size / 8; ++j) {
                out_buf[i + j] = msg[i + j] ^ temp[j];
            }
            if (self->segment_size == (BLOWFISH_BLOCK_SIZE * 8)) {
                memcpy(&self->iv[0], &msg[i], BLOWFISH_BLOCK_SIZE);
            } else if ((self->segment_size % 8) == 0) {
                size_t sz = self->segment_size / 8;
                memmove(self->iv, &self->iv[sz], BLOWFISH_BLOCK_SIZE - sz);
                memcpy(&self->iv[BLOWFISH_BLOCK_SIZE - sz], &msg[i], sz);
            } else {
                /* cannot happen?! */
            }
        }
        break;
    case MODE_ECB:
        for (i = 0; i < msg_len; i += BLOWFISH_BLOCK_SIZE) {
            block_decrypt(self, &msg[i], &out_buf[i]);
        }
        break;
    case MODE_CTR:
    case MODE_OFB:
        /* handled above */
        break;
    default:
        on_error(error_context, "Unimplemented mode");
        free(out_buf);
        out_buf = NULL;
        *out_len = 0;
        break;
    }

    return out_buf;
}
