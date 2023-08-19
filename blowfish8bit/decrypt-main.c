#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blowfish.h"
#include "cli-lib.h"

int
main(int argc, char *argv[])
{
    uint8_t *key, *iv;
    size_t key_len, iv_len;

    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s MODE KEY [IV]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    blowfish_mode mode = get_mode_or_fail(argv[1]);
    key = from_hex_or_fail(argv[2], &key_len);
    iv = from_hex_or_fail(argv[3], &iv_len);

    blowfish_state *state = blowfish_new(key, key_len, iv, iv_len, mode, 0, &report_error, stderr);
    if (state != NULL) {
        printf("Hex Ciphertext: ");
        fflush(stdout);
        while (true) {
            size_t cipher_len;
            uint8_t *ciphertext = read_hex_string(&cipher_len);
            if (!ciphertext) {
                break;
            }

            size_t plain_len;
            uint8_t *plaintext = blowfish_decrypt(state, ciphertext, cipher_len, &plain_len, &report_error, stderr);
            if (plaintext) {
                hexdump(stdout, plaintext, plain_len);
                free(plaintext);
            }
            free(ciphertext);

            printf("Hex Ciphertext: ");
            fflush(stdout);
            blowfish_reset(state);
        }
        blowfish_free(state);
    }
    free(key);
    if (iv) {
        free(iv);
    }

    return 0;
}