#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blowfish.h"
#include "cli-lib.h"

int
main(int argc, char *argv[])
{
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s MODE KEY [IV]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    size_t key_len, iv_len;
    blowfish_mode mode = get_mode_or_fail(argv[1]);
    uint8_t *key = from_hex_or_fail(argv[2], &key_len);
    uint8_t *iv = from_hex_or_fail(argv[3], &iv_len);
    blowfish_state *state = blowfish_new(key, key_len, iv, iv_len, mode, 0,
                                         &report_error, stderr);
    char plaintext[512];
    if (state != NULL) {
        printf("Plain text: ");
        fflush(stdout);
        while (fgets(&plaintext[0], sizeof(plaintext), stdin)) {
            size_t cipher_len;
            char *eos = &plaintext[strlen(plaintext) - 1];
            *eos = '\0';

            uint8_t *ciphertext = blowfish_encrypt(state, (uint8_t*)&plaintext,
                                                   eos - &plaintext[0], &cipher_len,
                                                   &report_error, stderr);
            if (ciphertext) {
                hexdump(stdout, ciphertext, cipher_len);
                free(ciphertext);
            }

            printf("Plain text: ");
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
