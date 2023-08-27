#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blowfish.h"
#include "cli-lib.h"

static char const *MODES[] = {"CBC", "CFB", "CTR", "ECB", "OFB"};
static size_t NUM_MODES = sizeof(MODES) / sizeof(MODES[0]);

static bool translate_hex(char const *hex_str, uint8_t *out, size_t out_len,
                          char const **end_ptr);

blowfish_mode
get_mode_or_fail(char const *mode_string)
{
    for (int i = 0; i < NUM_MODES; ++i) {
        if (strcmp(mode_string, MODES[i]) == 0) {
            return i;
        }
    }
    fprintf(stderr, "Invalid mode '%s'\n", mode_string);
    fprintf(stderr, "Valid modes are: ");
    for (int i = 0; i < NUM_MODES; ++i) {
        fprintf(stderr, "%s%s", MODES[i], (i + 1 == NUM_MODES ? "\n" : ", "));
    }
    exit(EXIT_FAILURE);
}

void
report_error(void *destination, char const *fmt, ...)
{
    FILE *fp = (FILE *)destination;
    va_list ap;

    fprintf(fp, "ERROR: ");
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fprintf(fp, "\n");
}

void
hexdump(FILE *fp, uint8_t const *buf, size_t buf_len)
{
    fprintf(fp, "\n");
    print_hex(fp, buf, buf_len);
    for (size_t offset = 0; offset < buf_len; offset += 16) {
        fprintf(fp, "| %08zx |", offset);
        for (size_t i = offset; i < offset + 16; ++i) {
            if (i < buf_len) {
                fprintf(fp, " %02x", buf[i]);
            } else {
                fprintf(fp, "   ");
            }
            if ((i + 1) % 8 == 0) {
                fprintf(fp, " ");
            }
        }
        fprintf(fp, "| ");
        for (size_t i = offset; i < offset + 16; ++i) {
            if (i >= buf_len) {
                fprintf(fp, " ");
            } else if (isalnum(buf[i]) || ispunct(buf[i])) {
                fprintf(fp, "%c", buf[i]);
            } else {
                fprintf(fp, ".");
            }
        }
        fprintf(fp, " |\n");
    }
    fprintf(fp, "\n");
}

void
print_hex(FILE *fp, uint8_t const *buf, size_t buf_len)
{
    while (buf_len--) {
        fprintf(fp, "%02x", *buf++);
    }
    fprintf(fp, "\n");
}

uint8_t *
read_hex_string(size_t *buf_len)
{
    bool done = false;
    uint8_t *out_buf = NULL;
    size_t out_buf_sz = 0;
    char hex_buf[256];
    uint8_t tmp_buf[128];

    *buf_len = 0;
    while (!done && fgets(&hex_buf[0], sizeof(hex_buf), stdin)) {
        if (hex_buf[0] == '\n') {
            break;
        }

        size_t l = strlen(hex_buf) - 1;
        if (hex_buf[l] == '\n') {
            hex_buf[l] = '\0';
            done = true;
        }

        if (translate_hex(&hex_buf[0], &tmp_buf[0], sizeof(tmp_buf), NULL)) {
            size_t new_len = out_buf_sz + (l / 2);
            uint8_t *new_buf = (uint8_t *)realloc(out_buf, new_len);
            if (new_buf) {
                memcpy(&new_buf[out_buf_sz], &tmp_buf[0], l);
                out_buf = new_buf;
                out_buf_sz = new_len;
                continue;
            }
        } else {
            fprintf(stderr, "ERROR: failed to parse hex string '%s'\n",
                    hex_buf);
        }
        /* failed! */
        if (out_buf) {
            free(out_buf);
        }
        return NULL;
    }

    *buf_len = out_buf_sz;

    return out_buf;
}

uint8_t *
from_hex_or_fail(char const *hexed, size_t *num_bytes)
{
    *num_bytes = 0;
    if (hexed == NULL) {
        return NULL;
    }

    size_t input_len = strlen(hexed);

    if (input_len & 1 || *hexed == 0) {
        fprintf(stderr, "ERROR: invalid hex string of length %zu: %s\n",
                input_len, hexed);
        return NULL;
    }

    *num_bytes = input_len / 2;
    uint8_t *out_buf = malloc(*num_bytes);
    if (!out_buf) {
        fprintf(stderr, "ERROR: failed to allocate %zu bytes.\n", *num_bytes);
        exit(EXIT_FAILURE);
    }

    char const *end_ptr;
    if (!translate_hex(hexed, out_buf, *num_bytes, &end_ptr)) {
        fprintf(
            stderr,
            "ERROR: failed to parse '%s' as a hex string starting with '%c'\n",
            hexed, *end_ptr);
        free(out_buf);
        exit(EXIT_FAILURE);
    }

    return out_buf;
}

static bool
translate_hex(char const *hex_str, uint8_t *out, size_t out_len,
              char const **end_ptr)
{
    if (end_ptr) {
        *end_ptr = NULL;
    }

    while (*hex_str && out_len--) {
        *out = 0;
        for (int i = 0; i < 2; ++i) {
            uint8_t nybble;
            if (isdigit(*hex_str)) {
                nybble = *hex_str - '0';
            } else if (isxdigit(*hex_str)) {
                nybble = (tolower(*hex_str) - 'a') + 10;
            } else {
                if (end_ptr) {
                    *end_ptr = hex_str;
                }
                return false;
            }
            *out = (*out << 4) | nybble;
            hex_str++;
        }
        ++out;
    }
    return true;
}
