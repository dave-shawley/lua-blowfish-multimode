#ifndef BLOWFISH_8BIT_CLI_LIB_H
#define BLOWFISH_8BIT_CLI_LIB_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

extern blowfish_mode get_mode_or_fail(char const *mode_string);
extern uint8_t *from_hex_or_fail(char const *hexed, size_t *num_bytes);

extern void report_error(void *destination, char const *fmt, ...);
extern void hexdump(FILE *fp, uint8_t const *buf, size_t buf_len);
extern void print_hex(FILE *fp, uint8_t const *buf, size_t buf_len);
extern uint8_t *read_hex_string(size_t *buf_len);

#endif /*!BLOWFISH_8BIT_CLI_LIB_H*/
