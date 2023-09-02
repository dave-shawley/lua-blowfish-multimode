#include <stdint.h>
#include <string.h>

#include "blowfish.h"
#include "test-lib.h"

static void
create_and_destroy_context()
{
    uint8_t const key[] = "1234567";
    blowfish_state *s = blowfish_new(&key[0], sizeof(key), &key[0], sizeof(key),
                                     MODE_CBC, 0, &on_error, HERE);
    assert_true(s != NULL, "blowfish_new failed unexpectedly");
    blowfish_free(s);
}

static void
test_basic_parameter_checking()
{
    blowfish_state state;

    assert_false(blowfish_init(&state, NULL, 0, &EIGHT_BYTES[0],
                               sizeof(EIGHT_BYTES), MODE_CBC, 0, NULL, NULL),
                 "blowfish requires a key");
    for (size_t i = 0; i < 64; ++i) {
        if (i < 4 || i > 56) {
            assert_false(blowfish_init(&state, &SIXTY_FOUR_BYTES[0], i,
                                       &EIGHT_BYTES[0], sizeof(EIGHT_BYTES),
                                       MODE_CBC, 0, NULL, NULL),
                         "blowfish requires a key between 4 and 56 bytes");
        } else {
            assert_true(blowfish_init(&state, &SIXTY_FOUR_BYTES[0], i,
                                      &EIGHT_BYTES[0], sizeof(EIGHT_BYTES),
                                      MODE_CBC, 0, NULL, NULL),
                        "blowfish accepts keys between 4 and 56 bytes");
        }
    }
}

static void
test_context_reset()
{
    blowfish_state state;

    assert_true(blowfish_init(&state, &EIGHT_BYTES[0], sizeof(EIGHT_BYTES),
                              &EIGHT_BYTES[0], sizeof(EIGHT_BYTES), MODE_CBC, 0,
                              &on_error, HERE),
                "unexpected blowfish_init failure");
    assert_true(memcmp(&state.iv, &state.initial_iv, sizeof(state.iv)) == 0,
                "initial IV should be saved on creation");
    for (size_t i = 0; i < sizeof(state.iv); ++i) {
        state.iv[i] ^= 0xFF;
    }
    blowfish_reset(&state);
    assert_true(memcmp(&state.iv, &state.initial_iv, sizeof(state.iv)) == 0,
                "IV should be restored on reset");
}

int
main(__attribute__((unused)) int argc, __attribute__((unused)) char *argv[])
{
    blowfish_free(NULL); /* this is legal */

    create_and_destroy_context();
    test_basic_parameter_checking();
    test_context_reset();

    return error_counter;
}
