#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <lauxlib.h>

#include "blowfish.h"

static const char TABLE_NAME[] = "Blowfish.state";
static inline blowfish_state *extract_state(lua_State *);
static void on_error(void *, char const *, ...);
static void return_error(void *, char const *, ...);

static int new_blowfish(lua_State *);
static int decrypt(lua_State *);
static int encrypt(lua_State *);
static int reset(lua_State *);
static int to_string(lua_State *);
static int enable_pkcs7_padding(lua_State *L);
static int disable_pkcs7_padding(lua_State *L);

static const struct luaL_Reg functions[] = {
    {"new", new_blowfish},
    {NULL, NULL},
};

static const struct luaL_Reg methods[] = {
    {"decrypt", decrypt},
    {"disable_pkcs7_padding", disable_pkcs7_padding},
    {"enable_pkcs7_padding", enable_pkcs7_padding},
    {"encrypt", encrypt},
    {"reset", reset},
    {"__tostring", to_string},
    {NULL, NULL},
};

static const struct {
    blowfish_mode mode;
    char const *label;
} labels[] = {
    {MODE_CBC, "CBC"}, {MODE_CFB, "CFB"}, {MODE_CTR, "CTR"},
    {MODE_ECB, "ECB"}, {MODE_OFB, "OFB"},
};

int
luaopen_blowfish(lua_State *L)
{
    luaL_newmetatable(L, TABLE_NAME);
    lua_pushstring(L, "__index");
    lua_pushvalue(L, -2);              /* metatable */
    lua_settable(L, -3);               /* metatable.__index = metatable */
    luaL_openlib(L, NULL, methods, 0); /* load methods into metatable */

    /* open the exported table, add the functions, then the enum constants */
    luaL_openlib(L, "blowfish", functions, 0);
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); ++i) {
        lua_pushstring(L, labels[i].label);
        lua_pushnumber(L, labels[i].mode);
        lua_settable(L, -3);
    }

    return 1;
}

static int
new_blowfish(lua_State *L)
{
    char const *key, *iv;
    size_t key_len, iv_len;
    lua_Integer mode, segment_size;
    bool enable_padding = true;

    mode = luaL_checkinteger(L, 1);
    key = luaL_checklstring(L, 2, &key_len);
    iv = luaL_optlstring(L, 3, NULL, &iv_len);
    segment_size = luaL_optinteger(L, 4, 8);
    if (!lua_isnil(L, 5)) {
        enable_padding = lua_tonumber(L, 5);
    }

    luaL_argcheck(L, key_len > 0, 2, "non-empty key required");
    luaL_argcheck(L, key_len >= 4 && key_len <= 56, 2,
                  "key length must be between 4 and 56 bytes");
    switch (mode) {
    case MODE_CBC:
    case MODE_CFB:
        luaL_argcheck(
            L, iv_len == BLOWFISH_BLOCK_SIZE, 3,
            "initialization vector is required to be 8 bytes in length");
        if (mode == MODE_CFB) {
            luaL_argcheck(
                L,
                (segment_size <= (BLOWFISH_BLOCK_SIZE * 8)
                 && (segment_size & 7) == 0),
                4,
                "segment size must be a multiple of 8 bits between 8 and 64");
        }
        break;
    case MODE_ECB:
        luaL_argcheck(L, iv == NULL, 3,
                      "ECB does not use an initialization vector");
        break;
    case MODE_OFB:
        luaL_argcheck(L, iv_len == BLOWFISH_BLOCK_SIZE, 3,
                      "OFB requires initialization vector of 8 bytes");
        break;
    default:
        luaL_argerror(L, 1, "invalid mode");
        break;
    }

    blowfish_state *state =
        (blowfish_state *)lua_newuserdata(L, sizeof(blowfish_state));
    if (blowfish_init(state, (uint8_t *)key, (size_t)key_len, (uint8_t *)iv,
                      (size_t)iv_len, (blowfish_mode)mode, (int)segment_size,
                      on_error, L))
    {
        state->pkcs7padding = enable_padding;
        luaL_getmetatable(L, TABLE_NAME);
        lua_setmetatable(L, -2);
        return 1;
    }
    return 0;
}

static inline blowfish_state *
extract_state(lua_State *L)
{
    void *maybe_state = luaL_checkudata(L, 1, TABLE_NAME);
    luaL_argcheck(L, maybe_state != NULL, 1, "`Blowfish.state' expected");
    return (blowfish_state *)maybe_state;
}

static int
decrypt(lua_State *L)
{
    blowfish_state *state = extract_state(L);
    char const *msg;
    uint8_t *decrypted;
    size_t msg_len, dec_len;

    if (!lua_isstring(L, 2)) {
        lua_pushnil(L);
        return_error(L,
                     "bad argument #1 to 'decrypt' (string expected, got %s)",
                     lua_typename(L, lua_type(L, 2)));
        return 2;
    }

    msg = lua_tolstring(L, 2, &msg_len);
    if (msg_len == 0) {
        lua_pushnil(L);
    } else {
        decrypted = blowfish_decrypt(state, (uint8_t const *)&msg[0], msg_len,
                                     &dec_len, return_error, L);
        if (decrypted != NULL) {
            lua_pushlstring(L, (char const *)decrypted, dec_len);
            free(decrypted);
        } else {
            return 2;
        }
    }

    return 1;
}

static int
disable_pkcs7_padding(lua_State *L)
{
    blowfish_state *state = extract_state(L);
    state->pkcs7padding = false;
    return 0;
}

static int
enable_pkcs7_padding(lua_State *L)
{
    blowfish_state *state = extract_state(L);
    state->pkcs7padding = true;
    return 0;
}

static int
encrypt(lua_State *L)
{
    blowfish_state *state = extract_state(L);
    char const *msg;
    uint8_t *encrypted;
    size_t msg_len, enc_len;

    if (!lua_isstring(L, 2)) {
        lua_pushnil(L);
        return_error(L,
                     "bad argument #1 to 'encrypt' (string expected, got %s)",
                     lua_typename(L, lua_type(L, 2)));
        return 2;
    }

    msg = lua_tolstring(L, 2, &msg_len);
    if (msg_len == 0) {
        lua_pushnil(L);
    } else {
        encrypted = blowfish_encrypt(state, (uint8_t const *)&msg[0], msg_len,
                                     &enc_len, return_error, L);
        if (encrypted) {
            lua_pushlstring(L, (char const *)encrypted, enc_len);
            free(encrypted);
        } else {
            return 2;
        }
    }

    return 1;
}

static int
reset(lua_State *L)
{
    blowfish_state *state = extract_state(L);
    blowfish_reset(state);
    return 0;
}

static int
to_string(lua_State *L)
{
    blowfish_state *state = extract_state(L);
    lua_pushfstring(L, "cipher(mode=%d)", state->mode);
    return 1;
}

static void
on_error(void *state, char const *fmt, ...)
{
    lua_State *L = (lua_State *)state;
    va_list ap;

    va_start(ap, fmt);
    lua_pushvfstring(L, fmt, ap);
    va_end(ap);
    lua_error(L);
}

static void
return_error(void *state, char const *fmt, ...)
{
    lua_State *L = (lua_State *)state;
    va_list ap;

    lua_pushnil(L);
    va_start(ap, fmt);
    lua_pushvfstring(L, fmt, ap);
    va_end(ap);
}