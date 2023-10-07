# Multimode Blowfish Encryption for Lua

Yeah ... that's right ... the symmetric block cipher created by Bruce Schneier in
the long gone 1990s wrapped in Lua. First of all, **DO NOT USE THIS UNLESS YOU
HAVE TO**. I'm serious about that. This algorithm is pretty cool and was awesome
for its day. But that day is long gone. I wrote this because I actually have a
decent amount of data that is encrypted using Blowfish CBC with 8 bit feedback.
I need to access said data from a Kong proxy so I needed a Lua module that can
manipulate the data.

Let me say this again **DO NOT USE THIS UNLESS YOU HAVE TO!**

I took the public domain implementation of the algorithm from the [PyCrypto]
library and rearranged it a little bit to make it more amenable to being a
Lua module. The C-based unit tests use ciphers that were cross checked with
the Python implementation on which it is based. For what it is worth, I chose
to based this on [PyCrypto] since that was the library that originally encrypted
the data. Don't use that library either!  Use [PyCryptodome] instead. It is still
supported through modern Python versions.

[PyCrypto]: https://github.com/pycrypto/pycrypto/commit/65b43bd4ffe2a48bdedae986b1a291f5a2cc7df7

[PyCryptodome]: https://pycryptodome.readthedocs.io/en/latest/index.html

## Usage

```lua
local blowfish = require("blowfish")
local keychain = blowfish.new(blowfish.MODE_CBC, "some-key", "short-iv")
local cipher_text = keychain:encrypt("message to encrypt")
keychain:reset()
local plain_text = keychange:decrypt(cipher_text)
print(plain_text)  -- message to encrypt
```

## API

### blowfish.new

Creates a new context or fail.

| Parameter             | Type   | Description                                                  |
|-----------------------|--------|--------------------------------------------------------------|
| mode                  | number | selects the processing mode                                  |
| key                   | string | encryption key between 4 and 56 bytes                        |
| initialization vector | string | bytes to mix into the cipher blocks                          |
| segment size          | number | number of bits in each segment this is only used in CBC mode |

This function fails by calling `error()` with a useful message. Use `pcall()` if you want to
protect from configuration errors.

### Blowfish:encrypt

Encrypt a string.

| Parameter  | Type   | Description        |
|------------|--------|--------------------|
| plain text | string | message to encrypt |

| Return index | Type   | Description                                         |
|:------------:|--------|-----------------------------------------------------|
|      1       | string | the ciphertext string or `nil` if an error occurs   |
|      2       | string | error message if an error occurred, `nil` otherwise |

This method will return `nil` for exactly one of the return slots. If an error occurs, then the first
slot will be `nil` and the second contains an error message. Otherwise, the first slot is the cipher
text and the second is `nil`.

### Blowfish:decrypt

Decrypt a string.

| Parameter   | Type   | Description        |
|-------------|--------|--------------------|
| cipher text | string | message to decrypt |

| Return index | Type   | Description                                         |
|:------------:|--------|-----------------------------------------------------|
|      1       | string | the plaintext string or `nil` if an error occurs    |
|      2       | string | error message if an error occurred, `nil` otherwise |

This method will return `nil` for exactly one of the return slots. If an error occurs, then the first
slot will be `nil` and the second contains an error message. Otherwise, the first slot is the decrypted
text and the second is `nil`.

### Blowfish:reset

Reset a context for additional processing.

This method resets the internal state in preparation to make another call.
