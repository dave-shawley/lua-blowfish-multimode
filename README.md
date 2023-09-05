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
