rockspec_format = "3.0"
package = "blowfish-multimode"
version = "0.0-1"
source = {
    url = "https://github.com/dave-shawley/lua-blowfish-multimode",
}
description = {
    homepage = "https://github.com/dave-shawley/lua-blowfish-multimode",
    summary = "Implementation of the Blowfish encryption algorithm",
    detailed = [[
        The implementation of this library is adapted from the Python
        PyCrypto library (https://github.com/pycrypto/pycrypto).
    ]],
    license = "Public Domain",
}
dependencies = {
    "lua >= 5.1",
}
build = {
    type = "builtin",
    modules = {
        ["blowfish"] = {"src/lua_blowfish.c", "src/blowfish.c"}
    }
}
test = {}
test_dependencies = {
    "busted"
}
