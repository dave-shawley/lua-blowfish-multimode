local blowfish = require("blowfish")

describe("#CFB", function()
    local MODE = blowfish.CFB
    local KEY = "any key that you want"
    local IV = "somebits" -- exactly 8 bytes

    it("encrypts and decrypts data", function()
        local plaintext = "text to be hidden from prying eyes"
        local keychain = blowfish.new(MODE, KEY, IV)
        local ciphertext = keychain:encrypt(plaintext)
        assert.equal("\150\124\155\194\224\185\51\50\54\0\198\106\239\38\96" ..
                         "\36\107\38\208\77\137\200\109\241\145\175\245\134" ..
                         "\139\101\228\157\171\239", ciphertext)
        keychain:reset()
        assert.equal(plaintext, keychain:decrypt(ciphertext))
    end)

    describe("creation", function()
        it("succeeds when IV is 8-bytes in length", function()
            assert.has_no
                .errors(function() blowfish.new(MODE, "any key", IV) end)
        end)
        it("fails when given an empty key", function()
            assert.has.errors(function() blowfish.new(MODE, nil, IV) end)
        end)
        it("fails unless IV is eight bytes long", function()
            assert.has.errors(function()
                blowfish.new(MODE, KEY, "not eight bytes")
            end)
        end)
        it("fails when key is too short", function()
            assert.has_no.errors(function()
                blowfish.new(MODE, "four", IV)
            end)
            assert.has.errors(function()
                blowfish.new(MODE, "fou", IV)
            end)
            assert.has.errors(function() blowfish.new(MODE, "fo", IV) end)
            assert.has.errors(function() blowfish.new(MODE, "f", IV) end)
            assert.has.errors(function() blowfish.new(MODE, "", IV) end)
        end)
        it("fails when key is too long", function()
            local key = string.rep("a", 32)
            while (#key <= 56) do
                assert.has_no.errors(function()
                    blowfish.new(MODE, key, IV)
                end)
                key = "b" .. key
            end
            assert.equal(57, #key)
            assert.has.errors(function() blowfish.new(MODE, key, IV) end)
        end)
        it("fails when segment size is not a multiple of 8 bits", function()
            for segment_size = 0, 70, 1 do
                local probe = function()
                    blowfish.new(MODE, KEY, IV, segment_size)
                end
                if ((segment_size % 8) ~= 0) then
                    assert.has.errors(probe)
                else
                    assert.has_no.errors(probe)
                end
            end
        end)
        it("can disable padding", function()
            local keychain = blowfish.new(MODE, KEY, IV, 16, false)
            local value, err = keychain:encrypt("a")
            assert.is_nil(value)
            assert.is_not_nil(err)
        end)
    end)

    describe("encryption", function()
        local keychain
        local segment_size = 32
        local value, err
        setup(function()
            keychain = blowfish.new(MODE, KEY, IV, segment_size)
        end)
        it("returns nil when given an empty string", function()
            value, err = keychain:encrypt("")
            assert.is_nil(value)
            assert.is_nil(err)
        end)
        it("fails when given a non-string", function()
            value, err = keychain:encrypt({})
            assert.is_nil(value)
            assert.is_not_nil(err)
        end)
        it("requires message that is multiple of segment_size #pkcs-disabled",
           function()
            keychain:disable_pkcs7_padding()
            local segment_byte_size = segment_size / 8
            local message = "a"
            while (#message <= 64) do
                value, err = keychain:encrypt(message)
                if (#message % segment_byte_size == 0) then
                    assert.is_not_nil(value)
                    assert.is_nil(err)
                else
                    assert.is_nil(value)
                    assert.is_not_nil(err)
                end
                message = message .. "b"
                keychain:reset()
            end
        end)
    end)

    describe("decryption", function()
        local segment_size = 24
        local keychain
        local value, err
        setup(function()
            keychain = blowfish.new(MODE, KEY, IV, segment_size)
        end)
        it("returns nil when given an empty string", function()
            value, err = keychain:decrypt("")
            assert.is_nil(value)
            assert.is_nil(err)
        end)
        it("fails when given a non-string", function()
            value, err = keychain:decrypt({})
            assert.is_nil(value)
            assert.is_not_nil(err)
        end)
        it(
            "requires cipher-text that is multiple of segment_size #pkcs7-disabled",
            function()
                keychain:disable_pkcs7_padding()
                local segment_byte_size = segment_size / 8
                local ciphertext = "\0"
                while (#ciphertext <= 64) do
                    value, err = keychain:decrypt(ciphertext)
                    if (#ciphertext % segment_byte_size == 0) then
                        assert.is_not_nil(value)
                        assert.is_nil(err)
                    else
                        assert.is_nil(value)
                        assert.is_not_nil(err)
                    end
                    ciphertext = ciphertext .. "\0"
                    keychain:reset()
                end
            end)
    end)

end)
