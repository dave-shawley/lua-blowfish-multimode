local blowfish = require("blowfish")

describe("#OFB", function()
    local MODE = blowfish.OFB
    local KEY = "any key that you want"
    local IV = "somebits" -- exactly 8 bytes

    it("encrypts and decrypts data", function()
        local plaintext = "no block size restriction"
        local keychain = blowfish.new(MODE, KEY, IV)
        local ciphertext = keychain:encrypt(plaintext)
        assert.equal(
            "\140\84\193\64\249\91\117\142\3\151\131\141\188\8\61\239" ..
                "\40\136\243\47\168\237\221\197\219", ciphertext)
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
    end)

    describe("encryption", function()
        local keychain
        local value, err
        setup(function() keychain = blowfish.new(MODE, KEY, IV) end)
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
    end)

    describe("decryption", function()
        local keychain
        local value, err
        setup(function() keychain = blowfish.new(MODE, KEY, IV) end)
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
    end)

end)
