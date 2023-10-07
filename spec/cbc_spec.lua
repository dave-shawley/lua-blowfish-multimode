local blowfish = require("blowfish")

describe("#CBC", function()
    local MODE = blowfish.CBC
    local KEY = "any key that you want"
    local IV = "somebits" -- exactly 8 bytes

    it("encrypts and decrypts data", function()
        local plaintext = "sixteen  letters"
        local keychain = blowfish.new(MODE, KEY, IV)
        local ciphertext = keychain:encrypt(plaintext)
        assert.equal(
            "\168\176\157\101\104\36\56\214\171\196\38\14\167\194\168\188",
            ciphertext)
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
        it("requires message that is multiple of 8 bytes", function()
            local message = "a"
            while (#message <= 64) do
                value, err = keychain:encrypt(message)
                if (#message % 8 == 0) then
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
        it("requires cipher-text that is multiple of 8 bytes", function()
            local ciphertext = "\0"
            while (#ciphertext <= 64) do
                value, err = keychain:decrypt(ciphertext)
                if (#ciphertext % 8 == 0) then
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
