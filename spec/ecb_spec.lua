local blowfish = require("blowfish")

describe("#ECB", function()
    local MODE = blowfish.ECB
    local KEY = "any key that you want"

    it("encrypts and decrypts data", function()
        local plaintext = "required to be a multiple of eight bytes"
        local keychain = blowfish.new(MODE, KEY)
        local ciphertext = keychain:encrypt(plaintext)
        assert.equal(
            "\118\161\130\160\192\89\214\103\213\170\14\213\63\15\114" ..
                "\86\73\30\243\232\76\148\132\240\23\27\245\87\162\24" ..
                "\123\250\99\39\20\45\144\217\0\46", ciphertext)
        keychain:reset()
        assert.equal(plaintext, keychain:decrypt(ciphertext))
    end)

    describe("creation", function()
        it("fails when given an IV", function()
            assert.has.errors(function()
                blowfish.new(MODE, "any key", "somebits")
            end)
        end)
        it("fails when given an empty key", function()
            assert.has.errors(function() blowfish.new(MODE, nil) end)
        end)
        it("fails when key is too short", function()
            assert.has_no.errors(function()
                blowfish.new(MODE, "four")
            end)
            assert.has.errors(function() blowfish.new(MODE, "fou") end)
            assert.has.errors(function() blowfish.new(MODE, "fo") end)
            assert.has.errors(function() blowfish.new(MODE, "f") end)
            assert.has.errors(function() blowfish.new(MODE, "") end)
        end)
        it("fails when key is too long", function()
            local key = string.rep("a", 32)
            while (#key <= 56) do
                assert.has_no.errors(function()
                    blowfish.new(MODE, key)
                end)
                key = "b" .. key
            end
            assert.equal(57, #key)
            assert.has.errors(function() blowfish.new(MODE, key) end)
        end)
    end)

    describe("encryption", function()
        local keychain
        setup(function() keychain = blowfish.new(MODE, KEY) end)
        it("returns nil when given an empty string",
           function() assert.equal(nil, keychain:encrypt("")) end)
        it("fails when given a non-string", function()
            assert.has.errors(function() keychain:encrypt({}) end)
        end)
        it("requires message that is multiple of eight bytes", function()
            local message = "a"
            while (#message <= 64) do
                if (#message % 8 == 0) then
                    assert.has_no.errors(function()
                        keychain:encrypt(message)
                    end)
                else
                    assert.has.errors(function()
                        keychain:encrypt(message)
                    end)
                end
                message = message .. "b"
                keychain:reset()
            end
        end)
    end)

    describe("decryption", function()
        local keychain
        setup(function() keychain = blowfish.new(MODE, KEY) end)
        it("returns nil when given an empty string",
           function() assert.equal(nil, keychain:decrypt("")) end)
        it("fails when given a non-string", function()
            assert.has.errors(function() keychain:decrypt({}) end)
        end)
        it("requires cipher-text that is multiple of eight bytes", function()
            local ciphertext = "\0"
            while (#ciphertext <= 64) do
                if (#ciphertext % 8 == 0) then
                    assert.has_no.errors(function()
                        keychain:decrypt(ciphertext)
                    end)
                else
                    assert.has.errors(function()
                        keychain:decrypt(ciphertext)
                    end)
                end
                ciphertext = ciphertext .. "\0"
                keychain:reset()
            end
        end)
    end)

end)