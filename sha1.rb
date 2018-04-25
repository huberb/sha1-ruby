require 'pry'

class Sha1
    # [2262422101, 3793833677, 1288310910, 3341981966, 72020916]
    def initialize(message)
        @bitstring = message.unpack('B*')[0]
        @orig_message_len = @bitstring.length
        @hash_words = { 
            a: 0x67452301,
            b: 0xEFCDAB89, 
            c: 0x98BADCFE, 
            d: 0x10325476, 
            e: 0xC3D2E1F0 
        }
    end

    def padding
        # append the bit '1' to the message
        @bitstring += "1"
        # append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
        # is congruent to −64 ≡ 448 (mod 512)
        while(448 % 512 != @bitstring.length % 512) do
            @bitstring += "0"
        end
        # append ml, the original message length,
        # as a 64-bit big-endian integer.
        # Thus, the total length is a multiple of 512 bits.
        @bitstring += (("0" * (64 - @orig_message_len.to_s(2).length)) + @orig_message_len.to_s(2))
        if @bitstring.length % 512 == 0
            @bitstring
        else
            throw("Error, Message length is wrong!")
        end
    end

    def split_up(string, size)
        if block_given?
            (string.length / size).times do |i|
                yield string[i * size, size]
            end
        else
            (string.length / size).times.collect do |i|
                string[i * size, size]
            end
        end
    end

    def left_rotate(word, count)
        ((word << count) | (word >> 32 - count))
    end

    def append_words(words)
        (16...80).each do |i|
            new_word = words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16]
            words[i] = left_rotate(new_word, 1) & 2**32-1
        end
        words
    end

    def compression(words)
        a = @hash_words[:a]
        b = @hash_words[:b]
        c = @hash_words[:c]
        d = @hash_words[:d]
        e = @hash_words[:e]

        # this is correct by now
        (0...80).each do |i|
            if i <= 19
                f = (b & c) ^ ((~b) & d)
                k = 0x5A827999
            elsif i <= 39
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elsif i <= 59
                f = (b & c) ^ (b & d) ^ (c & d)
                k = 0x8F1BBCDC
            else
                f = b ^ c ^ d
                k = 0xCA62C1D6
            end
            rotated_a = left_rotate(a, 5)
            tmp = (rotated_a + f + e + k + words[i]) & 2**32-1

            e = d
            d = c
            c = left_rotate(b, 30) & 2**32-1
            b = a
            a = tmp
        end

        # Add this chunk's hash to result so far:
        @hash_words[:a] = (@hash_words[:a] + a) & (2**32) - 1
        @hash_words[:b] = (@hash_words[:b] + b) & (2**32) - 1
        @hash_words[:c] = (@hash_words[:c] + c) & (2**32) - 1
        @hash_words[:d] = (@hash_words[:d] + d) & (2**32) - 1
        @hash_words[:e] = (@hash_words[:e] + e) & (2**32) - 1
    end

    # Produce the final hash value (big-endian) as a 160-bit number
    def produce_hash
        # hh = (h0 leftshift 128) or (h1 leftshift 96) or (h2 leftshift 64) or (h3 leftshift 32) or h4
        var1 = (@hash_words[:a]).to_s(16)
        var2 = (@hash_words[:b]).to_s(16)
        var3 = (@hash_words[:c]).to_s(16)
        var4 = (@hash_words[:d]).to_s(16)
        var5 = (@hash_words[:e]).to_s(16)
        # this is the final hash
        "#{var1}#{var2}#{var3}#{var4}#{var5}"
    end

    def digest
        @bitstring = padding()
        # break message into 512-bit chunks
        split_up(@bitstring, 512) do |chunk|
            # break chunk into sixteen 32-bit big-endian words
            words = split_up(chunk, 32)
            words = words.map { |word| word.to_i(2) }
            # extend the sixteen 32-bit words into eighty 32-bit words:
            words = append_words(words)
            # words.each { |w| puts(w) }
            # go into main loop
            compression(words)
        end
        produce_hash
    end
end

ARGV.each do |message|
    puts(Sha1.new(File.open(message).read()).digest())
end
