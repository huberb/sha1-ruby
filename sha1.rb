class Sha1
    def initialize(message)
        # the message as a string of bits
        @bitstring = message.unpack('B*')[0]
        @orig_message_len = @bitstring.length
        # initial values for compression function
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
        # thus, the total length is a multiple of 512 bits.
        @bitstring += (("0" * (64 - @orig_message_len.to_s(2).length)) + @orig_message_len.to_s(2))
    end

    # split up a string into chunks of a given size
    # works with and without block
    def split_up(string, size)
        strings = (string.length / size).times.collect { |i| string[i * size, size] }
        strings.each{ |s| yield s } if block_given?
        strings
    end

    # rotate a number bitwise, keep at 32 bit length
    # kind of hard to understand how this works:
    # https://en.wikipedia.org/wiki/Circular_shift
    def left_rotate(word, count)
        ((word << count) | (word >> 32 - count))
    end

    # take the inital 16 words from the block and generate 64 more of them
    def append_words(words)
        (16...80).each do |i|
            new_word = words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16]
            words[i] = left_rotate(new_word, 1) & (2**32)-1
        end
        words
    end

    # this is the core compression function of SHA1
    # runs over the 80 word block that was generated from the initial message block
    # and calcutes new seed values for the next block
    def compression(words)
        # hash words for this round:
        a = @hash_words[:a]
        b = @hash_words[:b]
        c = @hash_words[:c]
        d = @hash_words[:d]
        e = @hash_words[:e]

        # run 80 rounds of compression
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
            tmp = (left_rotate(a, 5) + f + e + k + words[i]) & 2**32-1
            e = d
            d = c
            c = left_rotate(b, 30) & 2**32-1
            b = a
            a = tmp
        end

        # Add this chunk's hash to result so far:
        # make sure it stays at 32 bit
        # since ruby likes to convert to BigNum class
        @hash_words[:a] = (@hash_words[:a] + a) & (2**32) - 1
        @hash_words[:b] = (@hash_words[:b] + b) & (2**32) - 1
        @hash_words[:c] = (@hash_words[:c] + c) & (2**32) - 1
        @hash_words[:d] = (@hash_words[:d] + d) & (2**32) - 1
        @hash_words[:e] = (@hash_words[:e] + e) & (2**32) - 1
    end

    # produce the final hash value (big-endian) as a 160-bit number
    # concat the 5 hash words as hex 
    # after the compression function ran over all message blocks
    def produce_hash
        @hash_words.values.map{ |word| word.to_s(16) }.join
    end

    def digest
        @bitstring = padding()
        # break message into 512-bit chunks
        split_up(@bitstring, 512) do |chunk|
            # break chunk into sixteen 32-bit big-endian words
            words = split_up(chunk, 32)
            # convert bitstrings to 32-bit integers for easier math
            words = words.map { |word| word.to_i(2) }
            # extend the sixteen words into eighty words:
            words = append_words(words)
            # go into main loop
            compression(words)
        end
        produce_hash
    end
end

# read the paths as param from the cmd line
ARGV.each do |path|
    message = File.open(path).read()
    hash = Sha1.new(message).digest
    puts("#{hash}  #{path}")
end
