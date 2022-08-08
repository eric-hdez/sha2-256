package sha2

import (
    "encoding/binary"
    "math/bits"
)

const (
    blockSize int = 64
    byteSize  int = 8
    u64Bytes  int = 8
    u32Bytes  int = 4
)

/*
  hash values:
    the first 32 bits of the fractional parts of the square roots of the first eight primes
*/
var h = [8]uint32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

/*
  round constants:
    the first 32 bits of the fractional parts of the cube roots of the first sixty four primes
*/
var k = [64]uint32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

/*
  the 'choose' logical operation used in sha2-256, the x input 'chooses'
  betweeh the bits of y or z
*/
func ch(x, y, z uint32) uint32 {
    return (x & y) ^ (bitCompliment32(x) & z)
}

/*
  the 'majority' logic operation used in sha2-256, the resulting bits
  are the majority bits at each index from the three inputs x, y, z
*/
func maj(x, y, z uint32) uint32 {
    return (x & y) ^ (x & z) ^ (y & z)
}

/*
  a (~) compliment operator for 32 bit unsigned integers used by ch
*/
func bitCompliment32(x uint32) uint32 {
    return x ^ 0xFFFFFFFF
}

/*
  pads the original message of length l with:
    - a '1' bit
    - z number of '0' bits such that l + 1 + z ≡ 448 mod 512
    - the big endian representation of l as a 64 bit unsigned int
  and returns the padded message
*/
func padMessage(msg []byte) []byte {
    l := len(msg)
    msg = append(msg, 0x80)

    z := (blockSize + 56 - (l%blockSize + 1)) % blockSize

    zeroes := make([]byte, z)
    msg = append(msg, zeroes...)

    binLen64 := make([]byte, u64Bytes)
    binary.BigEndian.PutUint64(binLen64, uint64(l*byteSize))
    msg = append(msg, binLen64...)

    return msg
}

/*
  packs a single 512 bit block into the first 16 words of the
  message schedule array (w) and returns the message schedule
  array
*/
func packBlockIntoWords(block []byte) [64]uint32 {
    var w [64]uint32
    offset := 0

    for i := 0; i < 16; i++ {
        w[i] = binary.BigEndian.Uint32(block[offset:])
        offset += u32Bytes
    }

    return w
}

/*
  extends the 512 bit block that was packed into the first 16 words
  of the message schedule array into the remaining 48 words and returns
  the message schedule array
*/
func extendWords(w [64]uint32) [64]uint32 {
    for i := 16; i < 64; i++ {
        s0 := bits.RotateLeft32(w[i-15], -7) ^ bits.RotateLeft32(w[i-15], -18) ^ (w[i-15] >> 3)
        s1 := bits.RotateLeft32(w[i-2], -17) ^ bits.RotateLeft32(w[i-2], -19) ^ (w[i-2] >> 10)
        w[i] = w[i-16] + s0 + w[i-7] + s1
    }

    return w
}

/*
  computes the ith block's intermediate hash value using the i - 1
  block's hash values, effectively compressing the block into
  the hash. Returns the ith block's internediate hash values
*/
func compress(w [64]uint32, hv [8]uint32) [8]uint32 {
    a := hv[0]
    b := hv[1]
    c := hv[2]
    d := hv[3]
    e := hv[4]
    f := hv[5]
    g := hv[6]
    h := hv[7]

    for i := 0; i < 64; i++ {
        S1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
        t1 := h + S1 + ch(e, f, g) + k[i] + w[i]
        S0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
        t2 := S0 + maj(a, b, c)

        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    }

    hv[0] += a
    hv[1] += b
    hv[2] += c
    hv[3] += d
    hv[4] += e
    hv[5] += f
    hv[6] += g
    hv[7] += h

    return hv
}

/*
  processes a message by padding the message, packing it into the
  message schedule array, and compressing all the blocks into the
  hash values
*/
func processMessage(msg []byte) [8]uint32 {
    msg = padMessage(msg)
    byteLen := len(msg)

    hashValues := h

    for i := 0; i < byteLen; i += blockSize {
        end := i + blockSize
        w := packBlockIntoWords(msg[i:end])
        w = extendWords(w)
        hashValues = compress(w, hashValues)
    }

    return hashValues
}

/*
  client hash function, processes the message and returns the 256
  bit digest (the hash) of the message
*/
func Hash256(msg []byte) []byte {
    hashValues := processMessage(msg)
    currHashValue := make([]byte, u32Bytes)
    var digest []byte

    for i := 0; i < 8; i++ {
        binary.BigEndian.PutUint32(currHashValue, hashValues[i])
        digest = append(digest, currHashValue...)
    }

    return digest
}
