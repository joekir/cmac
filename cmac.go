// Package cmac implements AES-CMAC (RFC4493)
package cmac

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"hash"
)

func shifted(x []byte) []byte {
	d := make([]byte, len(x))
	copy(d, x)
	for i := range d {
		if i > 0 {
			d[i-1] |= d[i] >> 7
		}
		d[i] <<= 1
	}
	return d
}

func padded(d []byte) []byte {
	p := make([]byte, aes.BlockSize)
	copy(p, d)
	p[len(d)] = 0x80
	return p
}

func gensubkey(c cipher.Block, l []byte, rb byte) []byte {
	sk := shifted(l)
	sk[len(sk)-1] ^= byte(subtle.ConstantTimeSelect(int(l[0]>>7), int(rb), 0))
	return sk
}

func gensubkeys(c cipher.Block) ([]byte, []byte) {
	l := make([]byte, c.BlockSize())
	c.Encrypt(l, l)
	k1 := gensubkey(c, l, 0x87)
	return k1, gensubkey(c, k1, 0x87)
}

type cmac struct {
	c  cipher.Block
	k1 []byte
	k2 []byte

	x []byte

	buf []byte
}

func newcmac(c cipher.Block) *cmac {
	k1, k2 := gensubkeys(c)
	m := &cmac{c: c, k1: k1, k2: k2}
	m.Reset()
	return m
}

func (m *cmac) block(b []byte) {
	y := make([]byte, m.c.BlockSize())
	for i := range y {
		y[i] = m.x[i] ^ b[i]
	}
	m.c.Encrypt(m.x, y)
}

func (m *cmac) Write(b []byte) (int, error) {
	d := append(m.buf, b...)

	for len(d) > m.c.BlockSize() {
		m.block(d[:m.c.BlockSize()])
		d = d[m.c.BlockSize():]
	}

	m.buf = d

	return len(b), nil
}

func (m *cmac) Sum(b []byte) []byte {
	last := make([]byte, m.c.BlockSize())

	if len(m.buf) > 0 && len(m.buf)%m.c.BlockSize() == 0 {
		for i := range last {
			last[i] = m.buf[i] ^ m.k1[i]
		}
	} else {
		copy(last, m.buf)
		last[len(m.buf)] = 0x80
		for i := range last {
			last[i] ^= m.k2[i]
		}
	}

	for i := range last {
		last[i] ^= m.x[i]
	}
	m.c.Encrypt(last, last)

	return append(b, last...)
}

func (m *cmac) Reset() {
	m.buf = nil
	m.x = make([]byte, m.c.BlockSize())
}

func (m *cmac) Size() int {
	return m.c.BlockSize()
}

func (m *cmac) BlockSize() int {
	return m.c.BlockSize()
}

// New returns a hash.Hash computing AES-CMAC.
func New(key []byte) hash.Hash {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	return NewWithCipher(c)
}

// NewWithCipher returns a hash.Hash computing CMAC using the given
// cipher.Block. The block cipher should have a block length of 16 bytes.
func NewWithCipher(c cipher.Block) hash.Hash {
	return newcmac(c)
}
