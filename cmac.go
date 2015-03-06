// Package cmac implements CMAC as defined in RFC4493 and NIST SP800-38b.
package cmac

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"hash"
)

const (
	_Rb128 = 0x87
	_Rb64  = 0x1b
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

func gensubkey(c cipher.Block, l []byte, rb byte) []byte {
	sk := shifted(l)
	sk[len(sk)-1] ^= byte(subtle.ConstantTimeSelect(int(l[0]>>7), int(rb), 0))
	return sk
}

func gensubkeys(c cipher.Block) ([]byte, []byte) {
	var rb byte

	switch c.BlockSize() {
	case 16:
		rb = _Rb128
	case 8:
		rb = _Rb64
	default:
		panic("cmac: invalid block size")

	}

	l := make([]byte, c.BlockSize())
	c.Encrypt(l, l)

	k1 := gensubkey(c, l, rb)
	return k1, gensubkey(c, k1, rb)
}

type cmac struct {
	c           cipher.Block
	k1, k2      []byte
	buf, x, tmp []byte
}

func newcmac(c cipher.Block) *cmac {
	k1, k2 := gensubkeys(c)
	tmp := make([]byte, c.BlockSize())
	m := &cmac{c: c, k1: k1, k2: k2, tmp: tmp}
	m.Reset()
	return m
}

func (m *cmac) block(b []byte) {
	for i := range m.tmp {
		m.tmp[i] = m.x[i] ^ b[i]
	}
	m.c.Encrypt(m.x, m.tmp)
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
func New(key []byte) (hash.Hash, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return NewWithCipher(c)
}

// NewWithCipher returns a hash.Hash computing CMAC using the given
// cipher.Block. The block cipher should have a block length of 8 or 16 bytes.
func NewWithCipher(c cipher.Block) (hash.Hash, error) {
	switch c.BlockSize() {
	case 8, 16:
		return newcmac(c), nil
	default:
		return nil, errors.New("cmac: invalid blocksize")
	}
}
