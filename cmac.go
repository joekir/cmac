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
	c       cipher.Block
	k1, k2  []byte
	buf, x  []byte
	scratch []byte
	cursor  int
}

func newcmac(c cipher.Block) *cmac {
	k1, k2 := gensubkeys(c)
	buf := make([]byte, c.BlockSize())
	x := make([]byte, c.BlockSize())
	m := &cmac{c: c, k1: k1, k2: k2, buf: buf, x: x}
	m.Reset()
	return m
}

func (m *cmac) Write(b []byte) (int, error) {
	totLen := len(b)

	n := copy(m.buf[m.cursor:], b)
	m.cursor += n
	b = b[n:]

	for len(b) > 0 {
		for i := range m.buf {
			m.buf[i] ^= m.x[i]
		}
		m.c.Encrypt(m.x, m.buf)

		m.cursor = copy(m.buf, b)
		b = b[m.cursor:]
	}

	return totLen, nil
}

func (m *cmac) Sum(b []byte) []byte {
	n := len(b)
	// I'm not sure why we need to do this: the second argument of
	// 	append(b, make([]byte, m.c.BlockSize())...)
	// shouldn't escape, so I'm not sure why it ends up getting heap
	// allocated (as of Go 1.4.2 at least).
	switch m.c.BlockSize() {
	case 8:
		b = append(b, 0, 0, 0, 0, 0, 0, 0, 0)
	case 16:
		b = append(b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	default:
		panic("unexpected block size")
	}
	scratch := b[n:]

	if m.cursor == m.c.BlockSize() {
		for i := range scratch {
			scratch[i] = m.buf[i] ^ m.k1[i]
		}
	} else {
		for i := 0; i < m.cursor; i++ {
			scratch[i] = m.buf[i] ^ m.k2[i]
		}
		scratch[m.cursor] = 0x80 ^ m.k2[m.cursor]
		for i := m.cursor + 1; i < len(m.buf); i++ {
			scratch[i] = m.k2[i]
		}
	}

	for i := range scratch {
		scratch[i] ^= m.x[i]
	}
	m.c.Encrypt(scratch, scratch)

	return b
}

func (m *cmac) Reset() {
	for i := 0; i < m.c.BlockSize(); i++ {
		m.buf[i] = 0
		m.x[i] = 0
	}
	m.cursor = 0
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
