package cmac

import (
	"bytes"
	"testing"
)

func TestGenSubkeys(t *testing.T) {
	for i, tv := range nistvectors {
		c, err := tv.cipher(tv.key)
		if err != nil {
			t.Fatal(err)
		}
		k1, k2 := gensubkeys(c)
		if !bytes.Equal(k1, tv.k1) {
			t.Errorf("tv[%d]: expected: %x got %x\n", i, tv.k1, k1)
		}
		if !bytes.Equal(k2, tv.k2) {
			t.Errorf("tv[%d]: expected: %x got %x\n", i, tv.k2, k2)
		}
	}
}

func TestNew(t *testing.T) {
	for i := 0; i < 3; i++ {
		tv := nistvectors[i]

		m, err := New(tv.key)
		if err != nil {
			t.Fatalf("tv[%d]: New() err: %s\n", i, err)
		}
		for j, tc := range tv.cases {
			m.Write(tc.msg)
			mac := m.Sum(nil)
			if !bytes.Equal(mac, tc.mac) {
				t.Errorf("tv[%d,%d]: expected: %x got %x\n", i, j, tc.mac, mac)
			}
			m.Reset()
		}
	}
}

func TestNewWithCipher(t *testing.T) {
	for i, tv := range nistvectors {
		c, err := tv.cipher(tv.key)
		if err != nil {
			t.Fatal(err)
		}
		m, err := NewWithCipher(c)
		if err != nil {
			t.Fatalf("tv[%d]: NewWithCipher() err: %s\n", i, err)
		}
		for j, tc := range tv.cases {
			m.Write(tc.msg)
			mac := m.Sum(nil)
			if !bytes.Equal(mac, tc.mac) {
				t.Errorf("tv[%d,%d]: expected: %x got %x\n", i, j, tc.mac, mac)
			}
			m.Reset()
		}
	}
}

func TestChunkedWrites(t *testing.T) {
	key := make([]byte, 16)
	expected := []byte{0xe9, 0x0a, 0xe6, 0xf3, 0x44, 0x73, 0x47, 0xf6, 0x19, 0xcf, 0xf1, 0x6a, 0xb2, 0xa3, 0xd4, 0x9c}
	total := 1 << 20

	h, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	n := 0
	for c := 0; n < total; c += 1 {
		if n+c > total {
			c = total - n
		}

		chunk := make([]byte, c)
		h.Write(chunk)
		n += len(chunk)
	}
	mac := h.Sum(nil)

	if !bytes.Equal(mac, expected) {
		t.Errorf("expected: %x got %x\n", expected, mac)
	}
}

func benchmarkHash(b *testing.B, size int64) {
	buf := make([]byte, size)
	h, _ := New(make([]byte, 128/8))
	sum := make([]byte, 0, h.Size())

	b.ReportAllocs()
	b.SetBytes(size)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf)
		h.Sum(sum)
	}
}

func BenchmarkHash1K(b *testing.B) { benchmarkHash(b, 1<<10) }
func BenchmarkHash1M(b *testing.B) { benchmarkHash(b, 1<<20) }
