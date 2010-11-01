// Copyright (c) 2010, Suryandaru Triandana. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package implements the Rabbit encryption algorithm as defined in eSTREAM portfolio.
package rabbit

// This Go implementation is derived in part from the reference
// ANSI C implementation, which carries the following notice:
//
//	File name: rabbit.c
//
//	Source file for reference C version of the Rabbit stream cipher.
//
//	For further documentation, see "Rabbit Stream Cipher, Algorithm
//	Specification" which can be found at http://www.cryptico.com/.
//
//	This source code is for little-endian processors (e.g. x86).
//
//	Copyright (C) Cryptico ApS. All rights reserved.
//
//	YOU SHOULD CAREFULLY READ THIS LEGAL NOTICE BEFORE USING THIS SOFTWARE.
//
//	This software is developed by Cryptico ApS and/or its suppliers. It is
//	free for commercial and non-commercial use.
//
//	Cryptico ApS shall not in any way be liable for any use or export/import
//	of this software. The software is provided "as is" without any express or
//	implied warranty.
//
//	Cryptico, CryptiCore, the Cryptico logo and "Re-thinking encryption" are
//	either trademarks or registered trademarks of Cryptico ApS.

import (
	"os"
	"strconv"
)

// A Cipher is an instance of Rabbit encryption using a particular key.
type Cipher struct {
	x, c, cx, cc [8]uint32
	carry, ccarry bool
	r []byte
}

type KeySizeError struct {
	t, sz int
}

func (k *KeySizeError) String() string {
	switch(k.t) {
	case 1:
		return "crypto/rabbit: invalid key size " + strconv.Itoa(int(k.sz))
	case 2:
		return "crypto/rabbit: invalid iv size " + strconv.Itoa(int(k.sz))
	}
	return "crypto/rabbit: unknown key error type"
}

func rotl(v, n uint32) uint32 {
	return v<<n | v>>(32-n)
}

func rabbitCalcG(x uint32) uint32 {
	var a, b uint32
	a = x&0xFFFF;
	b = x>>16;
	return ((((a*a)>>17 + a*b)>>15) + b*b)^(x*x)
}

func booltoi(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func (c *Cipher) rabbitNext() {
	var c0, c1, c2, c3, c4, c5, c6, c7 uint32

	c0, c1, c2, c3 = c.c[0], c.c[1], c.c[2], c.c[3]
	c4, c5, c6, c7 = c.c[4], c.c[5], c.c[6], c.c[7]

	c0 = c0 + 0x4D34D34D + booltoi(c.carry)
	c1 = c1 + 0xD34D34D3 + booltoi(c0 < c.c[0])
	c2 = c2 + 0x34D34D34 + booltoi(c1 < c.c[1])
	c3 = c3 + 0x4D34D34D + booltoi(c2 < c.c[2])
	c4 = c4 + 0xD34D34D3 + booltoi(c3 < c.c[3])
	c5 = c5 + 0x34D34D34 + booltoi(c4 < c.c[4])
	c6 = c6 + 0x4D34D34D + booltoi(c5 < c.c[5])
	c7 = c7 + 0xD34D34D3 + booltoi(c6 < c.c[6])
	c.carry = (c7 < c.c[7])

	g0 := rabbitCalcG(c.x[0] + c0)
	g1 := rabbitCalcG(c.x[1] + c1)
	g2 := rabbitCalcG(c.x[2] + c2)
	g3 := rabbitCalcG(c.x[3] + c3)
	g4 := rabbitCalcG(c.x[4] + c4)
	g5 := rabbitCalcG(c.x[5] + c5)
	g6 := rabbitCalcG(c.x[6] + c6)
	g7 := rabbitCalcG(c.x[7] + c7)

	c.x[0] = g0 + rotl(g7,16) + rotl(g6, 16)
	c.x[1] = g1 + rotl(g0, 8) + g7
	c.x[2] = g2 + rotl(g1,16) + rotl(g0, 16)
	c.x[3] = g3 + rotl(g2, 8) + g1
	c.x[4] = g4 + rotl(g3,16) + rotl(g2, 16)
	c.x[5] = g5 + rotl(g4, 8) + g3
	c.x[6] = g6 + rotl(g5,16) + rotl(g4, 16)
	c.x[7] = g7 + rotl(g6, 8) + g5

	c.c[0], c.c[1], c.c[2], c.c[3] = c0, c1, c2, c3
	c.c[4], c.c[5], c.c[6], c.c[7] = c4, c5, c6, c7
}

func (c *Cipher) rabbitGen(buf *[16]byte) {
	c.rabbitNext()
	var d0, d1, d2, d3 uint32
	d0 = c.x[0] ^ (c.x[5]>>16 ^ c.x[3]<<16)
	d1 = c.x[2] ^ (c.x[7]>>16 ^ c.x[5]<<16)
	d2 = c.x[4] ^ (c.x[1]>>16 ^ c.x[7]<<16)
	d3 = c.x[6] ^ (c.x[3]>>16 ^ c.x[1]<<16)
	buf[ 0], buf[ 1], buf[ 2], buf[ 3] = byte(d0), byte(d0>>8), byte(d0>>16), byte(d0>>24)
	buf[ 4], buf[ 5], buf[ 6], buf[ 7] = byte(d1), byte(d1>>8), byte(d1>>16), byte(d1>>24)
	buf[ 8], buf[ 9], buf[10], buf[11] = byte(d2), byte(d2>>8), byte(d2>>16), byte(d2>>24)
	buf[12], buf[13], buf[14], buf[15] = byte(d3), byte(d3>>8), byte(d3>>16), byte(d3>>24)
}

// NewCipher creates and returns a Cipher.
// Rabbit key, must be 16 bytes.
func NewCipher(key []byte) (*Cipher, os.Error) {
	k := len(key)
	if k != 16 {
		return nil, &KeySizeError{1, k}
	}
	var c Cipher

	var k0, k1, k2, k3 uint32
	k0 = uint32(key[ 0]) | uint32(key[ 1])<<8 | uint32(key[ 2])<<16 | uint32(key[ 3])<<24
	k1 = uint32(key[ 4]) | uint32(key[ 5])<<8 | uint32(key[ 6])<<16 | uint32(key[ 7])<<24
	k2 = uint32(key[ 8]) | uint32(key[ 9])<<8 | uint32(key[10])<<16 | uint32(key[11])<<24
	k3 = uint32(key[12]) | uint32(key[13])<<8 | uint32(key[14])<<16 | uint32(key[15])<<24

	c.x[0] = k0
	c.x[2] = k1
	c.x[4] = k2
	c.x[6] = k3
	c.x[1] = k3<<16 | k2>>16
	c.x[3] = k0<<16 | k3>>16
	c.x[5] = k1<<16 | k0>>16
	c.x[7] = k2<<16 | k1>>16

	c.c[0] = rotl(k2, 16)
	c.c[2] = rotl(k3, 16)
	c.c[4] = rotl(k0, 16)
	c.c[6] = rotl(k1, 16)
	c.c[1] = (k0&0xFFFF0000) | (k1&0xFFFF)
	c.c[3] = (k1&0xFFFF0000) | (k2&0xFFFF)
	c.c[5] = (k2&0xFFFF0000) | (k3&0xFFFF)
	c.c[7] = (k3&0xFFFF0000) | (k0&0xFFFF)

	c.carry = false

	for i := 0; i < 4; i++ {
		c.rabbitNext()
	}

	for i := range c.c {
		c.c[i] ^= c.x[(i+4)&0x7]
	}

	for i := range c.c {
		c.cx[i] = c.x[i]
		c.cc[i] = c.c[i]
	}
	c.ccarry = c.carry

	return &c, nil
}

// SetupIV will setup Initialization vector.
// Rabbit iv, must be 8 bytes.
func (c *Cipher) SetupIV(iv []byte) os.Error {
	k := len(iv)
	if k != 8 {
		return &KeySizeError{2, k}
	}

	var d0, d1, d2, d3 uint32
	d0 = uint32(iv[0]) | uint32(iv[1])<<8 | uint32(iv[2])<<16 | uint32(iv[3])<<24
	d2 = uint32(iv[4]) | uint32(iv[5])<<8 | uint32(iv[6])<<16 | uint32(iv[7])<<24
	d1 = d0>>16 | (d2&0xFFFF0000)
	d3 = d2<<16 | (d0&0x0000FFFF)

	c.c[0] = c.cc[0] ^ d0
	c.c[1] = c.cc[1] ^ d1
	c.c[2] = c.cc[2] ^ d2
	c.c[3] = c.cc[3] ^ d3
	c.c[4] = c.cc[4] ^ d0
	c.c[5] = c.cc[5] ^ d1
	c.c[6] = c.cc[6] ^ d2
	c.c[7] = c.cc[7] ^ d3

	for i := range c.x {
		c.x[i] = c.cx[i]
	}
	c.carry = c.ccarry

	for i := 0; i < 4; i++ {
		c.rabbitNext()
	}

	return nil
}

// ProcessStream will encrypt or decrypt given buffer.
func (c *Cipher) ProcessStream(buf []byte) {
	l := len(buf)
	i := 0
	if m := len(c.r); m > 0 {
		for ; i < m && i < l; i++ {
			buf[i] ^= c.r[i]
		}
		c.r = nil
	}
	for i < l {
		c.rabbitNext()

		if n := l - i; n >= 16 {
			o0 := c.x[0] ^ (c.x[5]>>16 ^ c.x[3]<<16)
			o1 := c.x[2] ^ (c.x[7]>>16 ^ c.x[5]<<16)
			o2 := c.x[4] ^ (c.x[1]>>16 ^ c.x[7]<<16)
			o3 := c.x[6] ^ (c.x[3]>>16 ^ c.x[1]<<16)
			buf[i + 0] ^= byte(o0     )
			buf[i + 1] ^= byte(o0 >> 8)
			buf[i + 2] ^= byte(o0 >>16)
			buf[i + 3] ^= byte(o0 >>24)
			buf[i + 4] ^= byte(o1     )
			buf[i + 5] ^= byte(o1 >> 8)
			buf[i + 6] ^= byte(o1 >>16)
			buf[i + 7] ^= byte(o1 >>24)
			buf[i + 8] ^= byte(o2     )
			buf[i + 9] ^= byte(o2 >> 8)
			buf[i +10] ^= byte(o2 >>16)
			buf[i +11] ^= byte(o2 >>24)
			buf[i +12] ^= byte(o3     )
			buf[i +13] ^= byte(o3 >> 8)
			buf[i +14] ^= byte(o3 >>16)
			buf[i +15] ^= byte(o3 >>24)
			i += 16
		} else {
			for b, j, z, f := buf, 0, c.x[0] ^ (c.x[5]>>16 ^ c.x[3]<<16), false; j < 4; j++ {
				for k := uint32(0); k < 4; k++ {
					b[i] ^= byte(z>>(k*8))
					if i++; f == false && i >= l {
						l = (3 - j)*4 + (3 - int(k))
						if l == 0 { return }
						c.r = make([]byte, l)
						b, i, f = c.r, 0, true
					}
				}
				switch(j) {
				case  0: z = c.x[2] ^ (c.x[7]>>16 ^ c.x[5]<<16)
				case  1: z = c.x[4] ^ (c.x[1]>>16 ^ c.x[7]<<16)
				case  2: z = c.x[6] ^ (c.x[3]>>16 ^ c.x[1]<<16)
				}
			}
		}
	}
}

// ResetCipher reset cipher round to original state. Initialization vector will be erased.
func (c *Cipher) ResetCipher() {
	for i := range c.c {
		c.c[i] = c.cc[i]
	}
	for i := range c.x {
		c.x[i] = c.cx[i]
	}
	c.carry = c.ccarry
}

// Reset zeros the key data so that it will no longer appear in the
// process's memory.
func (c *Cipher) Reset() {
	for i := range c.x {
		c.x[i], c.c[i], c.cx[i], c.cc[i] = 0, 0, 0, 0
	}
	c.carry, c.carry = false, false
}

