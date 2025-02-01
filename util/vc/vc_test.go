package vc

import (
	"crypto/rand"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"testing"
)

func BenchmarkVC(b *testing.B) {
	pp := NewPublicParams(8)

	xs := make([][]byte, 8)
	for i := range xs {
		xs[i] = make([]byte, 32)
		_, err := rand.Read(xs[i])
		if err != nil {
			b.Fatal(err)
		}
	}

	c := Commit(pp, xs)

	x := make([]byte, 32)
	_, err := rand.Read(x)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Add(i%len(xs), x)
	}
}

type PublicParams struct {
	Generators []edwards25519.Point
}

func NewPublicParams(n int) PublicParams {
	suite := edwards25519.SuiteEd25519{}

	generators := make([]edwards25519.Point, n)

	randBytes := suite.RandomStream()

	for i := 0; i < n; i++ {
		generators[i].Pick(randBytes)
	}

	return PublicParams{
		Generators: generators,
	}
}

type Commitment struct {
	generators []edwards25519.Point
	c          edwards25519.Point
}

func Commit(pp PublicParams, xs [][]byte) Commitment {
	for i := 0; i < len(xs); i++ {
		if len(xs[i]) != 32 {
			panic("input length must be 32 bytes")
		}
	}

	var c Commitment
	c.generators = pp.Generators
	c.c = edwards25519.Point{}
	c.c.Null()

	for i := 0; i < len(xs); i++ {
		c.Add(i, xs[i])
	}

	return c
}

func (c Commitment) Sub(i int, x []byte) {
	if len(x) != 32 {
		panic("input length must be 32 bytes")
	}

	var scalar edwards25519.Scalar
	scalar.SetBytes(x)

	var toAdd edwards25519.Point
	toAdd.Mul(&scalar, &c.generators[i])
	toAdd.Neg(&toAdd)

	c.c.Add(&toAdd, &c.c)
}

func (c Commitment) Add(i int, x []byte) {
	if len(x) != 32 {
		panic("input length must be 32 bytes")
	}

	var scalar edwards25519.Scalar
	scalar.SetBytes(x)

	var toAdd edwards25519.Point
	toAdd.MulPlain(&scalar, &c.generators[i])

	c.c.AddPlain(&toAdd, &c.c)
}
