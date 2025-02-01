package vc

import (
	"crypto/rand"
	"go.dedis.ch/kyber/v4/group/mod"
	"go.dedis.ch/kyber/v4/group/p256"
	"math/big"
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
	Generators []p256.CurvePoint
}

func NewPublicParams(n int) PublicParams {
	suite := p256.Suite128{}
	suite.Init()

	generators := make([]p256.CurvePoint, n)
	for i := range generators {
		generators[i] = suite.PointPlain()
	}

	randBytes := suite.RandomStream()

	for i := 0; i < n; i++ {
		generators[i].Pick(randBytes)
	}

	return PublicParams{
		Generators: generators,
	}
}

type Commitment struct {
	generators []p256.CurvePoint
	c          p256.CurvePoint
	suite      *p256.Suite128
}

func Commit(pp PublicParams, xs [][]byte) Commitment {
	for i := 0; i < len(xs); i++ {
		if len(xs[i]) != 32 {
			panic("input length must be 32 bytes")
		}
	}

	var c Commitment
	c.generators = pp.Generators

	suite := p256.Suite128{}
	suite.Init()
	c.suite = &suite

	c.c = suite.PointPlain()
	c.c.Null()

	for i := 0; i < len(xs); i++ {
		c.Add(i, xs[i])
	}

	return c
}

func (c Commitment) Add(i int, x []byte) {
	if len(x) != 32 {
		panic("input length must be 32 bytes")
	}

	var scalar mod.Int
	scalar.Init64(1, big.NewInt(1))
	scalar.SetBytes(x)

	toAdd := c.suite.PointPlain()
	toAdd.MulPlain(&scalar, &c.generators[i])

	c.c.AddPlain(&toAdd, &c.c)
}
