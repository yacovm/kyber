package p256

import (
	"crypto/cipher"
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/internal/marshalling"
	"go.dedis.ch/kyber/v4/group/mod"
	"go.dedis.ch/kyber/v4/util/random"
)

type CurvePoint struct {
	x, y *big.Int
	C    *Curve
}

func (P *CurvePoint) String() string {
	return "(" + P.x.String() + "," + P.y.String() + ")"
}

func (P *CurvePoint) Equal(P2 kyber.Point) bool {
	cp2 := P2.(*CurvePoint) //nolint:errcheck // Design pattern to emulate generics

	// Make sure both coordinates are normalized.
	// Apparently Go's elliptic Curve code doesn't always ensure this.
	M := P.C.p.P
	P.x.Mod(P.x, M)
	P.y.Mod(P.y, M)
	cp2.x.Mod(cp2.x, M)
	cp2.y.Mod(cp2.y, M)

	return P.x.Cmp(cp2.x) == 0 && P.y.Cmp(cp2.y) == 0
}

func (P *CurvePoint) Null() kyber.Point {
	P.x = new(big.Int).SetInt64(0)
	P.y = new(big.Int).SetInt64(0)
	return P
}

func (P *CurvePoint) Base() kyber.Point {
	P.x = P.C.p.Gx
	P.y = P.C.p.Gy
	return P
}

func (P *CurvePoint) Valid() bool {
	// The IsOnCurve function in Go's elliptic Curve package
	// doesn't consider the point-at-infinity to be "on the Curve"
	return P.C.IsOnCurve(P.x, P.y) ||
		(P.x.Sign() == 0 && P.y.Sign() == 0)
}

// Try to generate a point on this Curve from a chosen x-coordinate,
// with a random sign.
func (P *CurvePoint) genPoint(x *big.Int, rand cipher.Stream) bool {
	// Compute the corresponding Y coordinate, if any
	y2 := new(big.Int).Mul(x, x)
	y2.Mul(y2, x)
	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)
	y2.Sub(y2, threeX)
	y2.Add(y2, P.C.p.B)
	y2.Mod(y2, P.C.p.P)
	y := P.C.sqrt(y2)

	// Pick a random sign for the y coordinate
	b := make([]byte, 1)
	rand.XORKeyStream(b, b)
	if (b[0] & 0x80) != 0 {
		y.Sub(P.C.p.P, y)
	}

	// Check that it's a valid point
	y2t := new(big.Int).Mul(y, y)
	y2t.Mod(y2t, P.C.p.P)
	if y2t.Cmp(y2) != 0 {
		return false // Doesn't yield a valid point!
	}

	P.x = x
	P.y = y
	return true
}

func (P *CurvePoint) EmbedLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (P.C.p.P.BitLen() - 8 - 8) / 8
}

func (P *CurvePoint) Pick(rand cipher.Stream) kyber.Point {
	return P.Embed(nil, rand)
}

// Embed picks a Curve point containing a variable amount of embedded data.
// Remaining bits comprising the point are chosen randomly.
func (P *CurvePoint) Embed(data []byte, rand cipher.Stream) kyber.Point {
	l := P.C.coordLen()
	dl := P.EmbedLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		b := random.Bits(uint(P.C.p.P.BitLen()), false, rand)
		if data != nil {
			b[l-1] = byte(dl)         // Encode length in low 8 bits
			copy(b[l-dl-1:l-1], data) // Copy in data to embed
		}
		if P.genPoint(new(big.Int).SetBytes(b), rand) {
			return P
		}
	}
}

// Data extracts embedded data from a Curve point
func (P *CurvePoint) Data() ([]byte, error) {
	b := P.x.Bytes()
	l := P.C.coordLen()
	if len(b) < l { // pad leading zero bytes if necessary
		b = append(make([]byte, l-len(b)), b...)
	}
	dl := int(b[l-1])
	if dl > P.EmbedLen() {
		return nil, errors.New("invalid embedded data length")
	}
	return b[l-dl-1 : l-1], nil
}

func (P *CurvePoint) Add(A, B kyber.Point) kyber.Point {
	ca := A.(*CurvePoint) //nolint:errcheck // Design pattern to emulate generics
	cb := B.(*CurvePoint) //nolint:errcheck // Design pattern to emulate generics
	P.x, P.y = P.C.Add(ca.x, ca.y, cb.x, cb.y)
	return P
}

func (P *CurvePoint) AddPlain(A, B *CurvePoint) {
	ca := A //nolint:errcheck // Design pattern to emulate generics
	cb := B //nolint:errcheck // Design pattern to emulate generics
	P.x, P.y = P.C.Add(ca.x, ca.y, cb.x, cb.y)
}

func (P *CurvePoint) Sub(A, B kyber.Point) kyber.Point {
	ca := A.(*CurvePoint) //nolint:errcheck // Design pattern to emulate generics
	cb := B.(*CurvePoint) //nolint:errcheck // Design pattern to emulate generics

	cbn := P.C.Point().Neg(cb).(*CurvePoint) //nolint:errcheck // Design pattern to emulate generics
	P.x, P.y = P.C.Add(ca.x, ca.y, cbn.x, cbn.y)
	return P
}

func (P *CurvePoint) Neg(A kyber.Point) kyber.Point {
	s := P.C.Scalar().One()
	s.Neg(s)
	return P.Mul(s, A).(*CurvePoint)
}

func (P *CurvePoint) Mul(s kyber.Scalar, B kyber.Point) kyber.Point {
	cs := s.(*mod.Int) //nolint:errcheck // Design pattern to emulate generics
	if B != nil {
		cb := B.(*CurvePoint) //nolint:errcheck // Design pattern to emulate generics
		P.x, P.y = P.C.ScalarMult(cb.x, cb.y, cs.V.Bytes())
	} else {
		P.x, P.y = P.C.ScalarBaseMult(cs.V.Bytes())
	}
	return P
}

func (P *CurvePoint) MulPlain(s *mod.Int, B *CurvePoint) {
	cs := s //nolint:errcheck // Design pattern to emulate generics
	if B != nil {
		cb := B //nolint:errcheck // Design pattern to emulate generics
		P.x, P.y = P.C.ScalarMult(cb.x, cb.y, cs.V.Bytes())
	} else {
		P.x, P.y = P.C.ScalarBaseMult(cs.V.Bytes())
	}
}

func (P *CurvePoint) MarshalSize() int {
	coordlen := (P.C.Params().BitSize + 7) >> 3
	return 1 + 2*coordlen // uncompressed ANSI X9.62 representation
}

func (P *CurvePoint) MarshalBinary() ([]byte, error) {
	return elliptic.Marshal(P.C, P.x, P.y), nil
}

func (P *CurvePoint) UnmarshalBinary(buf []byte) error {
	// Check whether all bytes after first one are 0, so we
	// just return the initial point. Read everything to
	// prevent timing-leakage.
	var c byte
	for _, b := range buf[1:] {
		c |= b
	}
	if c != 0 {
		P.x, P.y = elliptic.Unmarshal(P.C, buf)
		if P.x == nil || !P.Valid() {
			return errors.New("invalid elliptic Curve point")
		}
	} else {
		// All bytes are 0, so we initialize x and y
		P.x = big.NewInt(0)
		P.y = big.NewInt(0)
	}
	return nil
}

func (P *CurvePoint) MarshalTo(w io.Writer) (int, error) {
	return marshalling.PointMarshalTo(P, w)
}

func (P *CurvePoint) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(P, r)
}

// interface for Curve-specifc mathematical functions
type curveOps interface {
	sqrt(y *big.Int) *big.Int
}

// Curve is an implementation of the kyber.Group interface
// for NIST elliptic curves, built on Go's native elliptic Curve library.
type Curve struct {
	elliptic.Curve
	curveOps
	p *elliptic.CurveParams
}

// Return the number of bytes in the encoding of a Scalar for this Curve.
func (c *Curve) ScalarLen() int { return (c.p.N.BitLen() + 7) / 8 }

// Create a Scalar associated with this Curve. The scalars created by
// this package implement kyber.Scalar's SetBytes method, interpreting
// the bytes as a big-endian integer, so as to be compatible with the
// Go standard library's big.Int type.
func (c *Curve) Scalar() kyber.Scalar {
	return mod.NewInt64(0, c.p.N)
}

// Number of bytes required to store one coordinate on this Curve
func (c *Curve) coordLen() int {
	return (c.p.BitSize + 7) / 8
}

// Return the number of bytes in the encoding of a Point for this Curve.
// Currently uses uncompressed ANSI X9.62 format with both X and Y coordinates;
// this could change.
func (c *Curve) PointLen() int {
	return 1 + 2*c.coordLen() // ANSI X9.62: 1 header byte plus 2 coords
}

// Create a Point associated with this Curve.
func (c *Curve) Point() kyber.Point {
	p := new(CurvePoint)
	p.C = c
	return p
}

// Create a Point associated with this Curve.
func (c *Curve) PointPlain() CurvePoint {
	p := new(CurvePoint)
	p.C = c
	return *p
}

func (P *CurvePoint) Set(A kyber.Point) kyber.Point {
	P.x = A.(*CurvePoint).x
	P.y = A.(*CurvePoint).y
	return P
}

func (P *CurvePoint) Clone() kyber.Point {
	return &CurvePoint{x: P.x, y: P.y, C: P.C}
}

// Return the order of this Curve: the prime N in the Curve parameters.
func (c *Curve) Order() *big.Int {
	return c.p.N
}
