// simple crypto bridge between crypto/elliptic and what's needed for PVSS
package main

import (
    "crypto/elliptic"
    "crypto/rand"
    "math/big"
    "fmt"
    "encoding/hex"
)

var fakeRandom = true

type Scalar struct {
    data []byte
}

type Point struct {
    x *big.Int
    y *big.Int
}

type DhSecret struct {
    data []byte // pre-form of an actual DH secret on elliptic curve
}

type KeyPair struct {
    private Scalar
    public Point
}

func (s Scalar) String() string {
    bi := s.toInt()
    return fmt.Sprintf("Scalar %s", bi.String())
}

func (p Point) String() string {
    return fmt.Sprintf("Point {x = %d,y = %d}", p.x, p.y)
}

func (dh DhSecret) String() string {
    return hex.EncodeToString(dh.data)
}

// hardcoded choice of curve
func getCurve() elliptic.Curve {
    return elliptic.P256()
}

func getCurveParams() *elliptic.CurveParams {
    return getCurve().Params()
}

func keypairGen() KeyPair {
    if fakeRandom {
        priv := new (Scalar).fromSmallInt(1)
        pub  := priv.toPoint()
        return KeyPair { *priv, pub }
    } else {
        priv, x, y, _ := elliptic.GenerateKey(getCurve(), rand.Reader)
        return KeyPair { Scalar { priv }, Point { x, y } }
    }
}

func (s Scalar) toInt() *big.Int {
    return new(big.Int).SetBytes(s.data)
}

func (s *Scalar) fromInt(bi *big.Int) *Scalar {
    order   := getCurveParams().N
    bitSize := getCurveParams().BitSize
    if bi.Cmp(big.NewInt(0)) == -1 {
        bi.Add(bi, order)
    }
    b       := bi.Bytes()
    blen    := cap(b)
    nbBytes := bitSize / 8
    switch {
    case blen == nbBytes: // expected size already
        s.data = b
    case blen < nbBytes: // complete with 0
        s.data = make([]byte, nbBytes)
        copy(s.data[nbBytes - blen:], b)
    }
    return s
}

func (s *Scalar) fromSmallInt(i int) *Scalar {
    bi := big.NewInt(int64(i))
    return s.fromInt(bi)
}

func (s *Scalar) Add(a *Scalar, b *Scalar) *Scalar {
    r  := new (big.Int).Add(a.toInt(),b.toInt())
    r2 := r.Mod(r, getCurveParams().N)
    s.fromInt(r2)
    return s
}

func (s *Scalar) Mul(a *Scalar, b *Scalar) *Scalar {
    r  := new (big.Int).Mul(a.toInt(),b.toInt())
    r2 := r.Mod(r, getCurveParams().N)
    s.fromInt(r2)
    return s
}

func (s *Scalar) Inverse(a *Scalar) *Scalar {
    bi  := a.toInt()
    inv := bi.ModInverse(bi, getCurveParams().N)
    s.fromInt(inv)
    return s
}

// lift to curve a scalar
func (s *Scalar) toPoint() Point {
    x,y := getCurve().ScalarBaseMult(s.data)
    return (Point { x, y })
}

func (p *Point) Add(a *Point, b *Point) *Point{
    r := new(Point)
    r.x, r.y = getCurve().Add(a.x, a.y, b.x, b.y)
    return r
}

func PointMul(p *Point, s *Scalar) *Point {
    r := new(Point)
    r.x, r.y = getCurve().ScalarMult(p.x, p.y, s.data)
    return r
}

// same as PointMul, but multiply by the modular inverse
func PointDiv(p *Point, s *Scalar) *Point {
    sInv := new (Scalar).Inverse(s)
    return PointMul(p, sInv)
}

func (p *Point) ToDhSecret() DhSecret {
    return DhSecret {p.x.Bytes()}
}
