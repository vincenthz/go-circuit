package main

import (
    "fmt"
    "math/big"
)

type Polynomial struct {
    A []Scalar
}

func (poly Polynomial) String() string {
    s := poly.A[0].toInt().String()
    for d := 1; d < poly.degree(); d++ {
        c := poly.A[d].toInt()
        if c.Cmp(big.NewInt(0)) != 0 {
            s = fmt.Sprintf("%s * x^%d", c.String(), d) + " + " + s
        }
    }
    return s
}

func polynomialGen(threshold int) Polynomial {
    elems := make([]Scalar, threshold)
    for i := 0; i < threshold; i++ {
        elems[i] = keypairGen().private
    }
    return Polynomial{elems}
}

func (p *Polynomial) degree() int {
    return cap(p.A)
}

// evaluate a polynomial at 'x' and returns the scalar value
func (p *Polynomial) evaluate(x *big.Int) Scalar {
    order := getCurveParams().N
    xN    := new (big.Int)
    v     := new (Scalar)

    // copy initial values
    *v = p.A[0]
    *xN = *x
    for power := 1; power < p.degree(); power++ {
        // coeff * x ^ degree
        coeff := p.A[power]
        d     := new(Scalar).Mul(&coeff, new(Scalar).fromInt(xN))

        v = v.Add(v, d)

        // get next degree value of x: xN = xN * x [order] (unless last iteration)
        //if power <= p.degree() - 1 {
            xN = xN.Mod(xN.Mul(xN, x), order)
        //}
    }
    return *v
}
