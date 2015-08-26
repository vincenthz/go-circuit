// 
// Implementation of the Public Verifiable Secret Scheme
// based on Berry Schoenmakers's paper:
//
//     <http://www.win.tue.nl/~berry/papers/crypto99.pdf>
//
// TODO: Only implement Shamir's Secret Sharing for now,
//       NIZK proofs, commitments and share verifications
//       are future works after the UI part is done
package main

import (
    "fmt"
    "math/big"
)

type ShareId int

type EncryptedShare struct {
    sid          ShareId
    encryptedVal Point
}

type DecryptedShare struct {
    sid          ShareId
    decryptedVal Point
}

type EvalPoint struct {
    p Point
}

// create a set of n shares, one for each participant, that can be recombined
// with threshold shares are available. Each share is encrypted to the participant
// public key (i.e. a Point).
//
// Along with the encrypted shares, a brand random DhSecret is returned that
// can be used to derived a symmetric key (ECIES like)
func escrow(threshold int, participants []Point) (DhSecret, []EncryptedShare) {
    poly  := polynomialGen(threshold)
    dh    := poly.A[0].toPoint()
    dhsec := dh.ToDhSecret()

    fmt.Println(poly)

    shares := make ([]EncryptedShare, len(participants))
    for p := 0; p < len(participants); p++ {
        // evaluate polynomial at x = p+1 and encrypt the value to the
        // public key (Point) associated with the participant
        evalVal   := poly.evaluate(big.NewInt(int64(p+2)))
        key       := participants[p]
        yi        := PointMul(&key, &evalVal)
        eshare    := EncryptedShare { ShareId(p+2), *yi }
        shares[p] = eshare
    }
    return dhsec, shares
}

// decrypt share take an encrypted share and decrypt the share using
// the owner private key
func (share *EncryptedShare) decryptShare(priv *Scalar) DecryptedShare {
    decryptedVal := PointDiv(&share.encryptedVal, priv)
    return DecryptedShare { share.sid, *decryptedVal }
}

// pool a bunch of decrypted share 
func pool(shares []DecryptedShare) DhSecret {
    var v *Point

    fmt.Println("pool with", len(shares))

    // lagrange interpolation at x=0
    for j := 0; j < len(shares); j++ {

        // calculate lagrange basis polynomial lj(0)
        r := new(Scalar).fromSmallInt(1)
        for m := 0; m < len(shares); m++ {
            if j != m {
                // calculate factor x_m / (x_m - x_j)
                num   := new (Scalar).fromSmallInt(int(shares[m].sid))
                denum := new (Scalar).fromSmallInt(int(shares[m].sid) - int(shares[j].sid))
                dinv  := denum.Inverse(denum)
                t     := new (Scalar).Mul(num, dinv)
                // append to product
                r     = r.Mul(r, t)
            }
        }
        p := PointMul(&shares[j].decryptedVal, r)

        // fold into the current calculation
        if v == nil {
            v = p
        } else {
            v = v.Add(v, p)
        }
    }
    return v.ToDhSecret()
}
