// Copyright 2021 TNO
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shamir

// Package secret implements Shamir secret sharing over finite fields and secret sharing over the integers for integers.
// In addition, facilities are offered to perform computations on shares of secrets.

import (
	"crypto/rand"
	"errors"
	"math/big"
)

var (
	ErrorNoShares           = errors.New("Empty share slice given")
	ErrorTooFewShares       = errors.New("Too few shares given")
	ErrorIncompatibleShares = errors.New("Attempted to combine shares with different parameters")
	ErrorFractionalSecret   = errors.New("Reconstruction of the secret failed")
)

// A Share is a share of a secret. If FieldSize == nil, it is a share over the integers, otherwise
// it is a Shamir secret share over a finite field.
type Share struct {
	FieldSize *big.Int
	Factor    *big.Int
	Degree    int
	X         int
	Y         *big.Int
}

// ShareFiniteField shares a secret over a finite field of integers modulo fieldSize.
// The caller must ensure that fieldSize is prime.
// It produces a configurable number of shares using a polynomial of given degree. Note that
// degree+1 shares are required for reconstruction of the secret.
func ShareFiniteField(secret *big.Int, fieldSize *big.Int, degree int, nShares int) []Share {
	coefficients := make([]*big.Int, degree)
	for i := range coefficients {
		coefficients[i], _ = rand.Int(rand.Reader, fieldSize)
	}
	shares := make([]Share, nShares)
	for i := range shares {
		shares[i].FieldSize = fieldSize
		shares[i].Degree = degree
		shares[i].X = i + 1
		shares[i].Y = big.NewInt(0).Set(secret)
		// compute f(i) == secret + sum(j) coeff[j] i^(j+1)
		for j := range coefficients {
			term := big.NewInt(int64(i + 1))
			term.Exp(term, big.NewInt(int64(j+1)), nil)
			term.Mul(term, coefficients[j])
			shares[i].Y.Add(shares[i].Y, term)
		}
		shares[i].Y.Mod(shares[i].Y, fieldSize)
	}
	return shares
}

// ShareIntegers shares a secret over the integers. It requires a known upper bound on the secret
// and will provide statSecParam bits of statistical security.
// It produces a configurable number of shares using a polynomial of given degree. Note that
// degree+1 shares are required for reconstruction of the secret.
func ShareIntegers(secret *big.Int, secretUpperBound *big.Int, statSecParam int, degree int, nShares int) []Share {
	coefficientUpperBound := big.NewInt(2)
	coefficientUpperBound.
		Exp(coefficientUpperBound, big.NewInt(int64(statSecParam)), nil).
		Mul(coefficientUpperBound, big.NewInt(int64(nShares*nShares))).
		Mul(coefficientUpperBound, secretUpperBound)

	coefficients := make([]*big.Int, degree)
	for i := range coefficients {
		coefficients[i], _ = rand.Int(rand.Reader, coefficientUpperBound)
	}

	shares := make([]Share, nShares)
	nFactorial := factorial(int64(nShares))
	secret = big.NewInt(0).Mul(secret, nFactorial)
	for i := range shares {
		shares[i].Degree = degree
		shares[i].Factor = nFactorial
		shares[i].X = i + 1
		shares[i].Y = big.NewInt(0).Set(secret)
		// compute f(i) == secret + sum(j) coeff[j] i^(j+1)
		for j := range coefficients {
			term := big.NewInt(int64(i + 1))
			term.Exp(term, big.NewInt(int64(j+1)), nil)
			term.Mul(term, coefficients[j])
			shares[i].Y.Add(shares[i].Y, term)
		}
	}
	return shares
}

// ShareCombine combines a set of shares of the same secret and recovers the secret.
// If too few shares are given, or the shares are incompatible, an error is returned instead.
func ShareCombine(shares []Share) (*big.Int, error) {
	// Check that we have enough shares and that they're compatible
	if len(shares) == 0 {
		return nil, ErrorNoShares
	}
	if len(shares) <= shares[0].Degree {
		return nil, ErrorTooFewShares
	}
	for i := 1; i != len(shares); i++ {
		if !equalOrBothNil(shares[0].FieldSize, shares[i].FieldSize) || shares[0].Degree != shares[i].Degree {
			return nil, ErrorIncompatibleShares
		}
	}

	// Reconstruct the secret using en.wikipedia.org/wiki/Shamir's_Secret_Sharing#Computationally_efficient_approach
	secret := big.NewRat(0, 1)
	term := big.NewRat(0, 1)
	for i := 0; i <= shares[0].Degree; i++ {
		term.SetInt(shares[i].Y)
		for j := 0; j <= shares[0].Degree; j++ {
			if i == j {
				continue
			}
			term.Mul(term, big.NewRat(int64(shares[j].X), int64(shares[j].X-shares[i].X)))
		}
		secret.Add(secret, term)
	}

	if shares[0].FieldSize != nil {
		// Rationals auto-normalize, but can't take into account the inversion rules in
		// a finite field. We have to do this manually.

		return big.NewInt(0).Mod(secret.Num().Mul(
			secret.Num(),
			secret.Denom().ModInverse(secret.Denom(), shares[0].FieldSize),
		), shares[0].FieldSize), nil
	} else {
		// If incompatible shares were used, this will result in a non-integer
		if !secret.IsInt() {
			return nil, ErrorFractionalSecret
		}
		// Rationals auto-normalize, so if it's integer, we can just use the numerator
		return big.NewInt(0).Div(secret.Num(), shares[0].Factor), nil
	}

}

// ShareAdd adds shares of two secrets to produce a share of the sum of the secrets.
// It requires a set of shares with equal X values, degrees, and field sizes.
func ShareAdd(shares []Share) (Share, error) {
	if len(shares) == 0 {
		return Share{}, ErrorNoShares
	}
	sum := Share{
		FieldSize: shares[0].FieldSize,
		Degree:    shares[0].Degree,
		Factor:    shares[0].Factor,
		X:         shares[0].X,
		Y:         big.NewInt(0).Set(shares[0].Y),
	}
	for i := 1; i != len(shares); i++ {
		if !equalOrBothNil(shares[0].FieldSize, shares[i].FieldSize) || shares[0].Degree != shares[i].Degree || shares[0].X != shares[i].X {
			return Share{}, ErrorIncompatibleShares
		}
		sum.Y.Add(sum.Y, shares[i].Y)
		if sum.FieldSize != nil {
			sum.Y.Mod(sum.Y, sum.FieldSize)
		}
	}
	return sum, nil
}

// ShareMul multiplies shares of two secrets to produce a share of the product of the secrets.
// It requires a set of shares with equal X values, degrees, and field sizes.
// Note that the degree of the product is the sum of the degrees of the factors.
func ShareMul(shares []Share) (Share, error) {
	if len(shares) == 0 {
		return Share{}, ErrorNoShares
	}
	sum := Share{
		FieldSize: shares[0].FieldSize,
		Degree:    shares[0].Degree,
		X:         shares[0].X,
		Y:         big.NewInt(0).Set(shares[0].Y),
	}
	if shares[0].Factor != nil {
		sum.Factor = big.NewInt(0).Set(shares[0].Factor)
	}
	for i := 1; i != len(shares); i++ {
		if !equalOrBothNil(shares[0].FieldSize, shares[i].FieldSize) || shares[0].Degree != shares[i].Degree || shares[0].X != shares[i].X {
			return Share{}, ErrorIncompatibleShares
		}
		sum.Y.Mul(sum.Y, shares[i].Y)
		if sum.FieldSize != nil {
			sum.Y.Mod(sum.Y, sum.FieldSize)
		}
		sum.Degree += shares[i].Degree
		if sum.Factor != nil {
			sum.Factor.Mul(sum.Factor, shares[i].Factor)
		}
	}
	return sum, nil
}

func equalOrBothNil(a, b *big.Int) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Cmp(b) == 0
}

func factorial(n int64) *big.Int {
	return big.NewInt(0).MulRange(1, n)
}
