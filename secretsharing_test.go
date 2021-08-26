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

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShamirSecretSharing(t *testing.T) {
	assert := assert.New(t)
	shares := ShareFiniteField(big.NewInt(123), big.NewInt(7919), 3, 5)

	var secret *big.Int
	var err error

	secret, err = ShareCombine(nil)
	assert.Nil(secret)
	assert.Equal(ErrorNoShares, err)

	secret, err = ShareCombine([]Share{})
	assert.Nil(secret)
	assert.Equal(ErrorNoShares, err)

	secret, err = ShareCombine(shares[0:3])
	assert.Nil(secret)
	assert.Equal(ErrorTooFewShares, err)

	secret, err = ShareCombine(shares[0:4])
	assert.NoError(err)
	if assert.NotNil(secret) {
		assert.Equal(int64(123), secret.Int64())
	}

	secret, err = ShareCombine(shares[1:5])
	assert.NoError(err)
	if assert.NotNil(secret) {
		assert.Equal(int64(123), secret.Int64())
	}
}

func TestShamirSecretAddition(t *testing.T) {
	assert := assert.New(t)
	shares1 := ShareFiniteField(big.NewInt(123), big.NewInt(7919), 3, 4)
	shares2 := ShareFiniteField(big.NewInt(456), big.NewInt(7919), 3, 4)

	var err error
	for i := range shares1 {
		shares1[i], err = ShareAdd([]Share{shares1[i], shares2[i]})
		assert.NoError(err)
	}

	secret, err := ShareCombine(shares1)
	assert.NoError(err)
	if assert.NotNil(secret) {
		assert.Equal(int64(579), secret.Int64())
	}
}

func TestShamirSecretMultiplication(t *testing.T) {
	assert := assert.New(t)
	shares1 := ShareFiniteField(big.NewInt(-123), big.NewInt(7919), 2, 5)
	shares2 := ShareFiniteField(big.NewInt(456), big.NewInt(7919), 2, 5)

	var err error
	for i := range shares1 {
		shares1[i], err = ShareMul([]Share{shares1[i], shares2[i]})
		assert.NoError(err)
	}

	secret, err := ShareCombine(shares1)
	answer := big.NewInt(-123)
	answer.Mul(answer, big.NewInt(456)).Mod(answer, big.NewInt(7919))
	assert.NoError(err)
	if assert.NotNil(secret) {
		assert.Equal(answer.Int64(), secret.Int64())
	}
}

func TestIntegerSecretSharing(t *testing.T) {
	assert := assert.New(t)
	shares := ShareIntegers(big.NewInt(123), big.NewInt(10000), 100, 3, 5)

	var secret *big.Int
	var err error

	secret, err = ShareCombine(nil)
	assert.Nil(secret)
	assert.Equal(ErrorNoShares, err)

	secret, err = ShareCombine([]Share{})
	assert.Nil(secret)
	assert.Equal(ErrorNoShares, err)

	secret, err = ShareCombine(shares[0:3])
	assert.Nil(secret)
	assert.Equal(ErrorTooFewShares, err)

	secret, err = ShareCombine(shares[0:4])
	assert.NoError(err)
	if assert.NotNil(secret) {
		assert.Equal(int64(123), secret.Int64())
	}

	secret, err = ShareCombine(shares[1:5])
	assert.NoError(err)
	if assert.NotNil(secret) {
		assert.Equal(int64(123), secret.Int64())
	}
}

func TestIntegerSecretAddition(t *testing.T) {
	assert := assert.New(t)
	shares1 := ShareIntegers(big.NewInt(123), big.NewInt(10000), 100, 3, 4)
	shares2 := ShareIntegers(big.NewInt(456), big.NewInt(10000), 100, 3, 4)

	var err error
	for i := range shares1 {
		shares1[i], err = ShareAdd([]Share{shares1[i], shares2[i]})
		assert.NoError(err)
	}

	secret, err := ShareCombine(shares1)
	assert.NoError(err)
	if assert.NotNil(secret) {
		assert.Equal(int64(579), secret.Int64())
	}
}

func TestIntegerSecretMultiplication(t *testing.T) {
	assert := assert.New(t)
	shares1 := ShareIntegers(big.NewInt(-123), big.NewInt(10000), 100, 2, 5)
	shares2 := ShareIntegers(big.NewInt(456), big.NewInt(10000), 100, 2, 5)

	var err error
	for i := range shares1 {
		shares1[i], err = ShareMul([]Share{shares1[i], shares2[i]})
		assert.NoError(err)
	}

	secret, err := ShareCombine(shares1)

	assert.NoError(err)
	if assert.NotNil(secret) {
		assert.Equal(int64(-123*456), secret.Int64())
	}
}

func TestErrors(t *testing.T) {
	assert := assert.New(t)

	var err error

	_, err = ShareAdd([]Share{})
	assert.Equal(ErrorNoShares, err)

	_, err = ShareMul([]Share{})
	assert.Equal(ErrorNoShares, err)

	shares1 := ShareFiniteField(big.NewInt(-123), big.NewInt(1234), 2, 5)
	shares2 := ShareFiniteField(big.NewInt(456), big.NewInt(7919), 2, 5)

	for i := range shares1 {
		_, err = ShareAdd([]Share{shares1[i], shares2[i]})
		assert.Equal(ErrorIncompatibleShares, err)
	}

	for i := range shares1 {
		_, err = ShareMul([]Share{shares1[i], shares2[i]})
		assert.Equal(ErrorIncompatibleShares, err)
	}

	shares1[0].FieldSize = nil
	_, err = ShareCombine(shares1)
	assert.Equal(ErrorIncompatibleShares, err)

	shares3 := ShareIntegers(big.NewInt(456), big.NewInt(7919), 100, 2, 5)
	shares3[0].X = 500
	_, err = ShareCombine(shares3)
	assert.Equal(ErrorFractionalSecret, err)
}
