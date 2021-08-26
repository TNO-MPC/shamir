# TNO MPC Lab - Shamir Secret Sharing

The TNO MPC lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of MPC solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed MPC functionalities to boost the development of new protocols and solutions.

The package shamir is part of the TNO Go Toolbox.

*Limitations in (end-)use: the content of this repository may solely be used for applications that comply with international export control laws.*

## Secret sharing library in Go

This library implements Shamir secret sharing over finite fields and secret sharing over the integers for integers.
In addition, facilities are offered to perform computations on shares of secrets.

### Shamir secret sharing

For an explanation of Shamir secret sharing over finite fields, refer to [Wikipedia](https://en.wikipedia.org/wiki/Shamir's_Secret_Sharing).

Suppose you'd like to share a secret `123` over the finite field of integers modulo 7919. You want to have 5 shares of which 4 are needed for reconstruction of the secret. In this case, you choose a sharing degree of 3.
```go
shares := ShareFiniteField(big.NewInt(123), big.NewInt(7919), 3, 5)
```
You can then reconstruct the secret by saying
```go
secret, err := SecretShareCombine(shares[0:4])
// secret is a big.Int containing 123
```

### Addition of secret shares

If you have two secrets `123` and `456`, and you would like to share these and compute the sum `123+456` as a group, you would send share n of `123` and share n of `456` to friend n for `0 < n < 5`, and keep shares 0 to yourself. Then each friend (and you) do
```go
sumShareN, err := ShareAdd([]SecretShare{firstShareN, secondShareN})
```
Then, you may `SecretShareCombine` the `sumShare`s to recover `579`.

### Multiplication of secret shares

In the same way, you can compute the product `123*456` by sharing them both and having all of your friends call `ShareMul`. Note that if your secrets are shared with degree `t`, you will need at least `2t+1` shares to recover the shared product (`k*t+1` shares for a product of `k` factors). For a group of five friends and two factors, this limits the degree to `t = 2`.

### Secret sharing over the integers

If you share secrets over a finite field, your computations might wrap around. If you do not want this, you can secret share over the integers instead. Note that while Shamir secret sharing is information theoretically secure, sharing over the integers is not, and provides instead a configurable `sigma` bits of statistical security.

To share `123` over the integers, with 100 bits of statistical security, write
```go
shares := ShareIntegers(big.NewInt(123), big.NewInt(10000), 100, 3, 5)
```
Here, 10000 is the upper bound on the secret you are sharing.
