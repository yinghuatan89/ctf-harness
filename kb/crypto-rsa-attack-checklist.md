tags: rsa, crypto, cube-root, wiener

# RSA classic attacks - ordered checklist

1. **e = 3 (or 5) + short message, no padding**: `m^3 < n` means c is exactly
   m^3 - take the integer cube root (Newton). CTF-favourite.
2. **Common modulus**: two ciphertexts of the same message under the same n
   with coprime e1,e2 - extended euclid recovers m.
3. **Wiener**: small d (d < n^(1/4)/3) - continued fractions of e/n expose
   k/d; verify with the p+q discriminant.
4. **Fermat**: p,q generated close (poor primes) - walk a = ceil(sqrt(n))
   until a^2-n is a perfect square.
5. **Common factor**: gcd(n1, n2) when the organiser reused a prime.
6. **Small prime / toy n**: trial division to 10^5 catches deliberate flaws.
7. **Related messages**: Franklin-Reiter (gcd of two polynomials) - write the
   polynomial gcd in python, no sage needed for e small.
8. **Coppersmith (small root)**: needs sage or a fpylll install - check recon
   notes whether those exist before promising it.

Always note the exact parameter set (n,e,c,d,p,q) on the blackboard first -
the harness recipe already attacks 1-6 automatically.

> AI生成
