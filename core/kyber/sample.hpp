#pragma once
// fips 203 section 4.2.2

#include "crypto/bytes.hpp"
#include "kyber/poly.hpp"

namespace pqs::kyber {

// alg 7 samplentt of rho, j, i, uniform poly already in ntt form, used for the matrix a hat
Poly sample_ntt(ByteView rho, std::uint8_t j, std::uint8_t i);

// alg 8 samplepolycbd eta, noise poly between minus eta and eta from 64 times eta prf bytes
Poly sample_poly_cbd(int eta, ByteView bytes);

// prf eta of s, b is shake256 of s then b, 64 times eta bytes, eq 4.3
Bytes prf(int eta, ByteView s, std::uint8_t b);

}
