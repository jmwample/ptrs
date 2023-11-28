//
//  elligator2.h
//  Assuming curve25519; prime p = 2^255-19; curve y^2 = x^3 + A*x^2 + x; A = 486662
//  Elliptic curve points represented as bytes. Each coordinate is 32 bytes.
//  On curve25519, always take canonical y in range 0,..,(p-1)/2. We can ignore y-coord.
//

#ifndef _elligator2_h
#define _elligator2_h

// Takes as input a 32-byte little endian string (technically 255 bits padded to 32 bytes)
// Returns 0 if string could not be decoded, i.e., does not correspond to an elliptic curve point (highly unlikely)
// If possible, outputs 32 byte x-coord of curve25519 point corresponding to input string
int _decode_c(unsigned char *out, const unsigned char *in);


// Takes as input 32 byte little endian encodable curve25519 point;
// high order bit is sign of y value
// Outputs 255-bit (little endian) uniform-looking 32-byte string
// Returns 0 if point could not be encoded as a string, returns 1 otherwise
int _encode_c(unsigned char *out, const unsigned char *in);

#endif
