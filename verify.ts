import j from "jsonwebtoken";
import { createPublicKey } from "crypto";

const jwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dlbWluaS5nb29nbGUuY29tIiwic3ViIjoidXNlci0xMjM0NSIsIm5hbWUiOiJHZW1pbmkgQUkiLCJpYXQiOjE3NDkxMDg4NzMsImV4cCI6MTc0OTExMjQ3M30.iwkvrEVOagtJIuK43wfsZc-NsVOSxGStpaGXOG6OWSsQXExLXWauD2go2srRe9aXKF1flDPpfky9oftL-EEVHw";

// JWK for public key
const jwk = {
  kty: "EC",
  use: "sig",
  crv: "P-256",
  x: "ifSgGMkEIEDPsxFxdOjeJxhYsz0STsTT5bni_MXNEJs",
  y: "viFDEvB61K6zuj2iq23j0FCmVYYQ8tGJ_3f35XXUDZ0",
  alg: "ES256",
};

// First import the JWK to obtain a CryptoKey
async function verifyJwt() {
  try {
    const publicKey = createPublicKey({ key: jwk, format: "jwk" });
    const a = j.verify(jwt, publicKey);
    console.log(a);
  } catch (err) {
    console.error("JWT verification failed:", err);
  }
}

verifyJwt();
