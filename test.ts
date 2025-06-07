import { p256 } from "@noble/curves/p256";
import { jwtVerify } from "jose";
import { sha256 } from "@sd-jwt/hash";
import { base64urlEncode, uint8ArrayToBase64Url } from "@sd-jwt/utils";
import { Base64 } from "js-base64";

/**
 * Encodes a JSON object to a Base64URL string.
 * @param data JSON object to encode
 * @returns Base64URL string
 */
function objectToBase64Url(data: object): string {
  const jsonString = JSON.stringify(data);
  return base64urlEncode(jsonString);
}
function fromBase64Url(base64Url: string): Uint8Array {
  return Base64.toUint8Array(base64Url);
}

const jwk = {
  kty: "EC",
  d: "hUQznqxINndxBHI8hMHvQmgSjYOCSqLUwMtzWCrh4ow",
  use: "sig",
  crv: "P-256",
  x: "ifSgGMkEIEDPsxFxdOjeJxhYsz0STsTT5bni_MXNEJs",
  y: "viFDEvB61K6zuj2iq23j0FCmVYYQ8tGJ_3f35XXUDZ0",
  alg: "ES256",
};

const pubJwk = {
  kty: "EC",
  crv: "P-256",
  x: "ifSgGMkEIEDPsxFxdOjeJxhYsz0STsTT5bni_MXNEJs",
  y: "viFDEvB61K6zuj2iq23j0FCmVYYQ8tGJ_3f35XXUDZ0",
  alg: "ES256",
};

const header = {
  alg: "ES256",
  typ: "JWT",
};

const payload = {
  iss: "https://gemini.google.com",
  sub: "user-12345",
  name: "Gemini AI",
};

async function signJwt(
  privateKeyJwkD: string,
  header: object,
  payload: object
): Promise<string> {
  const encodedHeader = objectToBase64Url(header);
  const encodedPayload = objectToBase64Url(payload);
  const pkey = fromBase64Url(privateKeyJwkD);

  const isP = p256.utils.isValidPrivateKey(pkey);
  const publicKey = p256.getPublicKey(pkey, false);
  console.log({ isP, publicKey });

  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signingInputBytes = sha256(signingInput);

  const signature = p256.sign(signingInputBytes, pkey);
  const compactSignatureBytes = signature.toCompactRawBytes();

  const encodedSignature = uint8ArrayToBase64Url(compactSignatureBytes);
  return `${signingInput}.${encodedSignature}`;
}

(async () => {
  const jwt = await signJwt(jwk.d, header, payload);
  console.log("Generated JWT:");
  console.log(jwt);

  const result = await jwtVerify(jwt, pubJwk, { algorithms: ["ES256"] });
  console.log(result);
})();
