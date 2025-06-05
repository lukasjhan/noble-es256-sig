import { p256 } from "@noble/curves/p256";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

const jwk = {
  kty: "EC",
  d: "hUQznqxINndxBHI8hMHvQmgSjYOCSqLUwMtzWCrh4ow",
  use: "sig",
  crv: "P-256",
  x: "ifSgGMkEIEDPsxFxdOjeJxhYsz0STsTT5bni_MXNEJs",
  y: "viFDEvB61K6zuj2iq23j0FCmVYYQ8tGJ_3f35XXUDZ0",
  alg: "ES256",
};

// Base64Url 문자열을 Uint8Array로 변환하는 함수
function fromBase64Url(base64Url: string) {
  let base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  // 패딩 추가
  let pad = base64.length % 4;
  if (pad) {
    if (pad === 2) base64 += "==";
    else if (pad === 3) base64 += "=";
  }
  const raw = atob(base64);
  const uint8Array = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    uint8Array[i] = raw.charCodeAt(i);
  }
  return uint8Array;
}

const pkey = fromBase64Url(jwk.d);
const isKeyValid = p256.utils.isValidPrivateKey(pkey);
console.log({ isKeyValid });

function toUTF8Array(str: string) {
  const utf8: Array<number> = [];
  for (let i = 0; i < str.length; i++) {
    let charcode = str.charCodeAt(i);
    if (charcode < 0x80) utf8.push(charcode);
    else if (charcode < 0x800) {
      utf8.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f));
    } else if (charcode < 0xd800 || charcode >= 0xe000) {
      utf8.push(
        0xe0 | (charcode >> 12),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f)
      );
    }
    // surrogate pair
    else {
      i++;
      // UTF-16 encodes 0x10000-0x10FFFF by
      // subtracting 0x10000 and splitting the
      // 20 bits of 0x0-0xFFFFF into two halves
      charcode =
        0x10000 + (((charcode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
      utf8.push(
        0xf0 | (charcode >> 18),
        0x80 | ((charcode >> 12) & 0x3f),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f)
      );
    }
  }
  return new Uint8Array(utf8);
}

export const sha256 = (text: string): Uint8Array => {
  const uint8Array = toUTF8Array(text);
  const hashBytes = nobleSha256(uint8Array);
  return hashBytes;
};

const priv = p256.utils.randomPrivateKey();
const pub = p256.getPublicKey(priv);
const msg = new Uint8Array(32).fill(1); // message hash (not message) in ecdsa
const sig = p256.sign(msg, priv); // `{prehash: true}` option is available
const isValid = p256.verify(sig, msg, pub) === true;
console.log(isValid);
