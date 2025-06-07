import { p256 } from "@noble/curves/nist";
import { bytesToHex, numberToBytesBE } from "@noble/curves/abstract/utils";
import { uint8ArrayToBase64Url } from "@sd-jwt/utils";
import { Base64 } from "js-base64";

// 1. JWK Type Definition
export interface EcPublicJwk {
  kty: "EC";
  crv: "P-256";
  x: string; // Base64URL
  y: string; // Base64URL
  kid?: string;
}

export interface EcPrivateJwk extends EcPublicJwk {
  d: string; // Base64URL
}

// 2. Helper Functions
/**
 * Convert BigInt to 32-byte Uint8Array (left padding)
 */
function bigIntTo32Bytes(num: bigint): Uint8Array {
  const bytes = numberToBytesBE(num, 32);
  if (bytes.length > 32) {
    throw new Error("BigInt is too large for 32 bytes.");
  }
  const padded = new Uint8Array(32);
  padded.set(bytes, 32 - bytes.length);
  return padded;
}

/**
 * Convert Uint8Array to BigInt
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt(`0x${bytesToHex(bytes)}`);
}

// 3. Private Key Conversion Functions
/**
 * Convert P-256 private key (Uint8Array) to EcPrivateJwk.
 * @param privateKeyBytes 32-byte private key
 * @returns EcPrivateJwk
 */
export function privateKeyUint8ArrayToJwk(
  privateKeyBytes: Uint8Array
): EcPrivateJwk {
  if (privateKeyBytes.length !== 32) {
    throw new Error("Invalid private key length. Must be 32 bytes.");
  }

  // Derive the public key (uncompressed format).
  const publicKeyBytes = p256.getPublicKey(privateKeyBytes, false);

  const d = uint8ArrayToBase64Url(privateKeyBytes);
  const x = uint8ArrayToBase64Url(publicKeyBytes.slice(1, 33));
  const y = uint8ArrayToBase64Url(publicKeyBytes.slice(33, 65));

  return {
    kty: "EC",
    crv: "P-256",
    d,
    x,
    y,
  };
}

/**
 * Convert EcPrivateJwk to P-256 private key (Uint8Array).
 * @param jwk EcPrivateJwk object
 * @returns 32-byte private key Uint8Array
 */
export function privateKeyJwkToUint8Array(jwk: EcPrivateJwk): Uint8Array {
  if (!jwk.d) {
    throw new Error('Invalid private JWK: missing "d" parameter.');
  }
  const privateKeyBytes = Base64.toUint8Array(jwk.d);
  if (privateKeyBytes.length !== 32) {
    throw new Error('Invalid "d" parameter length. Must decode to 32 bytes.');
  }
  return privateKeyBytes;
}

// 4. Public Key Conversion Functions
/**
 * Convert P-256 public key (Uint8Array) to EcPublicJwk.
 * Supports both compressed (33 bytes) and uncompressed (65 bytes) formats.
 * @param publicKeyBytes public key
 * @returns EcPublicJwk
 */
export function publicKeyUint8ArrayToJwk(
  publicKeyBytes: Uint8Array
): EcPublicJwk {
  if (publicKeyBytes.length !== 33 && publicKeyBytes.length !== 65) {
    throw new Error(
      "Invalid public key length. Must be 33 (compressed) or 65 (uncompressed) bytes."
    );
  }

  // fromHex automatically detects compressed/uncompressed format.
  const point = p256.Point.fromHex(bytesToHex(publicKeyBytes));

  const x = uint8ArrayToBase64Url(bigIntTo32Bytes(point.x));
  const y = uint8ArrayToBase64Url(bigIntTo32Bytes(point.y));

  return {
    kty: "EC",
    crv: "P-256",
    x,
    y,
  };
}

/**
 * Convert EcPublicJwk to P-256 public key (Uint8Array).
 * @param jwk EcPublicJwk object
 * @param compressed whether to compress the output format (true) (default: false)
 * @returns public key Uint8Array
 */
export function publicKeyJwkToUint8Array(
  jwk: EcPublicJwk,
  compressed = false
): Uint8Array {
  const xBytes = Base64.toUint8Array(jwk.x);
  const yBytes = Base64.toUint8Array(jwk.y);

  // 1. Reconstruct the public key in standard uncompressed format (65 bytes).
  const uncompressedPublicKey = new Uint8Array(65);
  uncompressedPublicKey[0] = 4; // Uncompressed prefix 0x04
  uncompressedPublicKey.set(xBytes, 1);
  uncompressedPublicKey.set(yBytes, 33);

  // 2. Use the library's parser to create a Point object.
  // This method is more stable as it's not affected by internal constructor changes.
  const point = p256.Point.fromHex(bytesToHex(uncompressedPublicKey));

  // 3. Convert Point to byte array in the desired format.
  return point.toRawBytes(compressed);
}

// 5. Demo Function
async function demo() {
  console.log("--- Private Key Conversion Demo ---");
  const originalPrivateKey = p256.utils.randomPrivateKey();
  console.log("Original Private Key (Uint8Array):", originalPrivateKey);

  // Uint8Array -> Private JWK
  const privateJwk = privateKeyUint8ArrayToJwk(originalPrivateKey);
  console.log("-> Converted Private JWK:", privateJwk);

  // Private JWK -> Uint8Array
  const restoredPrivateKey = privateKeyJwkToUint8Array(privateJwk);
  console.log("-> Restored Private Key (Uint8Array):", restoredPrivateKey);

  // validation
  console.log(
    "Private Key Restoration Success:",
    bytesToHex(originalPrivateKey) === bytesToHex(restoredPrivateKey)
  );

  console.log("\n--- Public Key Conversion Demo ---");
  // uncompressed public key
  const originalUncompressedPublicKey = p256.getPublicKey(
    originalPrivateKey,
    false
  );
  console.log(
    "Original Uncompressed Public Key (Uint8Array):",
    originalUncompressedPublicKey
  );

  // Uint8Array -> Public JWK
  const publicJwk = publicKeyUint8ArrayToJwk(originalUncompressedPublicKey);
  console.log("-> Converted Public JWK:", publicJwk);

  // Public JWK -> Uint8Array (uncompressed)
  const restoredUncompressedPublicKey = publicKeyJwkToUint8Array(
    publicJwk,
    false
  );
  console.log(
    "-> Restored Uncompressed Public Key (Uint8Array):",
    restoredUncompressedPublicKey
  );
  console.log(
    "Uncompressed Public Key Restoration Success:",
    bytesToHex(originalUncompressedPublicKey) ===
      bytesToHex(restoredUncompressedPublicKey)
  );

  // Public JWK -> Uint8Array (compressed)
  const restoredCompressedPublicKey = publicKeyJwkToUint8Array(publicJwk, true);
  console.log(
    "-> Restored Compressed Public Key (Uint8Array):",
    restoredCompressedPublicKey
  );
  const originalCompressedPublicKey = p256.getPublicKey(
    originalPrivateKey,
    true
  );
  console.log(
    "Compressed Public Key Restoration Success:",
    bytesToHex(originalCompressedPublicKey) ===
      bytesToHex(restoredCompressedPublicKey)
  );
}

// Run demo
demo();
