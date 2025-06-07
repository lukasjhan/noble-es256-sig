import { p256 } from "@noble/curves/nist";
import { bytesToHex, numberToBytesBE } from "@noble/curves/abstract/utils";
import { uint8ArrayToBase64Url } from "@sd-jwt/utils";
import { Base64 } from "js-base64";

// 1. JWK 타입 정의
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

// 2. 헬퍼 함수
/**
 * BigInt를 32바이트 Uint8Array로 변환 (좌측 패딩)
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
 * Uint8Array를 BigInt로 변환
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt(`0x${bytesToHex(bytes)}`);
}

// 3. 개인키 변환 함수
/**
 * P-256 개인키(Uint8Array)를 EcPrivateJwk로 변환합니다.
 * @param privateKeyBytes 32바이트 개인키
 * @returns EcPrivateJwk
 */
export function privateKeyUint8ArrayToJwk(
  privateKeyBytes: Uint8Array
): EcPrivateJwk {
  if (privateKeyBytes.length !== 32) {
    throw new Error("Invalid private key length. Must be 32 bytes.");
  }

  // 공개키를 파생시킵니다 (비압축 형식).
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
 * EcPrivateJwk를 P-256 개인키(Uint8Array)로 변환합니다.
 * @param jwk EcPrivateJwk 객체
 * @returns 32바이트 개인키 Uint8Array
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

// 4. 공개키 변환 함수
/**
 * P-256 공개키(Uint8Array)를 EcPublicJwk로 변환합니다.
 * 압축(33바이트) 및 비압축(65바이트) 형식을 모두 지원합니다.
 * @param publicKeyBytes 공개키
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

  // fromHex는 압축/비압축을 자동 감지합니다.
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
 * EcPublicJwk를 P-256 공개키(Uint8Array)로 변환합니다.
 * @param jwk EcPublicJwk 객체
 * @param compressed 출력 형식을 압축(true)할지 여부 (기본값: false)
 * @returns 공개키 Uint8Array
 */
export function publicKeyJwkToUint8Array(
  jwk: EcPublicJwk,
  compressed = false
): Uint8Array {
  const x = Base64.toUint8Array(jwk.x);
  const y = Base64.toUint8Array(jwk.y);

  const point = new p256.Point(bytesToBigInt(x), bytesToBigInt(y), 1n);
  point.assertValidity(); // 유효한 P-256 곡선 위의 점인지 확인

  return point.toRawBytes(compressed);
}

// 5. 데모 함수
async function demo() {
  console.log("--- 개인키 변환 데모 ---");
  const originalPrivateKey = p256.utils.randomPrivateKey();
  console.log("원본 개인키 (Uint8Array):", originalPrivateKey);

  // Uint8Array -> Private JWK
  const privateJwk = privateKeyUint8ArrayToJwk(originalPrivateKey);
  console.log("-> 변환된 Private JWK:", privateJwk);

  // Private JWK -> Uint8Array
  const restoredPrivateKey = privateKeyJwkToUint8Array(privateJwk);
  console.log("-> 복원된 개인키 (Uint8Array):", restoredPrivateKey);

  // 검증
  console.log(
    "개인키 복원 성공:",
    bytesToHex(originalPrivateKey) === bytesToHex(restoredPrivateKey)
  );

  console.log("\n--- 공개키 변환 데모 ---");
  // 비압축 공개키로 테스트
  const originalUncompressedPublicKey = p256.getPublicKey(
    originalPrivateKey,
    false
  );
  console.log(
    "원본 비압축 공개키 (Uint8Array):",
    originalUncompressedPublicKey
  );

  // Uint8Array -> Public JWK
  const publicJwk = publicKeyUint8ArrayToJwk(originalUncompressedPublicKey);
  console.log("-> 변환된 Public JWK:", publicJwk);

  // Public JWK -> Uint8Array (비압축)
  const restoredUncompressedPublicKey = publicKeyJwkToUint8Array(
    publicJwk,
    false
  );
  console.log(
    "-> 복원된 비압축 공개키 (Uint8Array):",
    restoredUncompressedPublicKey
  );
  console.log(
    "비압축 공개키 복원 성공:",
    bytesToHex(originalUncompressedPublicKey) ===
      bytesToHex(restoredUncompressedPublicKey)
  );

  // Public JWK -> Uint8Array (압축)
  const restoredCompressedPublicKey = publicKeyJwkToUint8Array(publicJwk, true);
  console.log(
    "-> 복원된 압축 공개키 (Uint8Array):",
    restoredCompressedPublicKey
  );
  const originalCompressedPublicKey = p256.getPublicKey(
    originalPrivateKey,
    true
  );
  console.log(
    "압축 공개키 복원 성공:",
    bytesToHex(originalCompressedPublicKey) ===
      bytesToHex(restoredCompressedPublicKey)
  );
}

// 데모 실행
demo();
