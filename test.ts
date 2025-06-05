import { p256 } from "@noble/curves/p256";
import { jwtVerify } from "jose";
import { sha256 } from "./hash";

// --- Helper Functions (uint8arrays 대체) ---

/**
 * Uint8Array를 Base64URL 문자열로 인코딩합니다.
 * @param bytes 인코딩할 Uint8Array
 * @returns Base64URL 문자열
 */
function bytesToBase64Url(bytes: Uint8Array): string {
  // 1. Uint8Array를 바이너리 문자열로 변환합니다.
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  // 2. btoa를 사용하여 Base64로 인코딩합니다.
  const base64 = btoa(binary);

  // 3. Base64를 URL-safe 형식으로 변환합니다.
  return base64
    .replace(/\+/g, "-") // '+' -> '-'
    .replace(/\//g, "_") // '/' -> '_'
    .replace(/=/g, ""); // padding 제거
}

/**
 * JSON 객체를 Base64URL 문자열로 인코딩합니다.
 * @param data 인코딩할 JSON 객체
 * @returns Base64URL 문자열
 */
function objectToBase64Url(data: object): string {
  const jsonString = JSON.stringify(data);
  const bytes = new TextEncoder().encode(jsonString);
  return bytesToBase64Url(bytes);
}
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

// --- JWT 생성 로직 ---

// 1. JWK 형식의 개인키 예시 (P-256 곡선)
// 실제 환경에서는 안전한 곳에서 이 키를 불러와야 합니다.
// 'd' 값은 Base64URL로 인코딩된 개인키입니다.
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

// 2. JWT 헤더 및 페이로드 정의
const header = {
  alg: "ES256",
  typ: "JWT",
};

const payload = {
  iss: "https://gemini.google.com",
  sub: "user-12345",
  name: "Gemini AI",
};

// 3. JWT 생성 및 서명 함수
async function signJwt(
  privateKeyJwkD: string,
  header: object,
  payload: object
): Promise<string> {
  // 헤더와 페이로드를 Base64URL로 인코딩합니다.
  const encodedHeader = objectToBase64Url(header);
  const encodedPayload = objectToBase64Url(payload);

  // 서명할 데이터 (signing input)를 구성합니다.
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signingInputBytes = sha256(signingInput);

  const pkey = fromBase64Url(privateKeyJwkD);

  const signature = p256.sign(signingInputBytes, pkey);

  // 서명을 Compact 형식(r+s)의 Uint8Array로 변환합니다.
  const compactSignatureBytes = signature.toCompactRawBytes();

  // 서명을 Base64URL로 인코딩합니다.
  const encodedSignature = bytesToBase64Url(compactSignatureBytes);

  // 최종 JWT를 반환합니다.
  return `${signingInput}.${encodedSignature}`;
}

(async () => {
  const jwt = await signJwt(jwk.d, header, payload);
  console.log("생성된 JWT:");
  console.log(jwt);

  const result = await jwtVerify(jwt, pubJwk, { algorithms: ["ES256"] });
  console.log(result);
})();
