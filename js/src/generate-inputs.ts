import { createSHA256 } from 'hash-wasm';

type GenerateInputsParams = {
  jwt: string;
  pubkey: JsonWebKey;
  shaPrecomputeTillKeys?: string[];
  maxSignedDataLength: number;
}

type JWTCircuitInputs = {
  data?: {
    storage: number[];
    len: number;
  };
  base64_decode_offset: number;
  pubkey_modulus_limbs: string[];
  redc_params_limbs: string[];
  signature_limbs: string[];
  partial_data?: {
    storage: number[];
    len: number;
  };
  partial_hash?: number[];
  full_data_length?: number;
}

/*
* Generates circuit inputs required for the jwt lib
* @param {Object} params - The input parameters
* @param {string} params.jwt - The JWT token to process (string)
* @param {JsonWebKey} params.pubkey - The public key to verify the signature (JsonWebKey)
* @param {string[]} params.shaPrecomputeTillKeys - (optional) Key(s) in the payload until which SHA should be precomputed
* @param {number} params.maxSignedDataLength - Maximum length of signed data (with or without partial hash) allowed by the circuit
*/
export async function generateInputs({
  jwt,
  pubkey,
  shaPrecomputeTillKeys,
  maxSignedDataLength, // when using partial hash, this will be the length of data after partial hash
}: GenerateInputsParams) {
  // Parse token
  const [headerB64, payloadB64] = jwt.split(".");

  // Extract signed data as byte array
  const signedDataString = jwt.split(".").slice(0, 2).join("."); // $header.$payload
  const signedData = new TextEncoder().encode(signedDataString) as Uint8Array;

  // Extract signature as bigint
  const signatureBase64Url = jwt.split(".")[2];
  const signatureBase64 = signatureBase64Url
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const signature = new Uint8Array(
    atob(signatureBase64)
      .split("")
      .map((c) => c.charCodeAt(0))
  );

  const signatureBigInt = BigInt("0x" + Array.from(signature).map(b => b.toString(16).padStart(2, '0')).join(''));

  // Extract pubkey modulus as bigint
  const pubkeyBigInt = BigInt("0x" + atob(pubkey.n!.replace(/-/g, "+").replace(/_/g, "/"))
    .split("")
    .map(c => c.charCodeAt(0).toString(16).padStart(2, "0"))
    .join(""));
  const redcParam = (1n << (2n * 2048n + 4n)) / pubkeyBigInt; // something needed by the noir big-num lib 

  const inputs: Partial<JWTCircuitInputs> = {
    pubkey_modulus_limbs: splitBigIntToChunks(pubkeyBigInt, 120, 18).map(s => s.toString()),
    redc_params_limbs: splitBigIntToChunks(redcParam, 120, 18).map(s => s.toString()),
    signature_limbs: splitBigIntToChunks(signatureBigInt, 120, 18).map(s => s.toString()),
  };

  if (!shaPrecomputeTillKeys || shaPrecomputeTillKeys.length === 0) {
    // No precompute selector - no need to precompute SHA256
    if (signedData.length > maxSignedDataLength) {
      throw new Error("Signed data length exceeds maxSignedDataLength");
    }
    const signedDataPadded = new Uint8Array(maxSignedDataLength);
    signedDataPadded.set(signedData);
    inputs.data = {
      storage: Array.from(signedDataPadded),
      len: signedData.length,
    }
    // entire payload is base64 decode-able when not using partial hash
    // offset in signed data is the index of payload start
    // this can be any multiple of 4 from payload start, if you want to skip some bytes from start
    inputs.base64_decode_offset = headerB64.length + 1;
  } else {
    // Precompute SHA256 of the signed data
    // SHA256 is done in 64 byte chunks, so we can hash upto certain portion outside of circuit to save constraints
    // Signed data is $headerB64.$payloadB64
    // We need to find the index in B64 payload corresponding to min(hdIndex, nonceIndex) when decoded
    // Then we find the 64 byte boundary before this index and precompute the SHA256 upto that
    const payloadString = atob(payloadB64);
    const indicesOfPrecomputeKeys = shaPrecomputeTillKeys.map((key) =>
      payloadString.indexOf(`"${key}":`)
    );
    const smallerIndex = Math.min(...indicesOfPrecomputeKeys);
    const smallerIndexInB64 = Math.floor((smallerIndex * 4) / 3); // 4 B64 chars = 3 bytes

    const sliceStart = headerB64.length + smallerIndexInB64 + 1; // +1 for the '.'
    // const precomputeSelector = signedDataString.slice(
    //   sliceStart,
    //   sliceStart + 12
    // ); // 12 is a random slice length - to get a unique string selector from base64 payload

    // generatePartialSHA expects padded input - Noir SHA lib doesn't need padded input; so we simply pad to 64x bytes
    // const dataPadded = new Uint8Array(Math.ceil(signedData.length / 64) * 64);
    // dataPadded.set(signedData);

    // Precompute the SHA256 hash
    const { precomputedSha, bodyRemaining: dataRemainingAfterPartialSHA } =
      await generatePartialSHA256(signedData, Math.floor(sliceStart / 64));

    console.log(precomputedSha);
    console.log(dataRemainingAfterPartialSHA);

    // generatePartialSHA returns the remaining data after the precomputed SHA256 hash including padding
    // We don't need this padding so can we trim to it nearest 64x
    const shaCutoffIndex = Math.floor(sliceStart / 64) * 64; // Index up to which we precomputed SHA256
    const remainingDataLength = signedData.length - shaCutoffIndex;
    const dataRemainingAfterPartialSHAClean = dataRemainingAfterPartialSHA.slice(0, remainingDataLength);

    // Pad to the max length configured in the circuit
    if (dataRemainingAfterPartialSHAClean.length > maxSignedDataLength) {
      throw new Error("dataRemainingAfterPartialSHAClean after partial hash exceeds maxSignedDataLength");
    }

    const dataRemainingAfterPartialSHAPadded = new Uint8Array(maxSignedDataLength);
    dataRemainingAfterPartialSHAPadded.set(dataRemainingAfterPartialSHAClean);

    inputs.partial_data = {
      storage: Array.from(dataRemainingAfterPartialSHAPadded),
      len: remainingDataLength,
    };
    inputs.partial_hash = Array.from(precomputedSha);
    inputs.full_data_length = signedData.length;

    // when using partial hash, the data after the partial hash might not be a valid base64
    // we need to find an offset (1, 2, or 3) such that the remaining payload is base64 decode-able
    // this is the number that should be added to the "payload chunk that was included in SHA precompute"
    // to make it a multiple of 4
    // in other words, if you trim offset number of bytes from the remaining payload, it will be base64 decode-able
    const payloadBytesInShaPrecompute = shaCutoffIndex - (headerB64.length + 1);
    const offsetToMakeIt4x = 4 - (payloadBytesInShaPrecompute % 4);
    inputs.base64_decode_offset = offsetToMakeIt4x;
  }

  return inputs as JWTCircuitInputs;
}

// Returns the intermediate SHA256 hash of the data
async function generatePartialSHA256(data: Uint8Array, blockIndex: number) {
  if (typeof data === 'string') {
    const encoder = new TextEncoder();
    data = encoder.encode(data); // Convert string to Uint8Array
}

const blockSize = 64; // 512 bits
const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

for (let i = 0; i <= blockIndex; i++) {
    if (i * blockSize >= data.length) {
        throw new Error('Block index out of range.');
    }

    const block = new Uint8Array(blockSize);
    block.set(data.slice(i * blockSize, (i + 1) * blockSize));
    sha256Block(H, block);
}

  // Get the intermediate digest (this is **not** the final hash)
  return {
    precomputedSha: H,
    bodyRemaining: data.slice(blockIndex * blockSize + blockSize)
  }
}

// Function to convert u8 array to u32 array - partial_hash expects u32[8] array
// new Uint32Array(input.buffer) does not work due to difference in endianness
// Copied from https://github.com/zkemail/zkemail.nr/blob/main/js/src/utils.ts#L9
// TODO: Import Mach34 npm package instead when zkemail.nr is ready
function u8ToU32(input: Uint8Array) {
  const out = new Uint32Array(input.length / 4);
  for (let i = 0; i < out.length; i++) {
    out[i] =
      (input[i * 4 + 0] << 24) |
      (input[i * 4 + 1] << 16) |
      (input[i * 4 + 2] << 8) |
      (input[i * 4 + 3] << 0);
  }
  return out;
}

/*
* Splits a BigInt into fixed-size chunks
* @param {bigint} bigInt - The BigInt to split
* @param {number} chunkSize - Size of each chunk in bits
* @param {number} numChunks - Number of chunks to split into
* @returns {bigint[]} Array of BigInt chunks
*/
export function splitBigIntToChunks(
  bigInt: bigint,
  chunkSize: number,
  numChunks: number
) {
  const chunks = [];
  const mask = (1n << BigInt(chunkSize)) - 1n;
  for (let i = 0; i < numChunks; i++) {
    const chunk = (bigInt / (1n << (BigInt(i) * BigInt(chunkSize)))) & mask;
    chunks.push(chunk);
  }
  return chunks;
}


// const crypto = require('crypto');

/**
 * SHA-256 constants (first 32 bits of fractional parts of cube roots of primes)
 */
const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

/**
* Rotate right function (SHA-256 bitwise operations)
*/
function rotr(n: number, x: number) {
  return (x >>> n) | (x << (32 - n));
}

/**
* SHA-256 Compression Function (Processes 64-byte blocks)
*/
function sha256Block(H: Uint32Array, block: Uint8Array) {
  let w = new Uint32Array(64);
  let a = H[0], b = H[1], c = H[2], d = H[3];
  let e = H[4], f = H[5], g = H[6], h = H[7];

  // Convert block into 32-bit words
  for (let i = 0; i < 16; i++) {
      w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
  }
  for (let i = 16; i < 64; i++) {
      const s0 = rotr(7, w[i - 15]) ^ rotr(18, w[i - 15]) ^ (w[i - 15] >>> 3);
      const s1 = rotr(17, w[i - 2]) ^ rotr(19, w[i - 2]) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
  }

  // Main compression loop
  for (let i = 0; i < 64; i++) {
      const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
  }

  // Update intermediate hash values
  H[0] = (H[0] + a) >>> 0;
  H[1] = (H[1] + b) >>> 0;
  H[2] = (H[2] + c) >>> 0;
  H[3] = (H[3] + d) >>> 0;
  H[4] = (H[4] + e) >>> 0;
  H[5] = (H[5] + f) >>> 0;
  H[6] = (H[6] + g) >>> 0;
  H[7] = (H[7] + h) >>> 0;
}