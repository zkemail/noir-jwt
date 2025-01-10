import { generatePartialSHA } from "@zk-email/helpers";

/*
* Generates circuit inputs required for the jwt lib
* @param {Object} params - The input parameters
* @param {string} params.jwt - The JWT token to process (string)
* @param {JsonWebKey} params.pubkey - The public key to verify the signature (JsonWebKey)
* @param {string[]} params.shaPrecomputeTillKeys - (optional) Key(s) in the payload until which SHA should be precomputed
* @param {number} params.maxSignedDataLength - Maximum length of signed data allowed by the circuit
*/
export async function generateInputs({
  jwt,
  pubkey,
  shaPrecomputeTillKeys,
  maxSignedDataLength,
}) {
  // Parse token
  const [headerB64, payloadB64] = jwt.split(".");

  // Extract signed data as byte array
  const signedDataString = jwt.split(".").slice(0, 2).join("."); // $header.$payload
  const signedData = new TextEncoder().encode(signedDataString);

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
  const signatureBigInt = BigInt("0x" + Buffer.from(signature).toString("hex"));

  // Extract pubkey modulus as bigint
  const pubkeyJWK = await crypto.subtle.exportKey("jwk", pubkey);
  const pubkeyBigInt = BigInt(
    "0x" + Buffer.from(pubkeyJWK.n, "base64").toString("hex")
  );
  const redcParam = (1n << (2n * 2048n + 4n)) / pubkeyBigInt;

  const inputs = {
    pubkey_modulus_limbs: splitBigIntToChunks(pubkeyBigInt, 120, 18),
    redc_params_limbs: splitBigIntToChunks(redcParam, 120, 18),
    signature_limbs: splitBigIntToChunks(signatureBigInt, 120, 18),
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

    // base64 offset is the offset on the signed-data byte array from where the circuit will try and decode the payload
    // in this case it will be index of the payload (header.length + 1 for the '.')
    const base64Offset = headerB64.length + 1;
    inputs.b64_offset = base64Offset;
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
    const precomputeSelector = signedDataString.slice(
      sliceStart,
      sliceStart + 12
    ); // 12 is a random slice length - to get a unique string selector from base64 payload

    // generatePartialSHA expects padded input - Noir SHA lib doesn't need padded input; so we simply pad to 64x bytes
    const dataPadded = new Uint8Array(Math.ceil(signedData.length / 64) * 64);
    dataPadded.set(signedData);

    // Precompute the SHA256 hash
    const { precomputedSha, bodyRemaining: bodyRemainingSHAPadded } =
      generatePartialSHA({
        body: dataPadded,
        bodyLength: dataPadded.length,
        selectorString: precomputeSelector,
        maxRemainingBodyLength: 640, // Max length configured in the circuit
      });

    // generatePartialSHA returns the remaining data after the precomputed SHA256 hash including padding
    // We don't need this padding so can we trim to it nearest 64x
    const shaCutoffIndex = Math.floor(sliceStart / 64) * 64; // Index up to which we precomputed SHA256
    const remainingDataLength = signedData.length - shaCutoffIndex;
    const bodyRemaining = bodyRemainingSHAPadded.slice(0, remainingDataLength);

    // Pad to the max length configured in the circuit
    if (bodyRemaining.length > maxSignedDataLength) {
      throw new Error("bodyRemaining after partial hash exceeds maxSignedDataLength");
    }

    const bodyRemainingPadded = new Uint8Array(maxSignedDataLength);
    bodyRemainingPadded.set(bodyRemaining);

    // B64 encoding happens serially, so we can decode a portion as long as the indices of the slice is a multiple of 4
    // Since we only pass the data after partial SHA to the circuit, the B64 slice might not be parse-able
    // This is because the first index of partial_data might not be a 4th multiple of original payload B64
    // So we also pass in an offset after which the data in partial_data is a 4th multiple of original payload B64
    // An attacker giving wrong index will fail as incorrectly decoded bytes wont contain "hd" or "nonce"
    const payloadLengthInRemainingData = shaCutoffIndex - headerB64.length - 1; // -1 for the separator '.'
    const b64Offset = 4 - (payloadLengthInRemainingData % 4);

    inputs.partial_data = {
      storage: Array.from(bodyRemainingPadded),
      len: remainingDataLength,
    };
    inputs.partial_hash = u8ToU32(precomputedSha);
    inputs.full_data_length = signedData.length;
    inputs.b64_offset = b64Offset;
  }

  return inputs;
}

// Function to convert u8 array to u32 array - partial_hash expects u32[8] array
// new Uint32Array(input.buffer) does not work due to difference in endianness
// Copied from https://github.com/zkemail/zkemail.nr/blob/main/js/src/utils.ts#L9
// TODO: Import Mach34 npm package instead when zkemail.nr is ready
function u8ToU32(input) {
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
* Extracts the modulus from a JWK public key as a BigInt
* @param {JsonWebKey} jwk - The public key in JWK format
* @returns {Promise<bigint>} The modulus as a BigInt
*/
export async function pubkeyModulusFromJWK(jwk) {

}

/*
* Splits a BigInt into fixed-size chunks
* @param {bigint} bigInt - The BigInt to split
* @param {number} chunkSize - Size of each chunk in bits
* @param {number} numChunks - Number of chunks to split into
* @returns {bigint[]} Array of BigInt chunks
*/
export function splitBigIntToChunks(
  bigInt,
  chunkSize,
  numChunks
) {
  const chunks = [];
  const mask = (1n << BigInt(chunkSize)) - 1n;
  for (let i = 0; i < numChunks; i++) {
    const chunk = (bigInt / (1n << (BigInt(i) * BigInt(chunkSize)))) & mask;
    chunks.push(chunk);
  }
  return chunks;
}
