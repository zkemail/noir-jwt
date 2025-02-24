import { generatePartialSHA256 } from './partial-sha';

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

    // Precompute the SHA256 hash
    const { partialHash, remainingData } =
      await generatePartialSHA256(signedData, sliceStart);

    // Pad to the max length configured in the circuit
    if (remainingData.length > maxSignedDataLength) {
      throw new Error("remainingData after partial hash exceeds maxSignedDataLength");
    }

    const remainingDataPadded = new Uint8Array(maxSignedDataLength);
    remainingDataPadded.set(remainingData);

    inputs.partial_data = {
      storage: Array.from(remainingDataPadded),
      len: remainingData.length,
    };
    inputs.partial_hash = Array.from(partialHash);
    inputs.full_data_length = signedData.length;

    // when using partial hash, the data after the partial hash might not be a valid base64
    // we need to find an offset (1, 2, or 3) such that the remaining payload is base64 decode-able
    // this is the number that should be added to the "payload chunk that was included in SHA precompute"
    // to make it a multiple of 4
    // in other words, if you trim offset number of bytes from the remaining payload, it will be base64 decode-able
    const shaCutoffIndex = signedData.length - remainingData.length;
    const payloadBytesInShaPrecompute = shaCutoffIndex - (headerB64.length + 1);
    const offsetToMakeIt4x = 4 - (payloadBytesInShaPrecompute % 4);
    inputs.base64_decode_offset = offsetToMakeIt4x;
  }

  return inputs as JWTCircuitInputs;
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