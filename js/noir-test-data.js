import crypto from "crypto";
import jsonwebtoken from "jsonwebtoken";
import { generateInputs } from "./generate-inputs.js";

export async function createKeyAndSignData() {
  // Generate a key pair using RSASSA-PKCS1-v1_5
  const key = await crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 65537,
  });

  // Sample payload
  const payload = {
    iss: "http://test.com",
    sub: "ABCD123123",
    aud: "123123123.456456456",
    exp: Math.floor(Date.now() / 1000) + 60 * 60,
    iat: Math.floor(Date.now() / 1000),
    nonce: Math.random().toString(36).substring(2, 15), // Random nonce
    email: "alice@test.com",
    email_verified: true,
  };

  // Sign the payload
  const signature = jsonwebtoken.sign(payload, key.privateKey, {
    algorithm: "RS256",
  });

  // Verify the signature
  jsonwebtoken.verify(signature, key.publicKey);

  // Convert public key to JWK
  const spkiKey = key.publicKey.export({ type: "spki", format: "der" });
  const pubkeyJwk = await globalThis.crypto.subtle.importKey(
    "spki",
    spkiKey,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["verify"]
  );

  return {
    pubkeyJwk,
    signature,
    payload,
  };
}

async function generateNoirTestData() {
  const { pubkeyJwk, signature } = await createKeyAndSignData();

  // Prepare inputs
  const inputs = await generateInputs({
    jwt: signature,
    pubkey: pubkeyJwk,
    maxSignedDataLength: 512,
  });

  return `
      let pubkey_modulus_limbs = [${inputs.pubkey_modulus_limbs.join(", ")}];
      let redc_params_limbs = [${inputs.redc_params_limbs.join(", ")}];
      let signature_limbs = [${inputs.signature_limbs.join(", ")}];
      let data: BoundedVec<u8, 512> = BoundedVec::from_array([${inputs.data.storage.filter(s => s !== 0).join(", ")}]);
      let b64_offset = ${inputs.b64_offset};

      let jwt = JWT::init(
        data,
        b64_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
      );

      jwt.verify();
    `
}

async function generateNoirTestDataPartialHash() {
  const { pubkeyJwk, signature } = await createKeyAndSignData();

  // Prepare inputs
  const inputs = await generateInputs({
    jwt: signature,
    pubkey: pubkeyJwk,
    shaPrecomputeTillKeys: ["nonce", "email"],
    maxSignedDataLength: 256,
  });

  return `
      let pubkey_modulus_limbs = [${inputs.pubkey_modulus_limbs.join(", ")}];
      let redc_params_limbs = [${inputs.redc_params_limbs.join(", ")}];
      let signature_limbs = [${inputs.signature_limbs.join(", ")}];
      let partial_data: BoundedVec<u8, 256> = BoundedVec::from_array([${inputs.partial_data.storage.filter(s => s !== 0).join(", ")}]);
      let b64_offset = ${inputs.b64_offset};
      let partial_hash = [${inputs.partial_hash.join(", ")}];
      let full_data_length = ${inputs.full_data_length};

      let jwt = JWT::init_with_partial_hash(
        partial_data,
        partial_hash,
        full_data_length,
        b64_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
      );

      jwt.verify();
    `
}

generateNoirTestData().then(console.log);
console.log("\n\n--------------------------------\n\n");
generateNoirTestDataPartialHash().then(console.log);

