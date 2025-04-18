# Noir JWT Verifier

[Noir](https://noir-lang.org/) library to verify JWT tokens and prove claims. Currently only supports RS256 with 2048 bit keys.

- Supports arbitrary sized JWTs.
- Supports partial SHA hashing on the signed data to save constraints.
- Can extract and verify claims of string, number, and boolean types efficiently.


## Version compatibility

- For Noir v1.0.0-beta.3 and below, use version `v0.4.4` of this library.
- For Noir v1.0.0-beta.4 and above, use version `v0.5.0` of this library.


### How it works

You can learn more about JWT [here](https://jwt.io/introduction). But in short, JWT is a data structure that contains three parts:
- Header: contains metadata about the token (JSON object with algorithm and type of token)
- Payload: contains the claims (JSON key-value pairs)
- Signature: RSA signature of the header and payload (assuming RS256 algorithm)

JWT token is a string represented as `base64(header).base64(payload).base64(signature)`.

This noir library takes the signed data (which is `base64(header).base64(payload)`),  signature and the public key and verifies the signature (RSA-SHA256 verification).

There are utility methods to extract or verify claims from the payload, which is powered by the [string_search](https://github.com/noir-lang/noir_string_search) lib.


## Installation

In your Nargo.toml file, add `jwt` as a dependency with the version you want to install:

```toml
[dependencies]
jwt = { tag = "v0.4.3", git = "https://github.com/zkemail/noir-jwt" }
```

## Usage

Assuming you installed the latest version, you can use it in your Noir program like this:

```nr
use jwt::JWT;

global MAX_DATA_LENGTH: u32 = 900; // max length of signed data (headerb64 + "." + payloadb64)
global MAX_NONCE_LENGTH: u32 = 32; // we are verifying `nonce` claim

fn main(
    data: BoundedVec<u8, MAX_DATA_LENGTH>,
    base64_decode_offset: u32,
    pubkey_modulus_limbs: pub [Field; 18],
    redc_params_limbs: [Field; 18],
    signature_limbs: [Field; 18],
    expected_nonce: pub BoundedVec<u8, MAX_NONCE_LENGTH>
) {
    let jwt = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    // Verify `iss` claim value is "test"
    jwt.assert_claim_string("iss".as_bytes(), BoundedVec::<u8, 4>::from_array("test".as_bytes()));
}
```

#### With partial hash

```nr
use jwt::JWT;

global MAX_PARTIAL_DATA_LENGTH: u32 = 640; // Max length of the remaining data after partial hash
global MAX_NONCE_LENGTH: u32 = 32;

fn main(
    partial_data: BoundedVec<u8, MAX_PARTIAL_DATA_LENGTH>,
    partial_hash: [u32; 8],
    full_data_length: u32,
    base64_decode_offset: u32,
    pubkey_modulus_limbs: pub [Field; 18],
    redc_params_limbs: [Field; 18],
    signature_limbs: [Field; 18],
    nonce: pub BoundedVec<u8, MAX_NONCE_LENGTH>,
) {
    let jwt = JWT::init_with_partial_hash(
        partial_data,
        partial_hash,
        full_data_length,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    // Validate key value pair in payload JSON
    jwt.assert_claim_string("nonce".as_bytes(), nonce);
}
```

## Input parameters

Here is an explanation of the input parameters used in the circuit. Note that you can **use the JS SDK to generate these inputs**.

- `data` is the signed data (headerb64 + "." + payloadb64)
- When using partial SHA:
    - `partial_data` is the data after the partial SHA.
    - `partial_hash` is the partial hash of the data before the partial SHA [8 limbs of 32 bits each]
    - `full_data_length` is the length of the full signed data (before partial SHA).
- `pubkey_modulus_limbs`, `redc_params_limbs`, `signature_limbs` are the limbs of the RSA public key, redc params (this is required for bignum lib), and signature respectively.
- `base64_decode_offset` is the index in `data` from which the circuit will try to decode the base64
    - We only need to decode the payload (or a portion of it), as the claims we want to extract are in the payload.
    - Normally, you can set `base64_decode_offset` to be the start index of payload data (index after first `.` in the JWT string)
    - Or, any multiple of 4 (as base64 decodes chunks of 4) from the start of the payload if you want to skip the first few bytes of the payload. This can be used to optimize some constraints if the claims you want to verify are usually in the middle or towards the end of the payload.
    - When using partial SHA, this should be 1, 2, or 3 to make the data after partial hash base64 decode-able (a valid base64). This should be the number of bytes that needs to be sliced from the data_remaining_after_partial_hash to make it a valid base64.


## Methods available

- `get_claim_string` - extracts a string claim from the payload and returns it as a `BoundedVec<u8, MAX_VALUE_LENGTH>`
    ```nr
    let claim: BoundedVec<u8, MAX_VALUE_LENGTH> = jwt.get_claim_string("email".as_bytes());
    ```

- `assert_claim_string` - verifies that the claim is present in the payload and is a valid base64 encoded string
    ```nr
    jwt.assert_claim_string("nonce".as_bytes(), nonce);
    ```
- `get_claim_number` - extracts a number claim from the payload and returns it as a `u64`
    ```nr
    let claim: u64 = jwt.get_claim_number("nonce".as_bytes());
    ```

- `assert_claim_number` - verifies that the claim is present in the payload and is a valid number
    ```nr
    jwt.assert_claim_number("nonce".as_bytes(), nonce);
    ```

- `get_claim_bool` - extracts a boolean claim from the payload and returns it as a `bool`
    ```nr
    let claim: bool = jwt.get_claim_bool("nonce".as_bytes());
    ```

- `assert_claim_bool` - verifies that the claim is present in the payload and is a valid boolean
    ```nr
    jwt.assert_claim_bool("nonce".as_bytes(), nonce);
    ```

> Please note that the keys of the claims need to be known at compile time.
> This library doesn't support runtime JSON keys.

## Input generation from JS

A JS SDK is included in the repo that can help you with generating inputs required for the JWT circuit. Since this is only a library, you would need to combine it with other input used in your application circuit.

Install the dependency
```
npm install noir-jwt
```

#### Usage
```js
const { generateInputs } = require("noir-jwt");

const inputs = generateInputs({
  jwt,
  pubkey,
  maxSignedDataLength,
  shaPrecomputeTillKeys,
});
```
where:
- `jwt` is the JWT token to process (string)
- `pubkey` is the public key to verify the signature in `JsonWebKey` format
- `maxSignedDataLength` is the maximum length of signed data (with or without partial hash). This should be same as `MAX_DATA_LENGTH` configured in your circuit.
- `shaPrecomputeTillKeys` (optional) is the claim key(s) in the payload until which SHA should be precomputed. You can specify the claims you are extracting in the circuit, and the JS SDK will precompute SHA up to the first claim.
