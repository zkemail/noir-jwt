# Noir JWT Verifier

[Noir](https://noir-lang.org/) library to verify JWT tokens, and prove claims. Currently only supports RS256 with 2048 bit keys.

- Supports arbitrary sized inputs.
- Supports partial hashing on the input.
- Uses [string_search](https://github.com/noir-lang/noir_string_search) lib to extract and verify claims efficiently.

You can learn more about JWT [here](https://jwt.io/introduction).


## Installation

In your Nargo.toml file, add `jwt` as a dependency with the version you want to install:

```toml
[dependencies]
jwt = { tag = "v0.3.0", git = "https://github.com/zkemail/noir-jwt" }
```

## Usage

Assusming you installed the latest version, you can use it in your Noir program like this:

```noir
use jwt::JWT;

global MAX_DATA_LENGTH: u32 = 900;
global MAX_NONCE_LENGTH: u32 = 32;

fn main(
    data: BoundedVec<u8, MAX_DATA_LENGTH>,
    base64_decode_offset: u32,
    pubkey_modulus_limbs: pub [Field; 18],
    redc_params_limbs: [Field; 18],
    signature_limbs: [Field; 18],
    domain: pub BoundedVec<u8, MAX_DOMAIN_LENGTH>,
    nonce: pub BoundedVec<u8, MAX_NONCE_LENGTH>,
) {
    let jwt = JWT::init(
        data,
        base64_decode_offset: u32,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    // Validate key value pair in payload JSON
    jwt.assert_claim_string::<300, 5, MAX_NONCE_LENGTH>("nonce".as_bytes(), nonce);
}
```

#### With partial hash

```noir
use jwt::JWT;

global MAX_PARTIAL_DATA_LENGTH: u32 = 640; // Data after partial SHA
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
    jwt.assert_claim_string::<300, 5, MAX_NONCE_LENGTH>("nonce".as_bytes(), nonce);
}
```

## Input parameters

Here is an explanation of the input parameters used in the circuit. Note that you can use the JS SDK to generate the values for these parameters.

- `base64_decode_offset` is the index in `data` from which the circuit will try to decode the base64
    - Normally, you can set this to the index of payload data (index after first `.` in the JWT string)
    - Or any multiple of 4 from the start of the payload, if you want to skip the first few bytes of the payload. This can be used to save some constraints if the claims you want to verify are not at the start of the payload.
    - When using partial SHA, this should be 1, 2, or 3 to make the data after partial hash base64 decode-abe. This should the number that needs to be added to the payload_portion_included_in_partial_hash a multiple of 4.
- `300` in the above example is the `PAYLOAD_SCAN_RANGE`, which is the index in the base64 encoded payload (from the `base64_decode_offset`) up to which we will seach for the claim.
    - This essentially means that everything from `base64_decode_offset` to `PAYLOAD_RANGE` should be a valid base64 character of the payload, and the claim should be present in this range.
    - `PAYLOAD_SCAN_RANGE` should be a multiple of 4 to be a valid base64 chunk.
- If you are want to verify multiple claims, it is cheaper to use the same `PAYLOAD_SCAN_RANGE` (maximum needed) for all `assert_claim` calls as the compiler will optimize the repeated calculations.
- `pubkey_modulus_limbs`, `redc_params_limbs`, `signature_limbs` are the limbs of the public key, redc params, and signature respectively (you can refer to the [bignum](https://github.com/noir-lang/noir-bignum) lib for more details).
- When using partial SHA
    - `partial_data` is the data after the partial SHA.
    - `partial_hash` is the partial hash of the data before the partial SHA [8 limbs of 32 bits each]
    - `full_data_length` is the length of the full signed data (before partial SHA).

## Methods available

- `get_claim_string` - extracts a string claim from the payload and returns it as a `BoundedVec<u8, MAX_VALUE_LENGTH>`
    ```noir
    let claim: BoundedVec<u8, MAX_VALUE_LENGTH> = jwt.get_claim_string::<300, 5, MAX_NONCE_LENGTH>("email".as_bytes());
    ```

- `assert_claim_string` - verifies that the claim is present in the payload and is a valid base64 encoded string
    ```noir
    jwt.assert_claim_string::<300, 5, MAX_NONCE_LENGTH>("nonce".as_bytes(), nonce);
    ```
- `get_claim_number` - extracts a number claim from the payload and returns it as a `u64`
    ```noir
    let claim: u64 = jwt.get_claim_number::<300, 5, MAX_NONCE_LENGTH>("nonce".as_bytes());
    ```

- `assert_claim_number` - verifies that the claim is present in the payload and is a valid number
    ```noir
    jwt.assert_claim_number::<300, 5, MAX_NONCE_LENGTH>("nonce".as_bytes(), nonce);
    ```

- `get_claim_bool` - extracts a boolean claim from the payload and returns it as a `bool`
    ```noir
    let claim: bool = jwt.get_claim_bool::<300, 5, MAX_NONCE_LENGTH>("nonce".as_bytes());
    ```

- `assert_claim_bool` - verifies that the claim is present in the payload and is a valid boolean
    ```noir
    jwt.assert_claim_bool::<300, 5, MAX_NONCE_LENGTH>("nonce".as_bytes(), nonce);
    ```
- These methods use generic arguments `<PAYLOAD_SCAN_RANGE, CLAIM_KEY_LENGTH, MAX_CLAIM_VALUE_LENGTH>` to optimize the constraints.
    - `PAYLOAD_SCAN_RANGE` is the index in the base64 encoded payload (from the `base64_decode_offset`) up to which we will seach for the claim.
    - `CLAIM_KEY_LENGTH` is the length of the claim key.
    - `MAX_CLAIM_VALUE_LENGTH` is the maximum length of the claim value.
- You can check the tests in `src/lib.nr` to see how these methods are used.



## Input generation from JS

A JS SDK is included in the repo to generate inputs for the circuit. Since this is only a library, you would need to combine it with your own input generation needed for your application circuit.

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
  shaPrecomputeTillKeys,
  maxSignedDataLength,
});
```
where:
- `jwt` is the JWT token to process (string)
- `pubkey` is the public key to verify the signature in `JsonWebKey` format
- `maxSignedDataLength` is the maximum length of signed data (with or without partial hash) which you configured in your circuit.
- `shaPrecomputeTillKeys` is the key(s) in the payload until which SHA should be precomputed. This is optional in case you want to precompute SHA to a certain point in the payload to save constraints.


## Limitation

Base64 does not support variable length in put now. Due to this you need to specify a `PAYLOAD_SCAN_RANGE` when calling `assert_claim_` which should always contain valid base64 characters of the payload (no padding characters). This makes it difficult to verify claims if they are the last key in the payload (as you might not know the exact length of the payload in advance).
