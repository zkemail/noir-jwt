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
jwt = { tag = "v0.1.0", git = "https://github.com/saleel/noir-jwt" }
```

## Usage

Assusming you installed the latest version, you can use it in your Noir program like this:

```noir
use dep::jwt::JWT;

global MAX_DATA_LENGTH: u32 = 900;
global MAX_NONCE_LENGTH: u32 = 32;

fn main(
    data: BoundedVec<u8, MAX_DATA_LENGTH>,
    b64_offset: u32,
    pubkey_modulus_limbs: pub [Field; 18],
    redc_params_limbs: [Field; 18],
    signature_limbs: [Field; 18],
    domain: pub BoundedVec<u8, MAX_DOMAIN_LENGTH>,
    nonce: pub BoundedVec<u8, MAX_NONCE_LENGTH>,
) {
    let jwt = JWT::init(
        data,
        b64_offset: u32,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    // Validate key value pair in payload JSON
    jwt.validate_key_value::<300, 5, MAX_NONCE_LENGTH>("nonce".as_bytes(), nonce);
}
```

#### With partial hash

```noir
use dep::jwt::JWT;

global MAX_PARTIAL_DATA_LENGTH: u32 = 640; // Data after partial SHA
global MAX_NONCE_LENGTH: u32 = 32;

fn main(
    partial_data: BoundedVec<u8, MAX_PARTIAL_DATA_LENGTH>,
    partial_hash: [u32; 8],
    full_data_length: u32,
    b64_offset: u32,
    pubkey_modulus_limbs: pub [Field; 18],
    redc_params_limbs: [Field; 18],
    signature_limbs: [Field; 18],
    nonce: pub BoundedVec<u8, MAX_NONCE_LENGTH>,
) {
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

    // Validate key value pair in payload JSON
    jwt.validate_key_value::<300, 5, MAX_NONCE_LENGTH>("nonce".as_bytes(), nonce);
}
```

- `b64_offset` is the index in `data` from which the circuit will try to decode the base64
    - You can set this to the index of payload data (index after first `.` in the JWT string)
    - When using partial SHA, this should be 1, 2, or 3 to make the data after partial hash a multiple of 4
- `300` in the above example is the `PAYLOAD_RANGE`, which is the index in the base64 encoded payload (from the b64_offset) up to which we will look for the key:value pair.
    - This essentially means that everything from `b64_offset` to `PAYLOAD_RANGE` should be a valid base64 character of the payload, and the key:value pair should be present in this range.
    - `PAYLOAD_RANGE` should be a multiple of 4 to be a valid base64 chunk.
- If you are want to verify multiple claims, it is better to use the same `PAYLOAD_RANGE` (maximum needed) for all `validate_key_value` calls as the compiler will optimize them.

## Input generation from JS

A JS SDK will be released soon to generate the inputs for Noir. In the meantime, refer to this [example](https://github.com/saleel/stealthnote/blob/main/app/lib/utils.ts#L514-L534). This is for the partial SHA case, but you can use a trimmed version of the same function for the full SHA case - though you would set `b64_offset` as start of the `payload`, something like (`idToken.indexOf(idToken.split(".")[1]) + 1`).


## Limitation

Base64 does not support variable length in put now. Due to this you need to specify a `PAYLOAD_RANGE` when calling `validate_key_value` which should always contain valid base64 characters of the payload (no padding characters). This makes it difficult to verify key/value if they are the last key in the payload - as you might not know the exact length of the payload in advance.
This will be fixed in a future release.


## TODO

- Add support for arbitrary input sizes without RANGE extraction
- Add a JS SDK
- Add tests
