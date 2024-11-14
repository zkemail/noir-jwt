# Noir JWT Verifier

[Noir](https://noir-lang.org/) library to verify JWT tokens, and prove claims. Currently only supports RS256 with 2048 bit keys.

- Supports arbitrary sized inputs.
- Supports partial hashing on the input.
- Uses [string_search](https://github.com/noir-lang/noir_string_search) lib to extract and verify claims efficiently.


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

fn main(
    data: BoundedVec<u8, MAX_DATA_LENGTH>,
    b64_offset: u32,
    pubkey_modulus_limbs: pub [Field; 18],
    redc_params_limbs: [Field; 18],
    signature_limbs: [Field; 18],
    domain: pub BoundedVec<u8, MAX_DOMAIN_LENGTH>,
    nonce: pub BoundedVec<u8, NONCE_LENGTH>,
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
    jwt.validate_key_value::<300, 5, NONCE_LENGTH>("nonce".as_bytes(), nonce);
}
```

#### With partial hash

```noir
use dep::jwt::JWT;

fn main(
    partial_data: BoundedVec<u8, MAX_PARTIAL_DATA_LENGTH>,
    partial_hash: [u32; 8],
    full_data_length: u32,
    b64_offset: u32,
    pubkey_modulus_limbs: pub [Field; 18],
    redc_params_limbs: [Field; 18],
    signature_limbs: [Field; 18],
    nonce: pub BoundedVec<u8, NONCE_LENGTH>,
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
    jwt.validate_key_value::<300, 5, NONCE_LENGTH>("nonce".as_bytes(), nonce);
}
```

- `b64_offset` is the index in `data` from which the circuit will try to decode the base64
    - You can set this to the index of payload data (index after first `.` in the JWT string)
    - When using partial SHA, this should be 1, 2, or 3 to make the data after partial hash a multiple of 4
- `300` in the above example is the max length in the decoded payload to look for the key value pair (from the b64_offset)
    - Due to a limitation mentioned below, this range should contain valid payload when base64 decoded (not the padding chars)
    - This makes it difficult to verify key/value if they are the last key in the payload

## Input generation from JS

A JS SDK will be released soon to generate the inputs for Noir. In the meantime, refer to this [example](https://github.com/saleel/stealthnote/blob/main/app/lib/utils.ts#L514-L534).


## Limitation

Base64 does not support variable length in put now. Due to this you need to specify a RANGE when calling `validate_key_value` which should always contain some data in the payload.
This will be fixed in a future release.
