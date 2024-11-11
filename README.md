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
    pubkey_modulus_limbs: pub [Field; 18],
    redc_params_limbs: [Field; 18],
    signature_limbs: [Field; 18],
    domain: pub BoundedVec<u8, MAX_DOMAIN_LENGTH>,
    nonce: pub BoundedVec<u8, NONCE_LENGTH>,
) {
    let jwt = JWT::init(
        data,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();
    jwt.validate_key_value("nonce".as_bytes(), nonce);
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

    jwt.validate_key_value("nonce".as_bytes(), nonce);
}
```

## Limitation

Partial hash is not fully supported yet due to a limitation in the base64 lib. It currently works using a hack where it assumes the data you want to retrieve is within `MAX_LENGTH - 64` bytes of the data. This will be fixed in a future release.
