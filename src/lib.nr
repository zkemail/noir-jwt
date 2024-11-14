use dep::std::hash::sha256_var;
use dep::bignum::{params::BigNumParams, RuntimeBigNum};
use dep::rsa::{rsa::verify_sha256_pkcs1v15, types::RBN2048};
use dep::string_search::{SubString, StringBody};
use dep::base64::BASE64_URL_DECODER;
use dep::zkemail::partial_hash::partial_sha256_var_end;

/**
 * @brief Struct representing a JWT. Use the init functions to create an instance
 *        Currently only supports RSA 2048/SHA256 signatures
 **/
pub struct JWT<let DATA_LENGTH: u32> {
    data: BoundedVec<u8, DATA_LENGTH>,
    pubkey_modulus_limbs: [Field; 18],
    redc_params_limbs: [Field; 18],
    signature_limbs: [Field; 18],
    partial_hash: [u32; 8],
    full_data_length: u32,
    b64_offset: u32,
    is_partial_hash: bool, // used internally
}

impl<let DATA_LENGTH: u32> JWT<DATA_LENGTH> {
    /**
    * @brief Initialize JWT struct
    *
    * @param data: Signed JWT data (base64 encoded `$header.$payload`) as byte array of ascii characters
    * @param pubkey_modulus_limbs: RSA public key modulus limbs (2048-bit split into 18 limbs)
    * @param redc_params_limbs: RSA reduction parameters limbs (2048-bit split into 18 limbs)
    * @param signature_limbs: RSA signature limbs (2048-bit split into 18 limbs)
    **/
    pub fn init(
        data: BoundedVec<u8, DATA_LENGTH>,
        b64_offset: u32,
        pubkey_modulus_limbs: [Field; 18],
        redc_params_limbs: [Field; 18],
        signature_limbs: [Field; 18],
    ) -> JWT<DATA_LENGTH> {
        assert(data.len() <= DATA_LENGTH, "data length is too long");

        JWT {
            data,
            full_data_length: DATA_LENGTH,
            partial_hash: [0; 8],
            b64_offset: b64_offset,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
            is_partial_hash: false,
        }
    }

    /**
    * @brief Initialize JWT with partial SHA256 hash'ed input

    * @param partial_data: Signed JWT data (base64 encoded `$header.$payload`) after partial SHA256 hashed block
    * @param partial_hash: The 256-bit partial hash of the `partial_data` up to a certain block
    * @param full_data_length: The full length of the `data` (before partial SHA)
    * @param b64_offset: Offset needed in `partial_data` to make the payloadB64 a multiple of 4 (for base64 decoding)
    *                    Not attack-able by giving an incorrect offset, as key-value matches will fail with incorrectly decoded payload
    * @param pubkey_modulus_limbs: RSA public key modulus limbs (2048-bit split into 18 limbs)
    * @param redc_params_limbs: RSA reduction parameters limbs
    * @param signature_limbs: RSA signature limbs
    **/
    pub fn init_with_partial_hash(
        partial_data: BoundedVec<u8, DATA_LENGTH>,
        partial_hash: [u32; 8],
        full_data_length: u32,
        b64_offset: u32,
        pubkey_modulus_limbs: [Field; 18],
        redc_params_limbs: [Field; 18],
        signature_limbs: [Field; 18],
    ) -> JWT<DATA_LENGTH> {
        assert(partial_data.len() <= DATA_LENGTH, "partial_data length is too long");

        JWT {
            data: partial_data,
            full_data_length,
            partial_hash,
            b64_offset,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
            is_partial_hash: true,
        }
    }

    /**
    * @brief Verify JWT signature with RSA 2048/SHA256
    **/
    pub fn verify(self) {
        let mut data_hash: [u8; 32] = [0; 32];

        if (!self.is_partial_hash) {
            // Hash the data using SHA256
            data_hash = sha256_var(self.data.storage(), self.data.len() as u64);
        } else {
            // Compute the full SHA256 hash with the partial hash
            data_hash = partial_sha256_var_end(
                self.partial_hash,
                self.data.storage(),
                self.data.len() as u64,
                self.full_data_length as u64,
            );
        }

        // Verify RSA signature
        let params: BigNumParams<18, 2048> =
            BigNumParams::new(false, self.pubkey_modulus_limbs, self.redc_params_limbs);

        let signature: RBN2048 = RuntimeBigNum::from_array(params, self.signature_limbs);

        assert(verify_sha256_pkcs1v15(data_hash, signature, 65537));
    }

    /**
    * @brief Checks if a key-value pair exists in the JWT payload
    *
    * RANGE is the index in the data up to which we will look for the key:value pair.
    * It is also required that the every byte up to RANGE should be a valid character after base64 decode.
    * This is necessary now due to a limitation in base64.
    **/
    pub fn validate_key_value<let RANGE: u32, let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        key: [u8; KEY_LENGTH],
        value: BoundedVec<u8, MAX_VALUE_LENGTH>,
    ) {
        assert(RANGE % 3 == 0, "range should be a multiple of 3");
        assert(RANGE <= self.data.len(), "range should be less than data length");
        assert(value.len() <= MAX_VALUE_LENGTH, "value length is too long");

        // Prepare base64 payload to decode
        // Only in partial sha - shift input chars by offset so the partial data is base64 decodable (multiple of 4)
        let mut payload_b64: [u8; RANGE / 3 * 4] = [0; RANGE / 3 * 4];
        for i in 0..RANGE / 3 * 4 {
            payload_b64[i] = self.data.storage()[(i + self.b64_offset)];
        }

        // Decode base64 and prepare a haystack for substring matching in validate_key_value() with decoded payload
        let payload: [u8; RANGE] = BASE64_URL_DECODER.decode(payload_b64); // b64 decoded length is ceil(DATA_LENGTH / 3) * 4

        // StringBody is constructed with <ceil(length / 31) * 31, ceil(length / 31), length>
        let haystack: StringBody<((RANGE + 31) / 31) * 31, (RANGE + 31) / 31, RANGE> =
            StringBody::new(payload, payload.len());

        // Search for "$key":"$value and assert the character after match is a `"`
        // json_key = "$key":"
        let mut json_key: [u8; KEY_LENGTH + 4] = [0; KEY_LENGTH + 4]; // +4 is for two quotes and two colon
        json_key[0] = 34; // "
        for i in 0..KEY_LENGTH {
            json_key[i + 1] = key[i];
        }
        json_key[KEY_LENGTH + 1] = 34; // "
        json_key[KEY_LENGTH + 2] = 58; // :
        json_key[KEY_LENGTH + 3] = 34; // "

        // SubString is constructed with <ceil(length / 31) * 31, length / 31, length>
        // length = KEY_LENGTH + 3
        let json_key_substring: SubString<((KEY_LENGTH + 4 + 31) / 31) * 31, (KEY_LENGTH + 4) / 31, KEY_LENGTH + 4> =
            SubString::new(json_key, json_key.len());
        
        // value length = KEY_LENGTH + 3 + MAX_VALUE_LENGTH
        let value_substring: SubString<((KEY_LENGTH + 4 + MAX_VALUE_LENGTH + 31) / 31) * 31, (KEY_LENGTH + 4 + MAX_VALUE_LENGTH) / 31, KEY_LENGTH + 4 + MAX_VALUE_LENGTH> =
            SubString::new(value.storage(), value.len());

        // Concatenate json_key_substring and value_substring to form the search term
        let needle = json_key_substring.concat_into(value_substring);

        let (match, position): (bool, u32) = haystack.substring_match(needle);
        assert(match, "key value pair not found");

        // Assert the value after search term is a `"`
        assert(payload[position + needle.len()] == 34, "incorrect value");
    }
}
