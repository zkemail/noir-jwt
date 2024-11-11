use dep::std::hash::sha256_var;
use dep::bignum::{params::BigNumParams, RuntimeBigNum};
use dep::rsa::{rsa::verify_sha256_pkcs1v15, types::RBN2048};
use dep::string_search::{SubString, StringBody};
use dep::base64::{BASE64_URL_DECODER};
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

    // For internal use
    is_partial_hash: bool,
    // Haystack for substring matching in validate_key()
    haystack: StringBody<((DATA_LENGTH + 31) / 31) * 31, (DATA_LENGTH + 31) / 31, DATA_LENGTH>,
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
        pubkey_modulus_limbs: [Field; 18],
        redc_params_limbs: [Field; 18],
        signature_limbs: [Field; 18],
    ) -> JWT<DATA_LENGTH> {
        assert(data.len() < DATA_LENGTH, "data length is too long");

        // Decode base64 and prepare a haystack for substring matching in validate_key_value()
        let payload: [u8; (DATA_LENGTH + 3) / 4 * 3] = BASE64_URL_DECODER.decode(data.storage);

        // StringBody is constructed with <ceil(length / 31) * 31, ceil(length / 31), length>
        let haystack: StringBody<((DATA_LENGTH + 31) / 31) * 31, (DATA_LENGTH + 31) / 31, DATA_LENGTH> =
            StringBody::new(payload, payload.len());

        JWT {
            data,
            full_data_length: DATA_LENGTH,
            partial_hash: [0; 8],
            b64_offset: 0,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
            is_partial_hash: false,
            haystack,
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
        assert(partial_data.len() < DATA_LENGTH, "partial_data length is too long");

        // Decode base64 and prepare a haystack for substring matching in validate_key_value()
        // Apply the offset to the partial data to make the partial base64 chunk decodable (multiple of 4)
        // TODO: `DATA_LENGTH - 32 is` arbitrary, this should be replaced with _var version of base64 when ready
        let mut payload_b64: [u8; (DATA_LENGTH - 32)] = [0; (DATA_LENGTH - 32)];
        for i in 0..(DATA_LENGTH - 32) {
            payload_b64[i] = partial_data.storage[i + b64_offset];
        }
        let payload: [u8; ((DATA_LENGTH - 32) + 3) / 4 * 3] = BASE64_URL_DECODER.decode(payload_b64); // b64 decoded length is ceil(DATA_LENGTH / 3) * 4
        let haystack: StringBody<((DATA_LENGTH + 31) / 31) * 31, (DATA_LENGTH + 31) / 31, DATA_LENGTH> =
            StringBody::new(payload, payload.len());

        JWT {
            data: partial_data,
            full_data_length,
            partial_hash,
            b64_offset,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
            is_partial_hash: true,
            haystack,
        }
    }

    /**
    * @brief Verify JWT signature with RSA 2048/SHA256
    **/
    pub fn verify(self) {
        let mut data_hash: [u8; 32] = [0; 32];

        if (!self.is_partial_hash) {
            // Hash the data using SHA256
            data_hash = sha256_var(self.data.storage, self.data.len() as u64);
        } else {
            // Compute the full SHA256 hash with the partial hash
            data_hash = partial_sha256_var_end(
                self.partial_hash,
                self.data.storage,
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
    **/
    pub fn validate_key_value<let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        key: [u8; KEY_LENGTH],
        value: BoundedVec<u8, MAX_VALUE_LENGTH>,
    ) {
        assert(value.len() < MAX_VALUE_LENGTH, "value length is too long");

        // Search for "$key":"$value and assert the character after match is a `"`
        // json_key = "$key":
        let mut json_key: [u8; KEY_LENGTH + 3] = [0; KEY_LENGTH + 3]; // +3 is for two quotes and a colon
        json_key[0] = 34; // "
        for i in 0..KEY_LENGTH {
            json_key[i + 1] = key[i];
        }
        json_key[KEY_LENGTH] = 34; // "
        json_key[KEY_LENGTH + 1] = 58; // :
        // SubString is constructed with <ceil(length / 31) * 31, length / 31, length>
        // length = KEY_LENGTH + 3
        let json_key_substring: SubString<((KEY_LENGTH + 3 + 31) / 31) * 31, (KEY_LENGTH + 3) / 31, KEY_LENGTH + 3> =
            SubString::new(json_key, json_key.len());
        // length = KEY_LENGTH + 3 + MAX_VALUE_LENGTH
        let value_substring: SubString<((KEY_LENGTH + 3 + MAX_VALUE_LENGTH + 31) / 31) * 31, (KEY_LENGTH + 3 + MAX_VALUE_LENGTH) / 31, KEY_LENGTH + 3 + MAX_VALUE_LENGTH> =
            SubString::new(value.storage, value.len());

        // Concatenate json_key_substring and value_substring to form the search term
        let needle = json_key_substring.concat_into(value_substring);

        let (match, position): (bool, u32) = self.haystack.substring_match(needle);
        assert(match, "key value pair not found");

        // Assert the value after search term is a `"`
        assert(self.data.storage[position + needle.len()] == 34, "incorrect value");
    }
}
