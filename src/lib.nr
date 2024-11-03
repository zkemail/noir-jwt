use dep::std::hash::sha256_var;
use dep::noir_rsa::bignum::BigNum;
use dep::noir_rsa::bignum::runtime_bignum::BigNumInstance;
use dep::noir_rsa::bignum::fields::Params2048;
use dep::noir_rsa::types::RSA;
use dep::string_search::{SubString, StringBody, SubString32, SubString64, StringBody256};
use dep::noir_base64::base64_decode;
use dep::zkemail::{partial_hash::partial_sha256_var_end};

global MAX_PARTIAL_DATA_LENGTH: u32 = 640; // Data after partial SHA
global MAX_DOMAIN_LENGTH: u32 = 50;
global NONCE_LENGTH: u32 = 32;
global B64_DECODE_LENGTH: u32 = 240; // Length of b64 data to be coded (we only need hd and nonce)
global ENCODED_PAYLOAD_LENGTH: u32 = B64_DECODE_LENGTH * 3 / 4;

type BN2048 = BigNum<18, Params2048>;
type RSA2048 = RSA<BN2048, BigNumInstance<18, Params2048>, 256>;

/**
 * @brief Verify JWT signature (RSA/SHA256 only) and validate hd and nonce fields
 *
 **/
pub struct JWT<let DATA_LENGTH: u32> {
    data: BoundedVec<u8, DATA_LENGTH>,
    partial_hash: [u32; 8],
    full_data_length: u32,
    b64_offset: u32,
    pubkey_modulus_limbs: [Field; 18],
    redc_params_limbs: [Field; 18],
    signature_limbs: [Field; 18],

    is_partial_hash: bool,
    haystack: StringBody<((DATA_LENGTH + 31) / 31) * 31, (DATA_LENGTH + 31) / 31, DATA_LENGTH>,
}

impl<let DATA_LENGTH: u32> JWT<DATA_LENGTH> {
    /**
    * @brief Initialize JWT with partial hash

    * @param partial_data: OIDC JWT (id_token) base64 data (`$header.$payload`) as byte array of ascii characters
    *                      We do partial SHA on the data up to "hd" field outside of the circuit, to reduce constraints
    *                      This field only contains the bytes after partial SHA; padded to MAX_PARTIAL_DATA_LENGTH
    * @param partial_data_length: The actual length of the `partial_data`
    * @param partial_hash: The 256-bit partial hash of the `data`
    * @param data_length: The full length of the `data` (before partial SHA)
    * @param b64_offset: Offset needed in `partial_data` to make the payloadB64 a multiple of 4
    *                    Signed data is "$header.$payload". $payload might not be a multiple of 4 in `partial_data`, so we need to offset
    *                    Not attack-able by giving an incorrect offset, as string match of "hd" and "nonce" will fail
    * @param pubkey_modulus_limbs: RSA public key modulus limbs (2048-bit split into 18 limbs)
    * @param redc_params_limbs: RSA reduction parameters limbs
    * @param signature_limbs: RSA signature limbs
    * @param domain_name: Domain name (`hd` key) as a byte array of ascii characters padded to MAX_DOMAIN_LENGTH
    * @param domain_name_length: The actual length of the `domain_name`
    * @param nonce: JWT `nonce` as a byte array of ascii characters - 32 bytes
    **/
    pub fn init(
        data: BoundedVec<u8, DATA_LENGTH>,
        pubkey_modulus_limbs: [Field; 18],
        redc_params_limbs: [Field; 18],
        signature_limbs: [Field; 18]
    ) -> JWT<DATA_LENGTH> {
        let haystack: StringBody<((DATA_LENGTH + 31) / 31) * 31, (DATA_LENGTH + 31) / 31, DATA_LENGTH> = StringBody::new(data.storage, data.len());
        JWT {
            data,
            full_data_length: DATA_LENGTH,
            partial_hash: [0; 8],
            b64_offset: 0,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
            is_partial_hash: false,
            haystack
        }
    }

    /**
    * @brief Initialize JWT with partial hash

    * @param partial_data: OIDC JWT (id_token) base64 data (`$header.$payload`) as byte array of ascii characters
    *                      We do partial SHA on the data up to "hd" field outside of the circuit, to reduce constraints
    *                      This field only contains the bytes after partial SHA; padded to MAX_PARTIAL_DATA_LENGTH
    * @param partial_data_length: The actual length of the `partial_data`
    * @param partial_hash: The 256-bit partial hash of the `data`
    * @param data_length: The full length of the `data` (before partial SHA)
    * @param b64_offset: Offset needed in `partial_data` to make the payloadB64 a multiple of 4
    *                    Signed data is "$header.$payload". $payload might not be a multiple of 4 in `partial_data`, so we need to offset
    *                    Not attack-able by giving an incorrect offset, as string match of "hd" and "nonce" will fail
    * @param pubkey_modulus_limbs: RSA public key modulus limbs (2048-bit split into 18 limbs)
    * @param redc_params_limbs: RSA reduction parameters limbs
    * @param signature_limbs: RSA signature limbs
    * @param domain_name: Domain name (`hd` key) as a byte array of ascii characters padded to MAX_DOMAIN_LENGTH
    * @param domain_name_length: The actual length of the `domain_name`
    * @param nonce: JWT `nonce` as a byte array of ascii characters - 32 bytes
    **/
    pub fn init_with_partial_hash(
        partial_data: BoundedVec<u8, DATA_LENGTH>,
        full_data_length: u32,
        b64_offset: u32,
        partial_hash: [u32; 8],
        pubkey_modulus_limbs: [Field; 18],
        redc_params_limbs: [Field; 18],
        signature_limbs: [Field; 18]
    ) -> JWT<DATA_LENGTH> {
        let haystack: StringBody<((DATA_LENGTH + 31) / 31) * 31, (DATA_LENGTH + 31) / 31, DATA_LENGTH> = StringBody::new(partial_data.storage, partial_data.len());
        JWT {
            data: partial_data,
            full_data_length,
            partial_hash,
            b64_offset,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
            is_partial_hash: true,
            haystack
        }
    }

    pub fn verify(self) {
        assert(self.data.len() < DATA_LENGTH, "partial_data_length is too long");

        let mut data_hash: [u8; 32] = [0; 32];

        if (!self.is_partial_hash) {
            // Hash the data using SHA256
            data_hash = sha256_var(self.data.storage, self.data.len() as u64);
        } else {
            data_hash = partial_sha256_var_end(
                self.partial_hash,
                self.data.storage,
                self.data.len() as u64,
                self.full_data_length as u64
            );
        }

        // Verify RSA signature
        let rsa: RSA2048 = RSA {};
        let pubkey: BigNumInstance<18, Params2048> = BigNumInstance::new(self.pubkey_modulus_limbs, self.redc_params_limbs);
        let signature: BN2048 = BigNum::from_array(self.signature_limbs);
        assert(
            rsa.verify_sha256_pkcs1v15(pubkey, data_hash, signature, 65537), "RSA signature verification failed"
        );
    }

    pub fn validate_key<let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(self, key: [u8; KEY_LENGTH], value: BoundedVec<u8, MAX_VALUE_LENGTH>) {
        assert(value.len() < MAX_VALUE_LENGTH, "value length is too long");

        let mut prefix: [u8; KEY_LENGTH + 3] = [0; KEY_LENGTH + 3];
        prefix[0] = "\"".as_bytes()[0];
        for i in 0..KEY_LENGTH {
            prefix[i + 1] = key[i];
        }
        prefix[KEY_LENGTH] = "\"".as_bytes()[0];
        prefix[KEY_LENGTH + 1] = ":".as_bytes()[0];

        let hd_prefix_substring: SubString32 = SubString::new(prefix, prefix.len());
        let domain_substring: SubString64 = SubString::new(value.storage, value.len());
        let domain_needle = hd_prefix_substring.concat_into(domain_substring);

        let (domain_found, domain_position): (bool, u32) = self.haystack.substring_match(domain_needle);
        assert(domain_found, "domain not found");
        // Assert the value after hd value is a `"` - to prevent partial match attacks
        assert(self.data.storage[domain_position + domain_needle.len()] == 34, "incorrect domain");
    }
}
