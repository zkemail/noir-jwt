mod partial_hash;

use base64::BASE64_URL_DECODER;
use bignum::{params::BigNumParams, RuntimeBigNum};
use nodash::str_to_u64;
use partial_hash::partial_sha256_var_end;
use rsa::rsa::verify_sha256_pkcs1v15;
use sha256::sha256_var;
use string_search::{StringBody, SubString};

/**
 * @brief Struct representing a JWT. Use the init functions to create an instance
 *        Currently only supports RSA 2048/SHA256 signatures
 **/
pub struct JWT<let MAX_DATA_LENGTH: u32> {
    data: BoundedVec<u8, MAX_DATA_LENGTH>,
    pubkey_modulus_limbs: [u128; 18],
    redc_params_limbs: [u128; 18],
    signature_limbs: [u128; 18],
    partial_hash: [u32; 8],
    full_data_length: u32,
    base64_decode_offset: u32,
    is_partial_hash: bool, // compile time variable used internally
}

impl<let MAX_DATA_LENGTH: u32> JWT<MAX_DATA_LENGTH> {
    /**
    * @brief Initialize JWT struct
    *
    * @param data: Signed JWT data (base64 encoded `$header.$payload`) as byte array of ascii characters
    * @param base64_decode_offset: The offset from which we will start base64 decoding the data.
    *                                   Any 4x multiple from the payload start index.
    * @param pubkey_modulus_limbs: RSA public key modulus limbs (2048-bit split into 18 limbs)
    * @param redc_params_limbs: RSA reduction parameters limbs (2048-bit split into 18 limbs)
    * @param signature_limbs: RSA signature limbs (2048-bit split into 18 limbs)
    **/
    pub fn init(
        data: BoundedVec<u8, MAX_DATA_LENGTH>,
        base64_decode_offset: u32,
        pubkey_modulus_limbs: [u128; 18],
        redc_params_limbs: [u128; 18],
        signature_limbs: [u128; 18],
    ) -> JWT<MAX_DATA_LENGTH> {
        assert(data.len() <= MAX_DATA_LENGTH, "data length is too long");

        JWT {
            data,
            base64_decode_offset,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
            // below fields are not relevant unless for partial hash
            full_data_length: MAX_DATA_LENGTH,
            partial_hash: [0; 8],
            is_partial_hash: false,
        }
    }

    /**
    * @brief Initialize JWT with partial SHA256 hash'ed input
    *        Since SHA hash is expensive to compute in circuit, we can optimize by pre-hashing up to a certain block outside the circuit,
    *        and verify for correctness in the circuit. This is possible since SHA works in incremental blocks.
    *        You can pre-hash up to the SHA-256 block from where you want to extract a claim.
    *
    * @param partial_data: Signed JWT data (base64 encoded `$header.$payload`) after partial hashed block
    * @param partial_hash: The 256-bit partial hash of the `partial_data` up to a certain block
    * @param full_data_length: The full length of the `data` (before partial SHA)
    * @param base64_decode_offset: The offset from which we will start base64 decoding the data.
    *                                   Trimming `offset` nubmer of bytes from the data should it base64 decode-able.
    * @param pubkey_modulus_limbs: RSA public key modulus limbs (2048-bit split into 18 limbs)
    * @param redc_params_limbs: RSA reduction parameters limbs
    * @param signature_limbs: RSA signature limbs
    **/
    pub fn init_with_partial_hash(
        partial_data: BoundedVec<u8, MAX_DATA_LENGTH>,
        partial_hash: [u32; 8],
        full_data_length: u32,
        base64_decode_offset: u32,
        pubkey_modulus_limbs: [u128; 18],
        redc_params_limbs: [u128; 18],
        signature_limbs: [u128; 18],
    ) -> JWT<MAX_DATA_LENGTH> {
        assert(partial_data.len() <= MAX_DATA_LENGTH, "partial_data length is too long");

        JWT {
            data: partial_data,
            full_data_length,
            partial_hash,
            base64_decode_offset,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
            is_partial_hash: true,
        }
    }

    /**
    * @brief Verify JWT signature with RSA 2048/SHA256
    **/
    pub fn verify(mut self) {
        let mut data_hash: [u8; 32] = [0; 32];

        if (!self.is_partial_hash) {
            // this is a compile time conditional
            // Hash the data using SHA256
            data_hash = sha256_var(self.data.storage(), self.data.len() as u64);
        } else {
            // Compute the full SHA256 hash with the given partial hash
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

        let signature = RuntimeBigNum { params, limbs: self.signature_limbs };

        assert(verify_sha256_pkcs1v15(data_hash, signature, 65537));
    }

    /**
    * @brief Get a string claim from the JWT payload
    *
    * @param KEY_LENGTH: The length of the claim key
    * @param MAX_VALUE_LENGTH: The maximum length of the claim value
    * @param claim_key: The claim key
    * @return: The claim value
    **/
    pub fn get_claim_string<let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        claim_key: [u8; KEY_LENGTH],
    ) -> BoundedVec<u8, MAX_VALUE_LENGTH> {
        self.get_claim::<KEY_LENGTH, MAX_VALUE_LENGTH>(claim_key, true)
    }

    /**
    * @brief Assert a string claim in the JWT payload.
    *        Refer to `get_claim_string` for details on the `KEY_LENGTH` and `MAX_VALUE_LENGTH`.
    * @param claim_key: The claim key
    * @param claim_value: The claim value to assert
    **/
    pub fn assert_claim_string<let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        claim_key: [u8; KEY_LENGTH],
        claim_value: BoundedVec<u8, MAX_VALUE_LENGTH>,
    ) {
        let value: BoundedVec<u8, MAX_VALUE_LENGTH> =
            self.get_claim_string::<KEY_LENGTH, MAX_VALUE_LENGTH>(claim_key);
        assert(value == claim_value, "incorrect value for claim");
    }

    /**
    * @brief Get a number (u64) claim from the JWT payload
    *        Refer to `get_claim_string` for details on the `KEY_LENGTH` and `MAX_VALUE_LENGTH`.
    * @param claim_key: The claim key
    * @return: The claim value
    **/
    pub fn get_claim_number<let KEY_LENGTH: u32>(self, claim_key: [u8; KEY_LENGTH]) -> u64 {
        let claim = self.get_claim::<KEY_LENGTH, 20>(claim_key, false);
        str_to_u64(claim.storage())
    }

    /**
    * @brief Assert a number (u64) claim in the JWT payload.
    *        Refer to `get_claim_number` for details on the `KEY_LENGTH` and `MAX_VALUE_LENGTH`.
    * @param claim_key: The claim key
    * @param claim_value: The claim value to assert
    **/
    pub fn assert_claim_number<let KEY_LENGTH: u32>(
        self,
        claim_key: [u8; KEY_LENGTH],
        claim_value: u64,
    ) {
        let value = self.get_claim_number::<KEY_LENGTH>(claim_key);
        assert(value == claim_value, "incorrect value for claim");
    }

    /**
    * @brief Get a boolean claim from the JWT payload
    * @param claim_key: The claim key
    * @return: The claim value
    **/
    pub fn get_claim_bool<let KEY_LENGTH: u32>(self, claim_key: [u8; KEY_LENGTH]) -> bool {
        let value = self.get_claim::<KEY_LENGTH, 5>(claim_key, false);
        let mut is_true = true;
        for i in 0..4 {
            is_true = is_true & (value.storage()[i] == "true".as_bytes()[i]);
        }
        let is_false = value.storage() == "false".as_bytes();

        assert(is_true | is_false, "incorrect value for claim");
        is_true
    }

    /**
    * @brief Assert a boolean claim in the JWT payload.
    *        Refer to `get_claim_bool` for details on the `KEY_LENGTH` and `MAX_VALUE_LENGTH`.
    * @param claim_key: The claim key
    * @param claim_value: The claim value to assert
    **/
    pub fn assert_claim_bool<let KEY_LENGTH: u32>(
        self,
        claim_key: [u8; KEY_LENGTH],
        claim_value: bool,
    ) {
        let value = self.get_claim_bool::<KEY_LENGTH>(claim_key);
        assert(value == claim_value, "incorrect value for claim");
    }

    /**
    * @brief Internal function to get claim bytes from the JWT payload
    **/
    fn get_claim<let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        claim_key: [u8; KEY_LENGTH],
        is_value_quoted: bool,
    ) -> BoundedVec<u8, MAX_VALUE_LENGTH> {
        //Safety: extract the value in unconstrained mode, and verify later
        let value: BoundedVec<u8, MAX_VALUE_LENGTH> = unsafe {
            self.extract_claim_unconstrained::<KEY_LENGTH, MAX_VALUE_LENGTH>(
                claim_key,
                is_value_quoted,
            )
        };

        // constrain the extracted value is present in the payload using string_search lib
        // haystack is the base64 decoded payload;
        let haystack = self.prepare_haystack();

        // needle is the key with quotes around it - searching for just the key string might return false positives from elsewhere
        // Note: key length is known at compile time as this lib doesn't support runtime keys
        let mut key_with_quote: [u8; KEY_LENGTH + 2] = [0; KEY_LENGTH + 2];
        key_with_quote[0] = 34; // ascii for quote
        for i in 0..KEY_LENGTH {
            key_with_quote[i + 1] = claim_key[i];
        }
        key_with_quote[KEY_LENGTH + 1] = 34; // ascii for quote

        let mut needle: SubString<(((KEY_LENGTH + 2) + 31) / 31) * 31, (KEY_LENGTH + 2) / 31, (KEY_LENGTH + 2)> =
            SubString::new(key_with_quote, key_with_quote.len());

        let (result, position): (bool, u32) = haystack.substring_match(needle);
        assert(result, "key not found in the payload");

        // assert value after quoted key is a colon
        let colon_index = position + KEY_LENGTH + 2; // +2 for the quotes around the key
        assert(haystack.body[colon_index] == 58); // :

        // assert the value is correct - string have quotes around them, numbers and booleans don't
        let mut value_start_index = colon_index + 1; // Value starts after the colon
        let mut index_after_value = value_start_index + value.len(); // Index after the value, quoted or otherwise

        if (is_value_quoted) {
            // adjust start index for the quotes around the value
            value_start_index = value_start_index + 1; // Adjust for the quote before the value
            index_after_value = index_after_value + 2; // Adjust for the quotes around the value

            // assert the char before and after the value is a quote
            assert(haystack.body[value_start_index - 1] == 34); // "
            assert(haystack.body[index_after_value - 1] == 34); // "
        }

        // assert the value is correct
        for i in 0..MAX_VALUE_LENGTH {
            if (i < value.len()) {
                assert(haystack.body[value_start_index + i] == value.storage()[i]);
            }
        }

        // assert the char after the value is a comma or a closing brace (last claim in the payload)
        let char_after_value = haystack.body[index_after_value];
        assert((char_after_value == 44) | (char_after_value == 125)); // , or }

        value
    }

    /**
    * @brief Internal function to prepare the haystack for string search (base64 decoded payload with offset applied)
    **/
    fn prepare_haystack(
        self,
    ) -> StringBody<((((MAX_DATA_LENGTH / 4) * 3) + 31) / 31) * 31, (((MAX_DATA_LENGTH / 4) * 3) + 31) / 31, ((MAX_DATA_LENGTH / 4) * 3)> {
        // We need to decode the payload from the payload_b64_offset; i.e. data.slice(0, base64_decode_offset)
        let mut data_to_b64_decode: [u8; MAX_DATA_LENGTH] = [0; MAX_DATA_LENGTH];

        // Conditional inside the for loop blows up the constraint size
        // So we fill the full MAX_DATA_LENGTH (rotate on overflow) and prepare a BoundedVec with the correct length later
        for i in 0..MAX_DATA_LENGTH {
            data_to_b64_decode[i] =
                self.data.storage()[(i + self.base64_decode_offset) % self.data.len()];
        }

        let data_to_decode_bv: BoundedVec<u8, MAX_DATA_LENGTH> = BoundedVec::from_parts(
            data_to_b64_decode,
            self.data.len() - self.base64_decode_offset,
        );

        // Decode the payload
        let payload: BoundedVec<u8, ((MAX_DATA_LENGTH / 4) * 3)> =
            BASE64_URL_DECODER::decode_var(data_to_decode_bv); // b64 decoded length is ceil(MAX_DATA_LENGTH / 3) * 4

        // Create the haystack
        let haystack: StringBody<((((MAX_DATA_LENGTH / 4) * 3) + 31) / 31) * 31, (((MAX_DATA_LENGTH / 4) * 3) + 31) / 31, ((MAX_DATA_LENGTH / 4) * 3)> =
            StringBody::new(payload.storage(), payload.len());

        haystack
    }

    /**
    * @brief Unconstrained function to extract claim bytes from the JWT payload
    **/
    pub unconstrained fn extract_claim_unconstrained<let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        key: [u8; KEY_LENGTH],
        is_value_quoted: bool,
    ) -> BoundedVec<u8, MAX_VALUE_LENGTH> {
        let haystack = self.prepare_haystack();

        let mut key_with_quote: [u8; KEY_LENGTH + 2] = [0; KEY_LENGTH + 2];
        key_with_quote[0] = 34; // ascii for quote
        for i in 0..KEY_LENGTH {
            key_with_quote[i + 1] = key[i];
        }
        key_with_quote[KEY_LENGTH + 1] = 34; // ascii for quote

        let mut needle: SubString<(((KEY_LENGTH + 2) + 31) / 31) * 31, (KEY_LENGTH + 2) / 31, (KEY_LENGTH + 2)> =
            SubString::new(key_with_quote, key_with_quote.len());

        let (result, position): (bool, u32) = haystack.substring_match(needle);
        assert(result, "key not found in the payload");

        // Get the value after the key
        let mut value_start_idx = position + key.len() + 3; // +3 for the quote around the key and the colon
        if (is_value_quoted) {
            value_start_idx += 1; // +1 for the quote before the value
        }

        let mut value: BoundedVec<u8, MAX_VALUE_LENGTH> = BoundedVec::new();

        for i in 0..MAX_VALUE_LENGTH {
            let val = haystack.body[value_start_idx + i];
            if ((val == 34) | (val == 44) | (val == 125)) {
                break;
            }
            value.push(haystack.body[value_start_idx + i]);
        }

        value
    }
}

#[test]
fn test_verify() {
    let pubkey_modulus_limbs = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];
    let redc_params_limbs = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];
    let signature_limbs = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120,
        102, 100, 109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85,
        115, 73, 109, 53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73,
        122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74,
        104, 98, 71, 108, 106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115,
        73, 109, 108, 104, 100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78,
        121, 119, 105, 89, 88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84,
        73, 122, 76, 106, 81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86,
        52, 99, 67, 73, 54, 77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48,
    ]);
    let base64_decode_offset = 37;

    let jwt = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();
}

#[test]
fn test_verify_partial_hash() {
    let pubkey_modulus_limbs = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];
    let redc_params_limbs = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];
    let signature_limbs = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];
    let partial_data: BoundedVec<u8, 256> = BoundedVec::from_array([
        106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107, 78, 69,
        77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120, 102, 100,
        109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85, 115, 73, 109,
        53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84, 73,
        122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74, 104, 98, 71, 108,
        106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115, 73, 109, 108, 104,
        100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78, 121, 119, 105, 89,
        88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84, 73, 122, 76, 106,
        81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86, 52, 99, 67, 73, 54,
        77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48,
    ]);
    let base64_decode_offset = 1;
    let partial_hash = [
        2065651337, 2814693704, 862745553, 2384319000, 1412758034, 3553265356, 3156727610,
        4160738201,
    ];
    let full_data_length = 268;

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
}

#[test]
fn test_get_claim_string() {
    let pubkey_modulus_limbs = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];
    let redc_params_limbs = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];
    let signature_limbs = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120,
        102, 100, 109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85,
        115, 73, 109, 53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73,
        122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74,
        104, 98, 71, 108, 106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115,
        73, 109, 108, 104, 100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78,
        121, 119, 105, 89, 88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84,
        73, 122, 76, 106, 81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86,
        52, 99, 67, 73, 54, 77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48,
    ]);
    let base64_decode_offset = 37;

    let jwt = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    let email: BoundedVec<u8, 100> = jwt.get_claim_string("email".as_bytes());
    let expected_email: BoundedVec<u8, 100> = BoundedVec::from_array("alice@test.com".as_bytes());
    assert(email == expected_email);
}

#[test]
fn test_get_claim_string_partial_hash() {
    let pubkey_modulus_limbs = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];
    let redc_params_limbs = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];
    let signature_limbs = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];
    let partial_data: BoundedVec<u8, 256> = BoundedVec::from_array([
        106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107, 78, 69,
        77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120, 102, 100,
        109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85, 115, 73, 109,
        53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84, 73,
        122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74, 104, 98, 71, 108,
        106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115, 73, 109, 108, 104,
        100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78, 121, 119, 105, 89,
        88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84, 73, 122, 76, 106,
        81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86, 52, 99, 67, 73, 54,
        77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48,
    ]);
    let base64_decode_offset = 1;
    let partial_hash = [
        2065651337, 2814693704, 862745553, 2384319000, 1412758034, 3553265356, 3156727610,
        4160738201,
    ];
    let full_data_length = 268;

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

    let email: BoundedVec<u8, 100> = jwt.get_claim_string("email".as_bytes());
    let expected_email: BoundedVec<u8, 100> = BoundedVec::from_array("alice@test.com".as_bytes());
    assert(email == expected_email);
}

#[test]
fn test_assert_claim_string() {
    let pubkey_modulus_limbs = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];
    let redc_params_limbs = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];
    let signature_limbs = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120,
        102, 100, 109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85,
        115, 73, 109, 53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73,
        122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74,
        104, 98, 71, 108, 106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115,
        73, 109, 108, 104, 100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78,
        121, 119, 105, 89, 88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84,
        73, 122, 76, 106, 81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86,
        52, 99, 67, 73, 54, 77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48,
    ]);
    let base64_decode_offset = 37;

    let jwt = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    let value: BoundedVec<u8, 100> = BoundedVec::from_array("alice@test.com".as_bytes());
    jwt.assert_claim_string("email".as_bytes(), value);
}

#[test]
fn test_get_claim_number() {
    let pubkey_modulus_limbs = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];
    let redc_params_limbs = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];
    let signature_limbs = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120,
        102, 100, 109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85,
        115, 73, 109, 53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73,
        122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74,
        104, 98, 71, 108, 106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115,
        73, 109, 108, 104, 100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78,
        121, 119, 105, 89, 88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84,
        73, 122, 76, 106, 81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86,
        52, 99, 67, 73, 54, 77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48,
    ]);
    let base64_decode_offset = 37;

    let jwt = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    let iat: u64 = jwt.get_claim_number("iat".as_bytes());
    let expected_iat: u64 = 1737642217;
    assert(iat == expected_iat);
}

#[test]
fn test_assert_claim_number() {
    let pubkey_modulus_limbs = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];
    let redc_params_limbs = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];
    let signature_limbs = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120,
        102, 100, 109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85,
        115, 73, 109, 53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73,
        122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74,
        104, 98, 71, 108, 106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115,
        73, 109, 108, 104, 100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78,
        121, 119, 105, 89, 88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84,
        73, 122, 76, 106, 81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86,
        52, 99, 67, 73, 54, 77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48,
    ]);
    let base64_decode_offset = 37;

    let jwt = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    let expected_iat: u64 = 1737642217;
    jwt.assert_claim_number("iat".as_bytes(), expected_iat);
}

#[test]
fn test_get_claim_bool() {
    let pubkey_modulus_limbs = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];
    let redc_params_limbs = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];
    let signature_limbs = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120,
        102, 100, 109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85,
        115, 73, 109, 53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73,
        122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74,
        104, 98, 71, 108, 106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115,
        73, 109, 108, 104, 100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78,
        121, 119, 105, 89, 88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84,
        73, 122, 76, 106, 81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86,
        52, 99, 67, 73, 54, 77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48,
    ]);
    let base64_decode_offset = 37;

    let jwt = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    let email_verified: bool = jwt.get_claim_bool("email_verified".as_bytes());
    assert(email_verified);
}

#[test]
fn test_assert_claim_bool() {
    let pubkey_modulus_limbs = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];
    let redc_params_limbs = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];
    let signature_limbs = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120,
        102, 100, 109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85,
        115, 73, 109, 53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73,
        122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74,
        104, 98, 71, 108, 106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115,
        73, 109, 108, 104, 100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78,
        121, 119, 105, 89, 88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84,
        73, 122, 76, 106, 81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86,
        52, 99, 67, 73, 54, 77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48,
    ]);
    let base64_decode_offset = 37;

    let jwt = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    jwt.assert_claim_bool("email_verified".as_bytes(), true);
}

#[test]
fn test_get_last_claim() {
    let pubkey_modulus_limbs = [
        484791102317025465533947056954494751,
        689128460766062759582134715581990032,
        810523707777777878428965619663888709,
        184404549238669475316963116864788898,
        93466218048229154672139102341852900,
        584828628768888069086079532464056431,
        97425187031931427039620311245463762,
        26273806718910063326353308419294998,
        788747954066548540615875263034804664,
        889704621954975151388848797463892494,
        311999144542197118282319553447935979,
        569776388981460921496753063185331362,
        903966640703701959992132828577771898,
        159022820921763067563807580152706463,
        503819859541011037194389727017199051,
        1078173269124751507098806957834900664,
        808018922828293630146825008649069450,
        163,
    ];
    let redc_params_limbs = [
        1143167338325541577958669340190596824,
        782066667103526839077340987159104121,
        1067845759344375818181746341911682002,
        880124617802511701465844415806808588,
        285259139341669707856057706066903101,
        1230850420220071595120007854793337041,
        243441877489860292941608721967510056,
        821283804950244931298352888469271304,
        265590023859021620015146340457966193,
        955602690275722281613949658760787989,
        704159826142581942518373637894303280,
        313938418637521056314346970388282852,
        296174013877567499290252280618882959,
        127533166408087917092441034792304239,
        486694435757811118946661778147879193,
        742440511645057019411661928820777129,
        106100992772450627263374716203348785,
        6409,
    ];
    let signature_limbs = [
        782421962573548264472674190647943355,
        528649442614902878048130358901749842,
        795671681115216636642039527621785323,
        342055983261463759066440970886912343,
        320943042314824191484469254030368420,
        233931545977215775766660875366648712,
        166738968145911552289782464945436391,
        1280090914380823160665554635957223606,
        225322564371992173705155119766257284,
        1012067778676730712845356243167441596,
        337008035250054394089555850701430953,
        441480997772890594691718538441538925,
        1266099611422563733802354067242028554,
        163890419575820619684088542045789366,
        71236811945264458762129145425586273,
        106105739687938386497215871288359508,
        598323717706499880526430558338637686,
        97,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120,
        102, 100, 109, 86, 121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 85,
        115, 73, 109, 53, 118, 98, 109, 78, 108, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73,
        122, 77, 84, 73, 122, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 119, 105, 79, 105, 74,
        104, 98, 71, 108, 106, 90, 85, 66, 48, 90, 88, 78, 48, 76, 109, 78, 118, 98, 83, 73, 115,
        73, 109, 108, 104, 100, 67, 73, 54, 77, 84, 99, 122, 78, 122, 89, 48, 77, 106, 73, 120, 78,
        121, 119, 105, 89, 88, 86, 107, 73, 106, 111, 105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84,
        73, 122, 76, 106, 81, 49, 78, 106, 81, 49, 78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86,
        52, 99, 67, 73, 54, 77, 84, 99, 53, 79, 84, 107, 53, 79, 84, 107, 53, 79, 88, 48,
    ]);
    let base64_decode_offset = 37;

    let jwt = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    let exp: u64 = jwt.get_claim_number("exp".as_bytes()); // exp is the last claim in the test payload
    let expected_exp: u64 = 1799999999;
    assert(exp == expected_exp);
}
