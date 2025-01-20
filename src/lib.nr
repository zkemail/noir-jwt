use base64::BASE64_URL_DECODER;
use bignum::{params::BigNumParams, RuntimeBigNum};
use nodash::str_to_u64;
use rsa::{rsa::verify_sha256_pkcs1v15, types::RBN2048};
use std::hash::sha256_var;
use string_search::{StringBody, SubString};
use zkemail::partial_hash::partial_sha256_var_end;

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
    * @param b64_offset: Offset needed in `data` byte array to make it a multiple of 4 (for base64 decoding)
    *                    Set the offset to the index of the first character of the payload (after the header)
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
    * PAYLOAD_SCAN_RANGE is the index in the base64 encoded payload (from the b64_offset) up to which we will look for the key:value pair.
    * This essentially means that everything from b64_offset to PAYLOAD_SCAN_RANGE should be a valid base64 character, and the key:value
    * pair should be present in this range.
    * This is necessary now due to a limitation in base64.
    **/
    pub fn assert_claim_string<let PAYLOAD_SCAN_RANGE: u32, let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        claim_key: [u8; KEY_LENGTH],
        claim_value: BoundedVec<u8, MAX_VALUE_LENGTH>,
    ) {
        let value: BoundedVec<u8, MAX_VALUE_LENGTH> =
            self.get_claim_string::<PAYLOAD_SCAN_RANGE, KEY_LENGTH, MAX_VALUE_LENGTH>(claim_key);
        assert(value == claim_value, "incorrect value for claim");
    }

    pub fn get_claim_string<let PAYLOAD_SCAN_RANGE: u32, let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        key: [u8; KEY_LENGTH],
    ) -> BoundedVec<u8, MAX_VALUE_LENGTH> {
        self.get_claim::<PAYLOAD_SCAN_RANGE, KEY_LENGTH, MAX_VALUE_LENGTH>(key, true)
    }

    pub fn get_claim_number<let PAYLOAD_SCAN_RANGE: u32, let KEY_LENGTH: u32>(
        self,
        key: [u8; KEY_LENGTH],
    ) -> u64 {
        let claim = self.get_claim::<PAYLOAD_SCAN_RANGE, KEY_LENGTH, 20>(key, false);
        str_to_u64(claim.storage())
    }

    fn get_claim<let PAYLOAD_SCAN_RANGE: u32, let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        key: [u8; KEY_LENGTH],
        is_value_quoted: bool,
    ) -> BoundedVec<u8, MAX_VALUE_LENGTH> {
        // extract the value in unconstrained mode
        let value: BoundedVec<u8, MAX_VALUE_LENGTH> = unsafe {
            self.extract_claim_unconstrained::<PAYLOAD_SCAN_RANGE, KEY_LENGTH, MAX_VALUE_LENGTH>(
                key,
                is_value_quoted,
            )
        };

        // constrain the extracted value is present in the payload using string_search lib
        // haystack is the base64 decoded payload; needle is the key
        let haystack = self.prepare_haystack::<PAYLOAD_SCAN_RANGE>();
        let needle: SubString<((KEY_LENGTH + 31) / 31) * 31, KEY_LENGTH / 31, KEY_LENGTH> =
            SubString::new(key, key.len());

        let (match, position): (bool, u32) = haystack.substring_match(needle);
        assert(match, "key not found in the payload");

        // assert value after key is a quote and colon
        assert(haystack.body[position + KEY_LENGTH] == 34); // "
        assert(haystack.body[position + KEY_LENGTH + 1] == 58); // :

        let mut value_offset = 0;
        if (is_value_quoted) {
            // assert the char before and after the value is a quote
            assert(haystack.body[position + KEY_LENGTH + 2] == 34); // "
            assert(haystack.body[position + KEY_LENGTH + 3 + value.len()] == 34); // "
            value_offset = position + KEY_LENGTH + 3; // for two quote and colon
        } else {
            // numeric - assert the character after the value is a comma
            assert(haystack.body[position + KEY_LENGTH + 2 + value.len()] == 44); // ,
            value_offset = position + KEY_LENGTH + 2; // for a quote and colon
        }

        // assert the value is correct
        for i in 0..MAX_VALUE_LENGTH {
            if (i < value.len()) {
                assert(haystack.body[value_offset + i] == value.storage()[i]);
            }
        }

        value
    }

    fn prepare_haystack<let PAYLOAD_SCAN_RANGE: u32>(
        self,
    ) -> StringBody<((((PAYLOAD_SCAN_RANGE / 4) * 3) + 31) / 31) * 31, (((PAYLOAD_SCAN_RANGE / 4) * 3) + 31) / 31, ((PAYLOAD_SCAN_RANGE / 4) * 3)> {
        assert(
            PAYLOAD_SCAN_RANGE % 4 == 0,
            "PAYLOAD_SCAN_RANGE should be a multiple of 4 to be a valid base64 chunk",
        );
        assert(
            PAYLOAD_SCAN_RANGE <= (self.data.len() - self.b64_offset),
            "PAYLOAD_SCAN_RANGE should be less than data length",
        );

        // Decode the payload (from the b64_offset)
        let mut payload_b64: [u8; PAYLOAD_SCAN_RANGE] = [0; PAYLOAD_SCAN_RANGE];
        for i in 0..PAYLOAD_SCAN_RANGE {
            payload_b64[i] = self.data.storage()[(i + self.b64_offset)];
        }

        let payload: [u8; (PAYLOAD_SCAN_RANGE / 4 * 3)] = BASE64_URL_DECODER.decode(payload_b64); // b64 decoded length is ceil(DATA_LENGTH / 3) * 4

        // Create the haystack
        let haystack: StringBody<(((PAYLOAD_SCAN_RANGE / 4 * 3) + 31) / 31) * 31, ((PAYLOAD_SCAN_RANGE / 4 * 3) + 31) / 31, (PAYLOAD_SCAN_RANGE / 4 * 3)> =
            StringBody::new(payload, payload.len());

        haystack
    }

    pub unconstrained fn extract_claim_unconstrained<let PAYLOAD_SCAN_RANGE: u32, let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        key: [u8; KEY_LENGTH],
        is_value_quoted: bool,
    ) -> BoundedVec<u8, MAX_VALUE_LENGTH> {
        let haystack = self.prepare_haystack::<PAYLOAD_SCAN_RANGE>();
        let needle: SubString<((KEY_LENGTH + 31) / 31) * 31, KEY_LENGTH / 31, KEY_LENGTH> =
            SubString::new(key, key.len());
        let (match, position): (bool, u32) = haystack.substring_match(needle);
        assert(match, "key not found");

        // Get the value after the key
        let mut value_start_idx = position + key.len() + 2;
        if (is_value_quoted) {
            value_start_idx += 1;
        }

        let mut value: BoundedVec<u8, MAX_VALUE_LENGTH> = BoundedVec::new();

        for i in 0..MAX_VALUE_LENGTH {
            let val = haystack.body[value_start_idx + i];
            if ((val == 34) | (val == 44)) {
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
        807146986404662989881754629896758351,
        1249196178022815689870551953626054977,
        1023084592656711112858656924641563514,
        439727497862278033660918462118611736,
        697309993076650971587934543296443384,
        98055832112060084020665147704538465,
        240784105423708519221967314168507731,
        995518139999891154934440786668432024,
        337652728182254657937117833008919199,
        713396662675555796961540340305330614,
        1219877800037688872351343895191348673,
        29365577253040068823313134295613999,
        1231536144422897795998179855130881232,
        1293505758993764648522194752980609552,
        893452809297398712206665072485397865,
        71752125996965625833082701910545051,
        848028214320551742742540836477995013,
        18,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 89, 88, 86, 107, 73, 106, 111,
        105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84, 73, 122, 76, 106, 81, 49, 78, 106, 81, 49,
        78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86, 52, 99, 67, 73, 54, 77, 84, 99, 122, 78,
        106, 85, 51, 78, 122, 103, 48, 77, 67, 119, 105, 97, 87, 70, 48, 73, 106, 111, 120, 78, 122,
        77, 50, 78, 84, 99, 48, 77, 106, 81, 119, 76, 67, 74, 117, 98, 50, 53, 106, 90, 83, 73, 54,
        73, 106, 69, 121, 77, 122, 69, 121, 77, 122, 69, 121, 77, 121, 73, 115, 73, 109, 86, 116,
        89, 87, 108, 115, 73, 106, 111, 105, 89, 87, 120, 112, 89, 50, 86, 65, 100, 71, 86, 122,
        100, 67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 108, 98, 87, 70, 112, 98, 70, 57, 50, 90, 88,
        74, 112, 90, 109, 108, 108, 90, 67, 73, 54, 100, 72, 74, 49, 90, 88, 48,
    ]);
    let b64_offset = 37;

    let jwt = JWT::init(
        data,
        b64_offset,
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
        807146986404662989881754629896758351,
        1249196178022815689870551953626054977,
        1023084592656711112858656924641563514,
        439727497862278033660918462118611736,
        697309993076650971587934543296443384,
        98055832112060084020665147704538465,
        240784105423708519221967314168507731,
        995518139999891154934440786668432024,
        337652728182254657937117833008919199,
        713396662675555796961540340305330614,
        1219877800037688872351343895191348673,
        29365577253040068823313134295613999,
        1231536144422897795998179855130881232,
        1293505758993764648522194752980609552,
        893452809297398712206665072485397865,
        71752125996965625833082701910545051,
        848028214320551742742540836477995013,
        18,
    ];
    let partial_data: BoundedVec<u8, 256> = BoundedVec::from_array([
        49, 78, 105, 73, 115, 73, 109, 86, 52, 99, 67, 73, 54, 77, 84, 99, 122, 78, 106, 85, 51, 78,
        122, 103, 48, 77, 67, 119, 105, 97, 87, 70, 48, 73, 106, 111, 120, 78, 122, 77, 50, 78, 84,
        99, 48, 77, 106, 81, 119, 76, 67, 74, 117, 98, 50, 53, 106, 90, 83, 73, 54, 73, 106, 69,
        121, 77, 122, 69, 121, 77, 122, 69, 121, 77, 121, 73, 115, 73, 109, 86, 116, 89, 87, 108,
        115, 73, 106, 111, 105, 89, 87, 120, 112, 89, 50, 86, 65, 100, 71, 86, 122, 100, 67, 53,
        106, 98, 50, 48, 105, 76, 67, 74, 108, 98, 87, 70, 112, 98, 70, 57, 50, 90, 88, 74, 112, 90,
        109, 108, 108, 90, 67, 73, 54, 100, 72, 74, 49, 90, 88, 48,
    ]);
    let b64_offset = 1;
    let partial_hash = [
        291844137, 871603302, 1977778012, 4213794212, 4080401768, 1349766907, 4032784244,
        2198146592,
    ];
    let full_data_length = 268;

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
        807146986404662989881754629896758351,
        1249196178022815689870551953626054977,
        1023084592656711112858656924641563514,
        439727497862278033660918462118611736,
        697309993076650971587934543296443384,
        98055832112060084020665147704538465,
        240784105423708519221967314168507731,
        995518139999891154934440786668432024,
        337652728182254657937117833008919199,
        713396662675555796961540340305330614,
        1219877800037688872351343895191348673,
        29365577253040068823313134295613999,
        1231536144422897795998179855130881232,
        1293505758993764648522194752980609552,
        893452809297398712206665072485397865,
        71752125996965625833082701910545051,
        848028214320551742742540836477995013,
        18,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 89, 88, 86, 107, 73, 106, 111,
        105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84, 73, 122, 76, 106, 81, 49, 78, 106, 81, 49,
        78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86, 52, 99, 67, 73, 54, 77, 84, 99, 122, 78,
        106, 85, 51, 78, 122, 103, 48, 77, 67, 119, 105, 97, 87, 70, 48, 73, 106, 111, 120, 78, 122,
        77, 50, 78, 84, 99, 48, 77, 106, 81, 119, 76, 67, 74, 117, 98, 50, 53, 106, 90, 83, 73, 54,
        73, 106, 69, 121, 77, 122, 69, 121, 77, 122, 69, 121, 77, 121, 73, 115, 73, 109, 86, 116,
        89, 87, 108, 115, 73, 106, 111, 105, 89, 87, 120, 112, 89, 50, 86, 65, 100, 71, 86, 122,
        100, 67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 108, 98, 87, 70, 112, 98, 70, 57, 50, 90, 88,
        74, 112, 90, 109, 108, 108, 90, 67, 73, 54, 100, 72, 74, 49, 90, 88, 48,
    ]);
    let b64_offset = 37;

    let jwt = JWT::init(
        data,
        b64_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    let value: BoundedVec<u8, 100> = BoundedVec::from_array("alice@test.com".as_bytes());
    jwt.assert_claim_string::<220, 5, 100>("email".as_bytes(), value);
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
        807146986404662989881754629896758351,
        1249196178022815689870551953626054977,
        1023084592656711112858656924641563514,
        439727497862278033660918462118611736,
        697309993076650971587934543296443384,
        98055832112060084020665147704538465,
        240784105423708519221967314168507731,
        995518139999891154934440786668432024,
        337652728182254657937117833008919199,
        713396662675555796961540340305330614,
        1219877800037688872351343895191348673,
        29365577253040068823313134295613999,
        1231536144422897795998179855130881232,
        1293505758993764648522194752980609552,
        893452809297398712206665072485397865,
        71752125996965625833082701910545051,
        848028214320551742742540836477995013,
        18,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 89, 88, 86, 107, 73, 106, 111,
        105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84, 73, 122, 76, 106, 81, 49, 78, 106, 81, 49,
        78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86, 52, 99, 67, 73, 54, 77, 84, 99, 122, 78,
        106, 85, 51, 78, 122, 103, 48, 77, 67, 119, 105, 97, 87, 70, 48, 73, 106, 111, 120, 78, 122,
        77, 50, 78, 84, 99, 48, 77, 106, 81, 119, 76, 67, 74, 117, 98, 50, 53, 106, 90, 83, 73, 54,
        73, 106, 69, 121, 77, 122, 69, 121, 77, 122, 69, 121, 77, 121, 73, 115, 73, 109, 86, 116,
        89, 87, 108, 115, 73, 106, 111, 105, 89, 87, 120, 112, 89, 50, 86, 65, 100, 71, 86, 122,
        100, 67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 108, 98, 87, 70, 112, 98, 70, 57, 50, 90, 88,
        74, 112, 90, 109, 108, 108, 90, 67, 73, 54, 100, 72, 74, 49, 90, 88, 48,
    ]);
    let b64_offset = 37;

    let jwt = JWT::init(
        data,
        b64_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    let email: BoundedVec<u8, 100> = jwt.get_claim_string::<220, 5, 100>("email".as_bytes());
    let expected_email: BoundedVec<u8, 100> = BoundedVec::from_array("alice@test.com".as_bytes());
    assert(email == expected_email);
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
        807146986404662989881754629896758351,
        1249196178022815689870551953626054977,
        1023084592656711112858656924641563514,
        439727497862278033660918462118611736,
        697309993076650971587934543296443384,
        98055832112060084020665147704538465,
        240784105423708519221967314168507731,
        995518139999891154934440786668432024,
        337652728182254657937117833008919199,
        713396662675555796961540340305330614,
        1219877800037688872351343895191348673,
        29365577253040068823313134295613999,
        1231536144422897795998179855130881232,
        1293505758993764648522194752980609552,
        893452809297398712206665072485397865,
        71752125996965625833082701910545051,
        848028214320551742742540836477995013,
        18,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 89, 88, 86, 107, 73, 106, 111,
        105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84, 73, 122, 76, 106, 81, 49, 78, 106, 81, 49,
        78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86, 52, 99, 67, 73, 54, 77, 84, 99, 122, 78,
        106, 85, 51, 78, 122, 103, 48, 77, 67, 119, 105, 97, 87, 70, 48, 73, 106, 111, 120, 78, 122,
        77, 50, 78, 84, 99, 48, 77, 106, 81, 119, 76, 67, 74, 117, 98, 50, 53, 106, 90, 83, 73, 54,
        73, 106, 69, 121, 77, 122, 69, 121, 77, 122, 69, 121, 77, 121, 73, 115, 73, 109, 86, 116,
        89, 87, 108, 115, 73, 106, 111, 105, 89, 87, 120, 112, 89, 50, 86, 65, 100, 71, 86, 122,
        100, 67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 108, 98, 87, 70, 112, 98, 70, 57, 50, 90, 88,
        74, 112, 90, 109, 108, 108, 90, 67, 73, 54, 100, 72, 74, 49, 90, 88, 48,
    ]);
    let b64_offset = 37;

    let jwt = JWT::init(
        data,
        b64_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    let iat: u64 = jwt.get_claim_number::<220, 3>("iat".as_bytes());
    let expected_iat: u64 = 1736574240;
    assert(iat == expected_iat);
}
