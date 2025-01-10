use base64::BASE64_URL_DECODER;
use bignum::{params::BigNumParams, RuntimeBigNum};
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
    pub fn validate_key_value<let PAYLOAD_SCAN_RANGE: u32, let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        key: [u8; KEY_LENGTH],
        value: BoundedVec<u8, MAX_VALUE_LENGTH>,
    ) {
        assert(
            PAYLOAD_SCAN_RANGE % 4 == 0,
            "PAYLOAD_SCAN_RANGE should be a multiple of 4 to be a valid base64 chunk",
        );
        assert(
            PAYLOAD_SCAN_RANGE <= (self.data.len() - self.b64_offset),
            "PAYLOAD_SCAN_RANGE should be less than data length",
        );
        assert(value.len() <= MAX_VALUE_LENGTH, "value length is too long");

        // Prepare base64 payload to decode
        // Only in partial sha - shift input chars by offset so the partial data is base64 decodable (multiple of 4)
        let mut payload_b64: [u8; PAYLOAD_SCAN_RANGE] = [0; PAYLOAD_SCAN_RANGE];
        for i in 0..PAYLOAD_SCAN_RANGE {
            payload_b64[i] = self.data.storage()[(i + self.b64_offset)];
        }

        // Decode base64 and prepare a haystack for substring matching in validate_key_value() with decoded payload
        let payload: [u8; (PAYLOAD_SCAN_RANGE / 4 * 3)] = BASE64_URL_DECODER.decode(payload_b64); // b64 decoded length is ceil(DATA_LENGTH / 3) * 4

        // StringBody is constructed with <ceil(length / 31) * 31, ceil(length / 31), length>
        let haystack: StringBody<(((PAYLOAD_SCAN_RANGE / 4 * 3) + 31) / 31) * 31, ((PAYLOAD_SCAN_RANGE / 4 * 3) + 31) / 31, (PAYLOAD_SCAN_RANGE / 4 * 3)> =
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

    pub fn get_value<let PAYLOAD_SCAN_RANGE: u32, let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        key: [u8; KEY_LENGTH],
    ) -> BoundedVec<u8, MAX_VALUE_LENGTH> {
        let value: BoundedVec<u8, MAX_VALUE_LENGTH> = unsafe {
            self.get_value_unconstrained::<PAYLOAD_SCAN_RANGE, KEY_LENGTH, MAX_VALUE_LENGTH>(key)
        };

        self.validate_key_value::<PAYLOAD_SCAN_RANGE, KEY_LENGTH, MAX_VALUE_LENGTH>(key, value);

        value
    }

    pub unconstrained fn get_value_unconstrained<let PAYLOAD_SCAN_RANGE: u32, let KEY_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
        self,
        key: [u8; KEY_LENGTH],
    ) -> BoundedVec<u8, MAX_VALUE_LENGTH> {
        let mut payload_b64: [u8; PAYLOAD_SCAN_RANGE] = [0; PAYLOAD_SCAN_RANGE];
        for i in 0..PAYLOAD_SCAN_RANGE {
            payload_b64[i] = self.data.storage()[(i + self.b64_offset)];
        }

        let payload: [u8; (PAYLOAD_SCAN_RANGE / 4 * 3)] = BASE64_URL_DECODER.decode(payload_b64); // b64 decoded length is ceil(DATA_LENGTH / 3) * 4

        let haystack: StringBody<(((PAYLOAD_SCAN_RANGE / 4 * 3) + 31) / 31) * 31, ((PAYLOAD_SCAN_RANGE / 4 * 3) + 31) / 31, (PAYLOAD_SCAN_RANGE / 4 * 3)> =
            StringBody::new(payload, payload.len());

        // key is the needle
        let needle: SubString<((KEY_LENGTH + 31) / 31) * 31, KEY_LENGTH / 31, KEY_LENGTH> =
            SubString::new(key, key.len());

        let (match, position): (bool, u32) = haystack.substring_match(needle);

        assert(match, "key not found");

        // Get the value after the key
        let value_start = position + needle.len() + 3;
        let mut value: BoundedVec<u8, MAX_VALUE_LENGTH> = BoundedVec::new();

        for i in 0..MAX_VALUE_LENGTH {
            if (payload[value_start + i] == 34) {
                break;
            }
            value.storage[i] = payload[value_start + i];
            value.len += 1;
        }

        value
    }
}

#[test]
fn test_verify() {
    let pubkey_modulus_limbs = [
        781228697113857985819673031169671049,
        918001779718550478801091651092507940,
        980935243444749009506791223207831971,
        864183106111112053582563569805506701,
        1244582016979368535477810305001970256,
        900059079448651479789008929908095231,
        992554506995563186620941946211763144,
        970826350955458914785507278407149725,
        956256101854590293335144199317147608,
        135728523631135560306035727917592750,
        960441581181399197807510951743563832,
        634480393647281464703136546254837650,
        594436193759347465531587734182162986,
        676624705147900057919976377533350909,
        963396684802699886451785226110547981,
        999959502818828821494790246802796176,
        1027657018852920222824870804769834108,
        156,
    ];
    let redc_params_limbs = [
        929731805241674850337049697387158904,
        207863856581165158423759403570383598,
        276662915261133394021824170073500347,
        332256520170011233997548663775714450,
        269250986209310018069403490224251396,
        1158879046738839298904414993646546085,
        914921340485588895610933660137559361,
        993030977423860999023866649714953569,
        261220869849897974554161772829326150,
        1125920442267255578994772527273487461,
        465283348298487493685637019016706669,
        152444501216329133784297377245585697,
        635289622067490742197534121147526258,
        182437327987520433618834550322306438,
        568286438481829290409622275821760657,
        480896042117607260868512495705573452,
        655841879549993277409009669876641754,
        6688,
    ];
    let signature_limbs = [
        1084922740882935993927550446752004723,
        531251963255857241142456029783565755,
        895506988910046896394391169402677895,
        729413505750883650093789965748412056,
        351788378559115039436650193953625146,
        54060101768335552464106084390072848,
        977845560825461683530208217657756178,
        1172643955963692788515729981091825172,
        197524565468283967093493061191892480,
        658097258095378380483614857040248908,
        13592935371012294370032505462825629,
        575399913463561438285293064346141731,
        725661672274739825167889928186350926,
        36229161266507821376455641556172250,
        1027513315797966011133556568224692592,
        348123718067484411757223073724797348,
        305004191223908956877831137224778455,
        22,
    ];
    let data: BoundedVec<u8, 512> = BoundedVec::from_array([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 73, 115, 73,
        110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 112, 99,
        51, 77, 105, 79, 105, 74, 111, 100, 72, 82, 119, 79, 105, 56, 118, 100, 71, 86, 122, 100,
        67, 53, 106, 98, 50, 48, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 74, 66, 81, 107,
        78, 69, 77, 84, 73, 122, 77, 84, 73, 122, 73, 105, 119, 105, 89, 88, 86, 107, 73, 106, 111,
        105, 77, 84, 73, 122, 77, 84, 73, 122, 77, 84, 73, 122, 76, 106, 81, 49, 78, 106, 81, 49,
        78, 106, 81, 49, 78, 105, 73, 115, 73, 109, 86, 52, 99, 67, 73, 54, 77, 84, 99, 122, 78,
        106, 81, 53, 77, 68, 81, 52, 78, 67, 119, 105, 97, 87, 70, 48, 73, 106, 111, 120, 78, 122,
        77, 50, 78, 68, 103, 50, 79, 68, 103, 48, 76, 67, 74, 117, 98, 50, 53, 106, 90, 83, 73, 54,
        73, 109, 49, 53, 97, 71, 120, 48, 97, 72, 81, 122, 100, 110, 81, 105, 76, 67, 74, 108, 98,
        87, 70, 112, 98, 67, 73, 54, 73, 109, 70, 115, 97, 87, 78, 108, 81, 72, 82, 108, 99, 51, 81,
        117, 89, 50, 57, 116, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120, 102, 100, 109, 86,
        121, 97, 87, 90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 86, 57,
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
        732898501691555569431936115089649579,
        1122754307009694855334680154453921454,
        248313557064962837198108999360378197,
        752806252778842392232109952606132026,
        166642313538894309522683024453604683,
        762604741928923775205207327839244513,
        882010539858286754865120077437831074,
        431092704923254213786814695341142824,
        571593993021605086735110117875723146,
        872913932519554100940905376726977329,
        173275582777558923207276423240771834,
        326648797663448184844659710115401830,
        967202000820708749585891042785893968,
        1308095003037984667307952669759405328,
        653274417891911049858619399915052409,
        502626541163616472096166650285852359,
        1323087078038572523238626087429896565,
        195,
    ];
    let redc_params_limbs = [
        722793651527263541877598610504965070,
        600104830802371926233294736936113067,
        1060025633172657172534913331804992926,
        331987524958611721073178123312318502,
        308609038260875289432489576639383849,
        139540925298816756498368174622646890,
        138355904967742810832859853440550174,
        626750281385399765655596193313437227,
        299336269592205837020917909612204667,
        368556815120203205388960892516041478,
        1277764188607872789868667126686663955,
        1045911023104375009785273038533799307,
        855321812367848980209422993060248730,
        126934347790641848083483344378306127,
        783725660091499508497614982573875524,
        487534216610355824657185456613406023,
        4859492319034978249948152541440489,
        5350,
    ];
    let signature_limbs = [
        374393013592287429221796290579804968,
        732623018145196409442812553145068953,
        1252273772447584901418315632856305571,
        1308429963957426744003406817474678328,
        51203233218188716716376200312464440,
        617757168872361788971997269941957087,
        1141754861273469273318726865934760991,
        48511624278226616448693802413210143,
        1261609543077750000890981952241142773,
        129716090764903892640688316345368345,
        318495715424913552229597995065564223,
        592940349600658634309004920148685659,
        1130449615452952249039932543331670553,
        1032352998956064077247707819951424954,
        916880988298121174263477903862432414,
        833808584181286326971513383260086485,
        573493720570803567192986439036762725,
        95,
    ];
    let partial_data: BoundedVec<u8, 256> = BoundedVec::from_array([
        49, 78, 105, 73, 115, 73, 109, 86, 52, 99, 67, 73, 54, 77, 84, 99, 122, 78, 106, 81, 52, 79,
        68, 81, 52, 79, 83, 119, 105, 97, 87, 70, 48, 73, 106, 111, 120, 78, 122, 77, 50, 78, 68,
        103, 48, 79, 68, 103, 53, 76, 67, 74, 117, 98, 50, 53, 106, 90, 83, 73, 54, 73, 109, 89,
        120, 77, 72, 89, 53, 100, 88, 111, 119, 99, 50, 99, 105, 76, 67, 74, 108, 98, 87, 70, 112,
        98, 67, 73, 54, 73, 109, 70, 115, 97, 87, 78, 108, 81, 72, 82, 108, 99, 51, 81, 117, 89, 50,
        57, 116, 73, 105, 119, 105, 90, 87, 49, 104, 97, 87, 120, 102, 100, 109, 86, 121, 97, 87,
        90, 112, 90, 87, 81, 105, 79, 110, 82, 121, 100, 87, 86, 57,
    ]);
    let b64_offset = 1;
    let partial_hash = [
        291844137, 871603302, 1977778012, 4213794212, 4080401768, 1349766907, 4032784244,
        2198146592,
    ];
    let full_data_length = 269;

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
