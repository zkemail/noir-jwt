use jwt::JWT;

fn main(
    data: BoundedVec<u8, 512>,
    base64_decode_offset: u32,
    pubkey_modulus_limbs: [Field; 18],
    redc_params_limbs: [Field; 18],
    signature_limbs: [Field; 18],
) -> pub BoundedVec<u8, 100> {
    let jwt = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    jwt.verify();

    let claim: BoundedVec<u8, 100> = jwt.get_claim_string("email".as_bytes());

    jwt.assert_claim_bool("email_verified".as_bytes(), true);

    jwt.assert_claim_string(
        "iss".as_bytes(),
        BoundedVec::<u8, 50>::from_array("http://test.com".as_bytes()),
    );

    claim
}
