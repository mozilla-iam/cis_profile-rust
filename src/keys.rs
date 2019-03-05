use biscuit::jwk::AlgorithmParameters;
use biscuit::jwk::RSAKeyParameters;
use biscuit::jwk::JWK;
use biscuit::jws;
use biscuit::jws::Secret;
use biscuit::Empty;
use num_bigint::BigUint;
use openssl::bn::BigNum;
use openssl::rsa::Rsa;
use openssl::rsa::RsaPrivateKeyBuilder;
use ring::signature::RSAKeyPair;
use serde::Deserialize;
use std::sync::Arc;
use untrusted;

pub fn verify_key_from_str(s: &str) -> Result<Secret, String> {
    if s.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        verify_key_from_private_pem(s)
    } else if s.starts_with("-----BEGIN PUBLIC KEY-----") {
        verify_key_from_public_pem(s)
    } else {
        verify_key_from_jwk(s)
    }
}

pub fn sign_key_from_str(s: &str) -> Result<Secret, String> {
    if s.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        sign_key_from_pem(s)
    } else {
        sign_key_from_jwk(s)
    }
}

fn sign_key_from_pem(key: &str) -> Result<Secret, String> {
    let rsa = Rsa::private_key_from_pem(key.as_bytes())
        .map_err(|e| format!("error reading key: {}", e))?;
    let sign = jws::Secret::RSAKeyPair(Arc::new(
        RSAKeyPair::from_der(untrusted::Input::from(
            &rsa.private_key_to_der()
                .map_err(|e| format!("error converting key: {}", e))?,
        ))
        .map_err(|e| format!("error converting to der: {}", e))?,
    ));
    Ok(sign)
}

fn verify_key_from_public_pem(key: &str) -> Result<Secret, String> {
    let rsa = Rsa::public_key_from_pem(key.as_bytes())
        .map_err(|e| format!("error reading key: {}", e))?;
    let verify = jws::Secret::RSAModulusExponent {
        n: BigUint::from_bytes_be(&rsa.n().to_vec()),
        e: BigUint::from_bytes_be(&rsa.e().to_vec()),
    };
    Ok(verify)
}

fn verify_key_from_private_pem(key: &str) -> Result<Secret, String> {
    let rsa = Rsa::private_key_from_pem(key.as_bytes())
        .map_err(|e| format!("error reading key: {}", e))?;
    let verify = jws::Secret::RSAModulusExponent {
        n: BigUint::from_bytes_be(&rsa.n().to_vec()),
        e: BigUint::from_bytes_be(&rsa.e().to_vec()),
    };
    Ok(verify)
}

pub fn sign_key_from_jwk(key: &str) -> Result<Secret, String> {
    let rsa = jwk_str_to_rsa_key_params(key)?;
    let sign = jws::Secret::RSAKeyPair(Arc::new(
        RSAKeyPair::from_der(untrusted::Input::from(&to_der(rsa)?))
            .map_err(|e| format!("error converting to der: {}", e))?,
    ));
    Ok(sign)
}

pub fn verify_key_from_jwk(key: &str) -> Result<Secret, String> {
    let rsa = jwk_str_to_rsa_key_params(key)?;
    let verify = rsa.jws_public_key_secret();
    Ok(verify)
}

#[allow(clippy::many_single_char_names)]
pub fn to_der(jwk_rsa: RSAKeyParameters) -> Result<Vec<u8>, String> {
    let n = jwk_rsa.n;
    let e = jwk_rsa.e;
    let d = jwk_rsa.d.ok_or_else(|| String::from("no d"))?;;
    let p = jwk_rsa.p.ok_or_else(|| String::from("no p"))?;
    let q = jwk_rsa.q.ok_or_else(|| String::from("no q"))?;
    let dp = jwk_rsa.dp.ok_or_else(|| String::from("no dp"))?;
    let dq = jwk_rsa.dq.ok_or_else(|| String::from("no dq"))?;
    let qinv = jwk_rsa.qi.ok_or_else(|| String::from("no q"))?;

    let builder = RsaPrivateKeyBuilder::new(
        BigNum::from_slice(&n.to_bytes_be()).unwrap(),
        BigNum::from_slice(&e.to_bytes_be()).unwrap(),
        BigNum::from_slice(&d.to_bytes_be()).unwrap(),
    )
    .unwrap();
    let builder = builder
        .set_factors(
            BigNum::from_slice(&p.to_bytes_be()).unwrap(),
            BigNum::from_slice(&q.to_bytes_be()).unwrap(),
        )
        .unwrap();
    let builder = builder
        .set_crt_params(
            BigNum::from_slice(&dp.to_bytes_be()).unwrap(),
            BigNum::from_slice(&dq.to_bytes_be()).unwrap(),
            BigNum::from_slice(&qinv.to_bytes_be()).unwrap(),
        )
        .unwrap();
    let der = builder.build().private_key_to_der().unwrap();
    Ok(der)
}

pub fn jwk_str_to_rsa_key_params(key: &str) -> Result<RSAKeyParameters, String> {
    let mut j = serde_json::Deserializer::from_str(key);
    let jwk: JWK<Empty> =
        JWK::deserialize(&mut j).map_err(|e| format!("error reading jwk: {}", e))?;
    jwk_to_rsa_key_params(jwk)
}

pub fn jwk_to_rsa_key_params(jwk: JWK<Empty>) -> Result<RSAKeyParameters, String> {
    if let AlgorithmParameters::RSA(x) = jwk.algorithm {
        Ok(x)
    } else {
        Err(String::from("no rsa jwk"))
    }
}
