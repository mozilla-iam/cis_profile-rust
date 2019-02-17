use biscuit::errors::Error::ValidationError;
use biscuit::jwa;
use biscuit::jwk::AlgorithmParameters;
use biscuit::jwk::RSAKeyParameters;
use biscuit::jwk::JWK;
use biscuit::jws;
use biscuit::Empty;
use openssl::bn::BigNum;
use openssl::rsa::RsaPrivateKeyBuilder;
use ring::signature::RSAKeyPair;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use untrusted;

use crate::schema::*;

pub struct Keys {
    sign: jws::Secret,
    verify: jws::Secret,
}

fn keys_from(jwk: JWK<Empty>) -> Result<Keys, String> {
    let rsa = to_rsa_key_params(jwk)?;
    let verify = rsa.jws_public_key_secret();
    let sign = jws::Secret::RSAKeyPair(Arc::new(
        RSAKeyPair::from_der(untrusted::Input::from(&to_der(rsa)?))
            .map_err(|e| format!("error converting to der: {}", e))?,
    ));
    Ok(Keys { sign, verify })
}

pub struct SecretStore {
    secrets: HashMap<String, Keys>,
}

#[allow(clippy::many_single_char_names)]
fn to_der(jwk_rsa: RSAKeyParameters) -> Result<Vec<u8>, String> {
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

fn to_rsa_key_params(jwk: JWK<Empty>) -> Result<RSAKeyParameters, String> {
    if let AlgorithmParameters::RSA(x) = jwk.algorithm {
        Ok(x)
    } else {
        Err(String::from("no rsa jwk"))
    }
}

fn jwk_from_str(key: &str) -> Result<JWK<Empty>, String> {
    let mut j = serde_json::Deserializer::from_str(key);
    JWK::deserialize(&mut j).map_err(|e| format!("error reading jwk: {}", e))
}

pub fn verify_attribute(attr: &Value, store: &SecretStore) -> Result<bool, String> {
    let mut attr_c = attr.clone();
    let publisher = attr["signature"]["publisher"]["name"]
        .as_str()
        .ok_or_else(|| String::from("publisher missing"))?;
    let keys = store
        .secrets
        .get(publisher)
        .ok_or_else(|| format!("no keys for {}", publisher))?;
    let token = attr_c["signature"]["publisher"]["value"]
        .take()
        .as_str()
        .map(String::from)
        .unwrap();
    attr_c.as_object_mut().unwrap().remove("signature");
    let c: jws::Compact<biscuit::ClaimsSet<Value>, Empty> = jws::Compact::new_encoded(&token);
    match c.decode(&keys.verify, jwa::SignatureAlgorithm::RS256) {
        Ok(c) => {
            let from_token = &c
                .payload()
                .map_err(|e| format!("broken payload: {}", e))?
                .private;
            Ok(from_token == &attr_c)
        }
        Err(ValidationError(_)) => Ok(false),
        Err(e) => Err(format!("error verifying attribute: {}", e)),
    }
}

pub fn sign_attribute(attr: &Value, store: &SecretStore) -> Result<Value, String> {
    let mut attr_c = if let Value::Object(m) = attr.clone() {
        m
    } else {
        return Err(String::from("attribute must be an object"));
    };
    let publisher = attr["signature"]["publisher"]["name"]
        .as_str()
        .ok_or_else(|| String::from("publisher missing"))?;
    let keys = store
        .secrets
        .get(publisher)
        .ok_or_else(|| format!("no keys for {}", publisher))?;
    let _ = attr_c.remove("signature").unwrap_or_default();

    let header: jws::Header<Empty> = jws::Header {
        registered: jws::RegisteredHeader {
            algorithm: jwa::SignatureAlgorithm::RS256,
            media_type: Some(String::from("JWT")),
            ..Default::default()
        },
        private: Default::default(),
    };
    let claims = biscuit::ClaimsSet {
        registered: Default::default(),
        private: Value::from(attr_c),
    };
    let c = jws::Compact::new_decoded(header, claims);
    let c = c
        .encode(&keys.sign)
        .map_err(|e| format!("error encoding jwt: {}", e))?;
    let token = c
        .encoded()
        .map_err(|e| format!("unable to get encoded jwt: {}", e))?
        .to_string();
    let mut attr_signed = attr.clone();
    attr_signed["signature"]["publisher"] = json!(Publisher {
        alg: Alg::Rs256,
        name: serde_json::from_str(&format!(r#""{}""#, publisher))
            .map_err(|e| format!("unknown publisher ({}): {}", publisher, e))?,
        value: token,
        typ: Typ::Jws,
    });
    Ok(attr_signed)
}

#[cfg(test)]
mod test {
    use super::*;

    fn get_fake_store() -> SecretStore {
        let jwk = jwk_from_str(include_str!("../data/fake_key.json")).unwrap();
        let mut store = SecretStore {
            secrets: HashMap::new(),
        };
        store
            .secrets
            .insert(String::from("mozilliansorg"), keys_from(jwk).unwrap());
        store
    }

    #[test]
    fn test_verify_attribute() -> Result<(), String> {
        let store = get_fake_store();

        let attr: Value = serde_json::from_str(include_str!("../data/attribute.json")).unwrap();
        let valid = verify_attribute(&attr, &store)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_verify_attribute_non_matching_claims() -> Result<(), String> {
        let store = get_fake_store();

        let mut attr: Value = serde_json::from_str(include_str!("../data/attribute.json")).unwrap();
        attr["value"] = Value::from("break it!");
        let valid = verify_attribute(&attr, &store)?;
        assert!(!valid);
        Ok(())
    }

    #[test]
    fn test_verify_attribute_invaild() -> Result<(), String> {
        let store = get_fake_store();

        let attr: Value =
            serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        let valid = verify_attribute(&attr, &store)?;
        assert!(!valid);
        Ok(())
    }

    #[test]
    fn test_sign_attribute() -> Result<(), String> {
        let store = get_fake_store();

        let attr: Value =
            serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        let _ = sign_attribute(&attr, &store)?;
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_attribute() -> Result<(), String> {
        let store = get_fake_store();

        let attr: Value =
            serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        let attr_signed = sign_attribute(&attr, &store)?;
        let valid = verify_attribute(&attr_signed, &store)?;
        assert!(valid);
        Ok(())
    }
}
