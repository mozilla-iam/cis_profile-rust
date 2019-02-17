use biscuit::jwa;
use biscuit::jwk::AlgorithmParameters;
use biscuit::jwk::RSAKeyParameters;
use biscuit::jwk::JWK;
use biscuit::jws;
use biscuit::Empty;
use biscuit::errors::Error::ValidationError;
use openssl::bn::BigNum;
use openssl::rsa::RsaPrivateKeyBuilder;
use ring::signature::RSAKeyPair;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use untrusted;

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
    let publisher = attr_c["signature"]["publisher"]["name"]
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
        Ok(c) => Ok(true),
        Err(ValidationError(_)) => Ok(false),
        Err(e) => Err(format!("error verifying attribute: {}", e)),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn get_fake_store() -> SecretStore {
        let jwk = jwk_from_str(include_str!("../data/fake_key.json")).unwrap();
        let mut store = SecretStore {
            secrets: HashMap::new()
        };
        store.secrets.insert(String::from("mozilliansorg"), keys_from(jwk).unwrap());
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
    fn test_verify_attribute_invaild() -> Result<(), String> {
        let store = get_fake_store();

        let attr: Value = serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        let valid = verify_attribute(&attr, &store)?;
        assert!(!valid);
        Ok(())
    }
}
