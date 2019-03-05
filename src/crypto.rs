use biscuit::errors::Error::ValidationError;
use biscuit::jwa;
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
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use untrusted;

#[cfg(feature = "aws")]
use rusoto_core::Region;
#[cfg(feature = "aws")]
use rusoto_ssm::{GetParameterRequest, Ssm, SsmClient};

use crate::schema::*;

fn verify_key_from_str(s: &str) -> Result<Secret, String> {
    if s.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        verify_key_from_private_pem(s)
    } else if s.starts_with("-----BEGIN PUBLIC KEY-----") {
        verify_key_from_public_pem(s)
    } else {
        verify_key_from_jwk(s)
    }
}

fn sign_key_from_str(s: &str) -> Result<Secret, String> {
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

fn sign_key_from_jwk(key: &str) -> Result<Secret, String> {
    let rsa = jwk_str_to_rsa_key_params(key)?;
    let sign = jws::Secret::RSAKeyPair(Arc::new(
        RSAKeyPair::from_der(untrusted::Input::from(&to_der(rsa)?))
            .map_err(|e| format!("error converting to der: {}", e))?,
    ));
    Ok(sign)
}

fn verify_key_from_jwk(key: &str) -> Result<Secret, String> {
    let rsa = jwk_str_to_rsa_key_params(key)?;
    let verify = rsa.jws_public_key_secret();
    Ok(verify)
}

pub struct SecretStore {
    sign_secrets: HashMap<String, Secret>,
    verify_secrets: HashMap<String, Secret>,
}

impl Default for SecretStore {
    fn default() -> Self {
        SecretStore {
            sign_secrets: HashMap::default(),
            verify_secrets: HashMap::default(),
        }
    }
}

impl SecretStore {
    pub fn with_sign_keys_from_inline_iter<I>(mut self, sign_keys: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let sign_secrets: Result<HashMap<String, Secret>, String> = sign_keys
            .into_iter()
            .map(|(k, v)| sign_key_from_str(&v).map(|key| (k, key)))
            .collect();
        self.sign_secrets.extend(sign_secrets?);
        Ok(self)
    }

    pub fn with_verify_keys_from_inline_iter<I>(mut self, sign_keys: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let verify_secrets: Result<HashMap<String, Secret>, String> = sign_keys
            .into_iter()
            .map(|(k, v)| verify_key_from_str(&v).map(|key| (k, key)))
            .collect();
        self.verify_secrets.extend(verify_secrets?);
        Ok(self)
    }

    #[cfg(feature = "aws")]
    pub fn with_sign_keys_from_ssm_iter<I>(mut self, keys: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let sign_secrets: Result<HashMap<String, Secret>, String> =
            SecretStore::str_keys_from_ssm_iter(keys)
                .into_iter()
                .map(|x| {
                    x.and_then(|(publisher, v)| sign_key_from_str(&v).map(|key| (publisher, key)))
                })
                .collect();
        self.sign_secrets.extend(sign_secrets?);
        Ok(self)
    }

    #[cfg(feature = "aws")]
    pub fn with_verify_keys_from_ssm_iter<I>(mut self, keys: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let verify_secrets: Result<HashMap<String, Secret>, String> =
            SecretStore::str_keys_from_ssm_iter(keys)
                .into_iter()
                .map(|x| {
                    x.and_then(|(publisher, v)| verify_key_from_str(&v).map(|key| (publisher, key)))
                })
                .collect();
        self.verify_secrets.extend(verify_secrets?);
        Ok(self)
    }

    #[cfg(feature = "aws")]
    fn str_keys_from_ssm_iter<I>(
        keys: I,
    ) -> impl IntoIterator<Item = Result<(String, String), String>>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let ssm_client = SsmClient::new(Region::default());
        keys.into_iter()
            .map(move |(publisher, ssm_parameter_name)| {
                let req = GetParameterRequest {
                    name: ssm_parameter_name,
                    with_decryption: Some(true),
                };
                ssm_client
                    .get_parameter(req)
                    .sync()
                    .map_err(|e| format!("error during get_paramter request: {}", e))
                    .and_then(|p| p.parameter.ok_or_else(|| String::from("no paramter")))
                    .and_then(|p| p.value.ok_or_else(|| String::from("no value")))
                    .map(|key| (publisher, key))
            })
    }

    #[cfg(feature = "well_known")]
    pub fn with_verify_keys_from_well_known(mut self, url: &str) -> Result<Self, String> {
        let mut res =
            reqwest::get(url).map_err(|e| format!("unable to get keys from well known: {}", e))?;
        let mut json: Value = res
            .json()
            .map_err(|e| format!("well known return invalid json: {}", e))?;
        if let Value::Object(keys) = json["api"]["publishers_jwks"].take() {
            let verify_secrets: Result<HashMap<String, Secret>, String> = keys
                .into_iter()
                .map(|(provider, mut v)| {
                    serde_json::from_value(v["keys"][0].take())
                        .map_err(|e| format!("invalid jwk: {}", e))
                        .and_then(|jwk| jwk_to_rsa_key_params(jwk))
                        .map(|rsa| rsa.jws_public_key_secret())
                        .map(|key| (provider, key))
                })
                .collect();
            self.verify_secrets.extend(verify_secrets?);
            Ok(self)
        } else {
            Err(format!("unable to retrieve signing keys from: {}", url))
        }
    }
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

fn jwk_str_to_rsa_key_params(key: &str) -> Result<RSAKeyParameters, String> {
    let mut j = serde_json::Deserializer::from_str(key);
    let jwk: JWK<Empty> =
        JWK::deserialize(&mut j).map_err(|e| format!("error reading jwk: {}", e))?;
    jwk_to_rsa_key_params(jwk)
}
fn jwk_to_rsa_key_params(jwk: JWK<Empty>) -> Result<RSAKeyParameters, String> {
    if let AlgorithmParameters::RSA(x) = jwk.algorithm {
        Ok(x)
    } else {
        Err(String::from("no rsa jwk"))
    }
}

pub fn verify_attribute(attr: &impl Serialize, store: &SecretStore) -> Result<bool, String> {
    let mut attr_c: Value =
        serde_json::to_value(attr).map_err(|e| format!("unable to serialize json: {}", e))?;
    if attr_c.get("value").or_else(|| attr_c.get("values")) == Some(&Value::Null)
        && attr_c["signature"]["publisher"]["value"] == ""
    {
        return Ok(true);
    }
    let publisher = attr_c["signature"]["publisher"]["name"]
        .as_str()
        .ok_or_else(|| String::from("publisher missing"))?;
    let key = store
        .verify_secrets
        .get(publisher)
        .ok_or_else(|| format!("no keys for {}", publisher))?;
    let token = attr_c["signature"]["publisher"]["value"]
        .take()
        .as_str()
        .map(String::from)
        .unwrap();
    attr_c.as_object_mut().unwrap().remove("signature");
    let c: jws::Compact<biscuit::ClaimsSet<Value>, Empty> = jws::Compact::new_encoded(&token);
    match c.decode(&key, jwa::SignatureAlgorithm::RS256) {
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

pub fn sign_attribute<T>(attr: &mut T, store: &SecretStore) -> Result<(), String>
where
    T: Serialize + Sign + Clone,
{
    let mut attr_c = if let Value::Object(m) = serde_json::to_value(attr.clone())
        .map_err(|e| format!("unable to serialize json: {}", e))?
    {
        m
    } else {
        return Err(String::from("attribute must be an object"));
    };
    if let Some(Value::Null) = attr_c.get("value").or_else(|| attr_c.get("values")) {
        return Ok(());
    }
    let publisher = attr_c["signature"]["publisher"]["name"]
        .clone()
        .as_str()
        .map(|s| s.to_owned())
        .ok_or_else(|| String::from("publisher missing"))?;
    let key = store
        .sign_secrets
        .get(&publisher)
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
        .encode(&key)
        .map_err(|e| format!("error encoding jwt: {}", e))?;
    let token = c
        .encoded()
        .map_err(|e| format!("unable to get encoded jwt: {}", e))?
        .to_string();
    attr.sign(Publisher {
        alg: Alg::Rs256,
        name: serde_json::from_str(&format!(r#""{}""#, publisher))
            .map_err(|e| format!("unknown publisher ({}): {}", publisher, e))?,
        value: token,
        typ: Typ::Jws,
    });
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::schema::StandardAttributeString;

    fn get_fake_store() -> SecretStore {
        let key = include_str!("../data/fake_key.json");
        SecretStore::default()
            .with_sign_keys_from_inline_iter(vec![(String::from("mozilliansorg"), key.to_owned())])
            .unwrap()
            .with_verify_keys_from_inline_iter(vec![(
                String::from("mozilliansorg"),
                key.to_owned(),
            )])
            .unwrap()
    }

    #[test]
    fn keys_from_jwks() {
        let key = include_str!("../data/fake_key.json");
        let store = SecretStore::default()
            .with_sign_keys_from_inline_iter(vec![(String::from("mozilliansorg"), key.to_owned())])
            .unwrap()
            .with_verify_keys_from_inline_iter(vec![(
                String::from("mozilliansorg"),
                key.to_owned(),
            )]);
        assert!(store.is_ok())
    }

    #[test]
    fn keys_from_pems() {
        let private = include_str!("../data/fake_key_private.pem");
        let public = include_str!("../data/fake_key_public.pem");
        let store = SecretStore::default()
            .with_sign_keys_from_inline_iter(vec![(
                String::from("mozilliansorg"),
                private.to_owned(),
            )])
            .unwrap()
            .with_verify_keys_from_inline_iter(vec![(
                String::from("mozilliansorg"),
                public.to_owned(),
            )]);
        assert!(store.is_ok())
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

        let mut attr: StandardAttributeString =
            serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        let _ = sign_attribute(&mut attr, &store)?;
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_attribute() -> Result<(), String> {
        let store = get_fake_store();

        let mut attr: StandardAttributeString =
            serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        sign_attribute(&mut attr, &store)?;
        let valid = verify_attribute(&attr, &store)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_struct() -> Result<(), String> {
        let store = get_fake_store();

        let mut attr = StandardAttributeString::default();
        attr.value = Some(String::from("foobar"));
        sign_attribute(&mut attr, &store)?;
        let valid = verify_attribute(&attr, &store)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_struct_null_value() -> Result<(), String> {
        let store = get_fake_store();

        let mut attr = StandardAttributeString::default();
        attr.value = None;
        sign_attribute(&mut attr, &store)?;
        assert!(attr.signature.publisher.value.is_empty());
        let valid = verify_attribute(&attr, &store)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_struct_null_values() -> Result<(), String> {
        let store = get_fake_store();

        let mut attr = StandardAttributeValues::default();
        attr.values = None;
        sign_attribute(&mut attr, &store)?;
        assert!(attr.signature.publisher.value.is_empty());
        let valid = verify_attribute(&attr, &store)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_profile_field() -> Result<(), String> {
        let store = get_fake_store();

        let mut profile = Profile::default();
        profile.primary_username.value = Some(String::from("foobar"));
        profile.staff_information.staff.value = Some(true);
        sign_attribute(&mut profile.primary_username, &store)?;
        sign_attribute(&mut profile.staff_information.staff, &store)?;
        let valid = verify_attribute(&profile.primary_username, &store)?;
        assert!(valid);
        let valid = verify_attribute(&profile.staff_information.staff, &store)?;
        assert!(valid);
        Ok(())
    }
}

#[cfg(feature = "aws")]
#[cfg(test)]
mod aws_test {
    use super::*;
    use std::env;

    #[test]
    fn test_keys_from_ssm() -> Result<(), String> {
        if let Ok(mozillians_key_ssm_name) = env::var("CIS_SSM_MOZILLIANSORG_KEY") {
            let store = SecretStore::default()
                .with_sign_keys_from_ssm_iter(vec![(
                    String::from("mozilliansorg"),
                    mozillians_key_ssm_name.clone(),
                )])?
                .with_verify_keys_from_ssm_iter(vec![(
                    String::from("mozilliansorg"),
                    mozillians_key_ssm_name,
                )])?;
            let mut attr: StandardAttributeString =
                serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
            sign_attribute(&mut attr, &store)?;
            let valid = verify_attribute(&attr, &store)?;
            assert!(valid);
        }
        Ok(())
    }
}

#[cfg(feature = "well_known")]
#[cfg(test)]
mod well_known_test {
    use super::*;

    #[test]
    fn test_keys_from_well_knwon() {
        // check for ok once we fix x5c in the well-known
        assert!(SecretStore::default()
            .with_verify_keys_from_well_known("https://auth.allizom.org/.well-known/mozilla-iam")
            .is_err());
    }

}
