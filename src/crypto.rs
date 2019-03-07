use biscuit::errors::Error::ValidationError;
use biscuit::jwa;
use biscuit::jws;
use biscuit::jws::Secret;
use biscuit::Empty;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;

use crate::keys::*;
use crate::schema::*;

#[cfg(feature = "aws")]
use rusoto_core::Region;
#[cfg(feature = "aws")]
use rusoto_ssm::{GetParameterRequest, Ssm, SsmClient};

pub trait Signer {
    fn sign_attribute<T>(&self, attr: &mut T) -> Result<(), String>
    where
        T: Serialize + Sign + Clone;
}

pub trait Verifier {
    fn verify_attribute(&self, attr: &impl Serialize) -> Result<bool, String>;
}

pub struct SecretStore {
    pub sign_secrets: HashMap<String, Secret>,
    pub verify_secrets: HashMap<String, Secret>,
}

impl Default for SecretStore {
    fn default() -> Self {
        SecretStore {
            sign_secrets: HashMap::default(),
            verify_secrets: HashMap::default(),
        }
    }
}

impl Signer for SecretStore {
    fn sign_attribute<T>(&self, attr: &mut T) -> Result<(), String>
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
        let key = self
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
}

impl Verifier for SecretStore {
    fn verify_attribute(&self, attr: &impl Serialize) -> Result<bool, String> {
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
        let key = self
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
                        .and_then(jwk_to_rsa_key_params)
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
    fn test_verify_attribute() -> Result<(), String> {
        let store = get_fake_store();

        let attr: Value = serde_json::from_str(include_str!("../data/attribute.json")).unwrap();
        let valid = store.verify_attribute(&attr)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_verify_attribute_non_matching_claims() -> Result<(), String> {
        let store = get_fake_store();

        let mut attr: Value = serde_json::from_str(include_str!("../data/attribute.json")).unwrap();
        attr["value"] = Value::from("break it!");
        let valid = store.verify_attribute(&attr)?;
        assert!(!valid);
        Ok(())
    }

    #[test]
    fn test_verify_attribute_invaild() -> Result<(), String> {
        let store = get_fake_store();

        let attr: Value =
            serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        let valid = store.verify_attribute(&attr)?;
        assert!(!valid);
        Ok(())
    }

    #[test]
    fn test_sign_attribute() -> Result<(), String> {
        let store = get_fake_store();

        let mut attr: StandardAttributeString =
            serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        let _ = store.sign_attribute(&mut attr)?;
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_attribute() -> Result<(), String> {
        let store = get_fake_store();

        let mut attr: StandardAttributeString =
            serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        store.sign_attribute(&mut attr)?;
        let valid = store.verify_attribute(&attr)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_struct() -> Result<(), String> {
        let store = get_fake_store();

        let mut attr = StandardAttributeString::default();
        attr.value = Some(String::from("foobar"));
        store.sign_attribute(&mut attr)?;
        let valid = store.verify_attribute(&attr)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_struct_null_value() -> Result<(), String> {
        let store = get_fake_store();

        let mut attr = StandardAttributeString::default();
        attr.value = None;
        store.sign_attribute(&mut attr)?;
        assert!(attr.signature.publisher.value.is_empty());
        let valid = store.verify_attribute(&attr)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_struct_null_values() -> Result<(), String> {
        let store = get_fake_store();

        let mut attr = StandardAttributeValues::default();
        attr.values = None;
        store.sign_attribute(&mut attr)?;
        assert!(attr.signature.publisher.value.is_empty());
        let valid = store.verify_attribute(&attr)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_profile_field() -> Result<(), String> {
        let store = get_fake_store();

        let mut profile = Profile::default();
        profile.primary_username.value = Some(String::from("foobar"));
        profile.staff_information.staff.value = Some(true);
        store.sign_attribute(&mut profile.primary_username)?;
        store.sign_attribute(&mut profile.staff_information.staff)?;
        let valid = store.verify_attribute(&profile.primary_username)?;
        assert!(valid);
        let valid = store.verify_attribute(&profile.staff_information.staff)?;
        assert!(valid);
        Ok(())
    }
}

#[cfg(test)]
mod test_secret_store {
    use super::*;

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
}

#[cfg(feature = "aws")]
#[cfg(test)]
mod aws_test {
    use super::*;
    use crate::schema::StandardAttributeString;
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
            store.sign_attribute(&mut attr)?;
            let valid = store.verify_attribute(&attr)?;
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
            .is_ok());
    }

}
