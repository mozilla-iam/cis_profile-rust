use crate::error::SignerVerifierError;
use crate::keys::*;
use crate::schema::*;
use biscuit::errors::Error::ValidationError;
use biscuit::jwa;
use biscuit::jws;
use biscuit::jws::Secret;
use biscuit::Empty;
use failure::Error;
use serde_json::Value;
use std::collections::HashMap;

#[cfg(feature = "aws")]
use crate::error::SsmError;
#[cfg(feature = "aws")]
use futures::future::try_join_all;
#[cfg(feature = "aws")]
use rusoto_core::Region;
#[cfg(feature = "aws")]
use rusoto_ssm::{GetParameterRequest, Ssm, SsmClient};

#[cfg(feature = "well_known")]
use crate::error::WellKnownError;

/// Trait implemented by types that can sign fields.
pub trait Signer {
    /// Sign a field implementing the `WithPublihser` trait.
    fn sign_attribute(&self, attr: &mut impl WithPublisher) -> Result<(), Error>;
}

/// Trait implemented by types that can verify fields.
pub trait Verifier {
    // Verify a field implementing the `WithPublisher` trait.
    fn verify_attribute(&self, attr: &impl WithPublisher) -> Result<bool, Error>;
}

/// Stores secrets to sign and verify.
pub struct SecretStore {
    /// A Map _Name_ → `Secret` used for signing.
    pub sign_secrets: HashMap<String, Secret>,
    /// A Map _Name_ → `Secret` used for verifying.
    pub verify_secrets: HashMap<String, Secret>,
}

impl Default for SecretStore {
    /// An empty store.
    fn default() -> Self {
        SecretStore {
            sign_secrets: HashMap::default(),
            verify_secrets: HashMap::default(),
        }
    }
}

impl Signer for SecretStore {
    /// Signs an attribute field.
    /// Returns `Ok` if field is empty.
    /// Retruns `Err` if publisher has no signing key in the store.
    fn sign_attribute(&self, attr: &mut impl WithPublisher) -> Result<(), Error> {
        if attr.is_empty() {
            return Ok(());
        }
        let publisher = attr.get_publisher().name.clone();
        let key = self
            .sign_secrets
            .get(publisher.as_str())
            .ok_or_else(|| SignerVerifierError::NoPublisherKeys(publisher.as_str().to_owned()))?;
        let data = attr.data()?;

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
            private: data,
        };
        let c = jws::Compact::new_decoded(header, claims);
        let c = c.encode(key)?;
        let token = c.encoded()?.to_string();
        attr.set_publisher(Publisher {
            alg: Alg::Rs256,
            name: publisher,
            value: token,
            typ: Typ::Jws,
        });
        Ok(())
    }
}

impl Verifier for SecretStore {
    /// Verifies an attribute field.
    /// Returns `Ok` if field is empty.
    /// Retruns `Err` if publisher has no signing key in the store.
    fn verify_attribute(&self, attr: &impl WithPublisher) -> Result<bool, Error> {
        if attr.is_empty() {
            return Ok(true);
        }
        let publisher = attr.get_publisher().name.as_str().to_owned();
        let key = self
            .verify_secrets
            .get(&publisher)
            .ok_or_else(|| SignerVerifierError::NoPublisherKeys(publisher.to_owned()))?;
        let token = attr.get_publisher().value.clone();
        let data = attr.data()?;
        let c: jws::Compact<biscuit::ClaimsSet<Value>, Empty> = jws::Compact::new_encoded(&token);
        match c.decode(key, jwa::SignatureAlgorithm::RS256) {
            Ok(c) => {
                let from_token = &c.payload()?.private;
                Ok(from_token == &data)
            }
            Err(ValidationError(_)) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

impl SecretStore {
    /// Loads singing keys from a `(Name, Key)` iterator.
    pub fn with_sign_keys_from_inline_iter<I>(mut self, sign_keys: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let sign_secrets: Result<HashMap<String, Secret>, Error> = sign_keys
            .into_iter()
            .map(|(k, v)| sign_key_from_str(&v).map(|key| (k, key)))
            .collect();
        self.sign_secrets.extend(sign_secrets?);
        Ok(self)
    }

    /// Loads verifying keys from a `(Name, Key)` iterator.
    pub fn with_verify_keys_from_inline_iter<I>(mut self, sign_keys: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let verify_secrets: Result<HashMap<String, Secret>, Error> = sign_keys
            .into_iter()
            .map(|(k, v)| verify_key_from_str(&v).map(|key| (k, key)))
            .collect();
        self.verify_secrets.extend(verify_secrets?);
        Ok(self)
    }

    #[cfg(feature = "aws")]
    /// Loads singing keys from a `(Name, SSM_PATH)` iterator.
    pub async fn with_sign_keys_from_ssm_iter<I>(mut self, keys: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let sign_secrets: Result<HashMap<String, Secret>, Error> =
            SecretStore::str_keys_from_ssm_iter(keys)
                .await?
                .into_iter()
                .map(|(publisher, v)| sign_key_from_str(&v).map(|key| (publisher, key)))
                .collect();
        self.sign_secrets.extend(sign_secrets?);
        Ok(self)
    }

    #[cfg(feature = "aws")]
    /// Loads verifying keys from a `(Name, SSM_PATH)` iterator.
    pub async fn with_verify_keys_from_ssm_iter<I>(mut self, keys: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let verify_secrets: Result<HashMap<String, Secret>, Error> =
            SecretStore::str_keys_from_ssm_iter(keys)
                .await?
                .into_iter()
                .map(|(publisher, v)| verify_key_from_str(&v).map(|key| (publisher, key)))
                .collect();
        self.verify_secrets.extend(verify_secrets?);
        Ok(self)
    }

    #[cfg(feature = "aws")]
    async fn str_keys_from_ssm_iter<I>(keys: I) -> Result<Vec<(String, String)>, Error>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        try_join_all(
            keys.into_iter()
                .map(move |(publisher, ssm_parameter_name)| async move {
                    let ssm_client = SsmClient::new(Region::default());
                    let req = GetParameterRequest {
                        name: ssm_parameter_name,
                        with_decryption: Some(true),
                    };
                    ssm_client
                        .get_parameter(req)
                        .await
                        .map_err(Into::into)
                        .and_then(|res| {
                            if let Some(p) = res.parameter {
                                if let Some(key) = p.value {
                                    Ok((publisher, key))
                                } else {
                                    Err(SsmError::NoValue.into())
                                }
                            } else {
                                Err(SsmError::NoParameter.into())
                            }
                        })
                }),
        )
        .await
    }

    #[cfg(feature = "well_known")]
    /// Loads verifying keys from a remote http jwks source.
    pub async fn with_verify_keys_from_well_known(mut self, url: &str) -> Result<Self, Error> {
        let res = reqwest::get(url).await?;
        let mut json: Value = res.json().await?;
        if let Value::Object(keys) = json["api"]["publishers_jwks"].take() {
            let verify_secrets: Result<HashMap<String, Secret>, Error> = keys
                .into_iter()
                .map(|(provider, mut v)| {
                    serde_json::from_value(v["keys"][0].take())
                        .map_err(|e| e.into())
                        .and_then(jwk_to_rsa_key_params)
                        .map(|rsa| rsa.jws_public_key_secret())
                        .map(|key| (provider, key))
                })
                .collect();
            self.verify_secrets.extend(verify_secrets?);
            Ok(self)
        } else {
            Err(WellKnownError::RetrieveVerifyKeysFailed.into())
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
    fn test_verify_attribute() -> Result<(), Error> {
        let store = get_fake_store();

        let attr: StandardAttributeString =
            serde_json::from_str(include_str!("../data/attribute.json")).unwrap();
        let valid = store.verify_attribute(&attr)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_verify_attribute_non_matching_claims() -> Result<(), Error> {
        let store = get_fake_store();

        let mut attr: StandardAttributeString =
            serde_json::from_str(include_str!("../data/attribute.json")).unwrap();
        attr.value = Some(String::from("break it!"));
        let valid = store.verify_attribute(&attr)?;
        assert!(!valid);
        Ok(())
    }

    #[test]
    fn test_verify_attribute_invaild() -> Result<(), Error> {
        let store = get_fake_store();

        let attr: StandardAttributeString =
            serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        let valid = store.verify_attribute(&attr)?;
        assert!(!valid);
        Ok(())
    }

    #[test]
    fn test_sign_attribute() -> Result<(), Error> {
        let store = get_fake_store();

        let mut attr: StandardAttributeString =
            serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        store.sign_attribute(&mut attr)?;
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_attribute() -> Result<(), Error> {
        let store = get_fake_store();

        let mut attr: StandardAttributeString =
            serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        store.sign_attribute(&mut attr)?;
        let valid = store.verify_attribute(&attr)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_struct() -> Result<(), Error> {
        let store = get_fake_store();

        let mut attr = StandardAttributeString {
            value: Some(String::from("foobar")),
            ..StandardAttributeString::default()
        };
        store.sign_attribute(&mut attr)?;
        let valid = store.verify_attribute(&attr)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_struct_null_value() -> Result<(), Error> {
        let store = get_fake_store();

        let mut attr = StandardAttributeString {
            value: None,
            ..StandardAttributeString::default()
        };
        store.sign_attribute(&mut attr)?;
        assert!(attr.signature.publisher.value.is_empty());
        let valid = store.verify_attribute(&attr)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_struct_null_values() -> Result<(), Error> {
        let store = get_fake_store();

        let mut attr = StandardAttributeValues {
            values: None,
            ..StandardAttributeValues::default()
        };
        store.sign_attribute(&mut attr)?;
        assert!(attr.signature.publisher.value.is_empty());
        let valid = store.verify_attribute(&attr)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_profile_field() -> Result<(), Error> {
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

    #[test]
    fn sign_wtih_pem_verify_with_jwk() -> Result<(), Error> {
        let private = include_str!("../data/fake_key_private.pem");
        let public = include_str!("../data/fake_key.json");
        let store = SecretStore::default()
            .with_sign_keys_from_inline_iter(vec![(
                String::from("mozilliansorg"),
                private.to_owned(),
            )])
            .unwrap()
            .with_verify_keys_from_inline_iter(vec![(
                String::from("mozilliansorg"),
                public.to_owned(),
            )])?;
        let mut attr: StandardAttributeString =
            serde_json::from_str(include_str!("../data/attribute_invalid.json")).unwrap();
        store.sign_attribute(&mut attr)?;
        let valid = store.verify_attribute(&attr)?;
        assert!(valid);
        Ok(())
    }
}

#[cfg(feature = "aws")]
#[cfg(test)]
mod aws_test {
    use super::*;
    use crate::schema::StandardAttributeString;
    use std::env;

    #[tokio::test]
    async fn test_keys_from_ssm() -> Result<(), Error> {
        if let Ok(mozillians_key_ssm_name) = env::var("CIS_SSM_MOZILLIANSORG_KEY") {
            let store = SecretStore::default()
                .with_sign_keys_from_ssm_iter(vec![(
                    String::from("mozilliansorg"),
                    mozillians_key_ssm_name.clone(),
                )])
                .await?
                .with_verify_keys_from_ssm_iter(vec![(
                    String::from("mozilliansorg"),
                    mozillians_key_ssm_name,
                )])
                .await?;
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

    #[tokio::test]
    async fn test_keys_from_well_knwon() {
        // check for ok once we fix x5c in the well-known
        assert!(SecretStore::default()
            .with_verify_keys_from_well_known("https://auth.allizom.org/.well-known/mozilla-iam")
            .await
            .is_ok());
    }
}
