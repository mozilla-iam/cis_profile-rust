use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("invalid string for DisplayLevel")]
    InvalidDisplayLevelString,
    #[error("invalid string for Publisher")]
    InvalidPublisherString,
}

#[derive(Debug, Error)]
pub enum RsaKeyError {
    #[error("no d")]
    NoD,
    #[error("no p")]
    NoP,
    #[error("no q")]
    NoQ,
    #[error("no dp")]
    NoDP,
    #[error("no dq")]
    NoDQ,
    #[error("no qi")]
    NoQI,
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("no rsa jwk")]
    NoRsaJwk,
    #[error("no rsa pem")]
    NoRsaPem,
    #[error("rsa key error: {0}")]
    RsaKeyError(#[from] RsaKeyError),
    #[error("deserialize error: {0}")]
    DeserializeError(#[from] serde_json::Error),
    #[error("openssl error: {0}")]
    OpenSSLError(#[from] openssl::error::ErrorStack),
    #[error("docoding error: {0}")]
    DecodingError(#[from] biscuit::errors::Error),
    #[error("signer/verifier error: {0}")]
    SignerVerifierError(#[from] SignerVerifierError),
    #[cfg(feature = "aws")]
    #[error("ssm error: {0}")]
    SsmError(#[from] SsmError),
    #[cfg(feature = "well_known")]
    #[error("well known error: {0}")]
    WellKnownError(#[from] WellKnownError),
}

#[derive(Debug, Error)]
pub enum SignerVerifierError {
    #[error("no publisher")]
    NoPublisher,
    #[error("attribute must be an object")]
    NonObjectAttribute,
    #[error("keys missing for publihser {}", _0)]
    NoPublisherKeys(String),
}

#[cfg(feature = "aws")]
#[derive(Debug, Error)]
pub enum SsmError {
    #[error("no parameter")]
    NoParameter,
    #[error("no value")]
    NoValue,
    #[error("ssm get parameter error: {0}")]
    GetParameterError(#[from] rusoto_core::RusotoError<rusoto_ssm::GetParameterError>),
}

#[cfg(feature = "well_known")]
#[derive(Debug, Error)]
pub enum WellKnownError {
    #[error("unable to retrieve verify keys")]
    RetrieveVerifyKeysFailed,
    #[error("reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
}
