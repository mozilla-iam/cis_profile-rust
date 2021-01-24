use failure::Fail;
#[derive(Debug, Fail)]
pub enum RsaKeyError {
    #[fail(display = "no d")]
    NoD,
    #[fail(display = "no p")]
    NoP,
    #[fail(display = "no q")]
    NoQ,
    #[fail(display = "no dp")]
    NoDP,
    #[fail(display = "no dq")]
    NoDQ,
    #[fail(display = "no qi")]
    NoQI,
}

#[derive(Debug, Fail)]
pub enum KeyError {
    #[fail(display = "no rsa jwk")]
    NoRsaJwk,
    #[fail(display = "no rsa pem")]
    NoRsaPem,
}

#[derive(Debug, Fail)]
pub enum SignerVerifierError {
    #[fail(display = "no publisher")]
    NoPublisher,
    #[fail(display = "attribute must be an object")]
    NonObjectAttribute,
    #[fail(display = "keys missing for publihser {}", _0)]
    NoPublisherKeys(String),
}

#[cfg(feature = "aws")]
#[derive(Debug, Fail)]
pub enum SsmError {
    #[fail(display = "no parameter")]
    NoParameter,
    #[fail(display = "no value")]
    NoValue,
}

#[cfg(feature = "well_known")]
#[derive(Debug, Fail)]
pub enum WellKnownError {
    #[fail(display = "unable to retrieve verify keys")]
    RetrieveVerifyKeysFailed,
}
