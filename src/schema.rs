use crate::error::SignerVerifierError;
use chrono::DateTime;
use chrono::NaiveDateTime;
use chrono::SecondsFormat;
use chrono::Utc;
use dino_park_trust::Trust;
use failure::format_err;
use failure::Error;
use lazy_static::lazy_static;
use serde::Deserializer;
use serde::Serializer;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use serde_json::to_value;
use serde_json::Value;
use std::collections::BTreeMap;
use std::convert::TryFrom;

#[cfg(feature = "graphql")]
use juniper::{GraphQLEnum, GraphQLObject, ParseScalarValue};
#[cfg(feature = "graphql")]
use std::iter::FromIterator;

lazy_static! {
    static ref ZERO: DateTime<Utc> =
        DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
}
pub fn serialize_datetime<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&date.to_rfc3339_opts(SecondsFormat::Millis, true))
}

pub fn deserialize_datetime<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::Deserialize;
    let s = String::deserialize(deserializer)?;
    DateTime::parse_from_rfc3339(&s)
        .map(Into::into)
        .or_else(|_| {
            NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT:%H:%M:%S%.fZ")
                .map(|d| DateTime::from_utc(d, Utc))
        })
        .or_else(|_| DateTime::parse_from_str(&s, "%Y-%m-%dT:%H:%M:%S%.f%z").map(Into::into))
        .map_err(serde::de::Error::custom)
}

/// Trait implement by field types. Exposes the publisher of a field for signing and verifying.
pub trait WithPublisher {
    /// Set the publisher.
    fn set_publisher(&mut self, publisher: Publisher);
    // Retrieve data as `Value`. For field typed this should return the payload to sign or verify.
    fn data(&self) -> Result<Value, Error>;
    // Retrieve the publisher.
    fn get_publisher(&self) -> &Publisher;
    // Check wether the field type shoud be considered empty.
    fn is_empty(&self) -> bool;
}

/// We only support String → String dictionaries for now.
#[derive(Default, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct KeyValue(pub BTreeMap<String, Option<String>>);

#[cfg(feature = "graphql")]
#[juniper::graphql_scalar(name = "KeyValue")]
impl<S> GraphQLScalar for KeyValue
where
    S: juniper::ScalarValue,
{
    fn resolve(&self) -> juniper::Value {
        juniper::Value::Object(juniper::Object::from_iter(
            self.0
                .iter()
                .map(|(k, v)| (k.clone(), juniper::Value::from(v.clone()))),
        ))
    }
    fn from_input_value(v: &InputValue) -> Option<KeyValue> {
        v.to_object_value().map(|o| {
            KeyValue(
                o.iter()
                    .map(|(k, v)| (String::from(*k), v.as_string_value().map(ToOwned::to_owned)))
                    .collect(),
            )
        })
    }
    fn from_str<'a>(value: ScalarToken<'a>) -> juniper::ParseScalarResult<'a, S> {
        <String as ParseScalarValue<S>>::from_str(value)
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLEnum))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum Alg {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "HS256")]
    Hs256,
    #[serde(rename = "RSA")]
    Rsa,
    #[serde(rename = "ED25519")]
    Ed25519,
}

/// Data classification for fields.
#[cfg_attr(feature = "graphql", derive(GraphQLEnum))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum Classification {
    #[serde(rename = "MOZILLA CONFIDENTIAL")]
    MozillaConfidential,
    #[serde(rename = "WORKGROUP CONFIDENTIAL: STAFF ONLY")]
    WorkgroupConfidentialStaffOnly,
    #[serde(rename = "WORKGROUP CONFIDENTIAL")]
    WorkgroupConfidential,
    #[serde(rename = "PUBLIC")]
    Public,
    #[serde(rename = "INDIVIDUAL CONFIDENTIAL")]
    IndividualConfidential,
}

impl Default for Classification {
    fn default() -> Self {
        Classification::WorkgroupConfidential
    }
}

/// Display level for fields. This reflects a users preference and may overrule data classification
/// for displaying purposes. The values are ordered and implicitly include all stricter display
/// levels (e.g. `ndaed` includes `staff` and `private`).
#[cfg_attr(feature = "graphql", derive(GraphQLEnum))]
#[derive(Clone, PartialEq, Eq, PartialOrd, Debug, Deserialize, Serialize)]
pub enum Display {
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "authenticated")]
    Authenticated,
    #[serde(rename = "vouched")]
    Vouched,
    #[serde(rename = "ndaed")]
    Ndaed,
    #[serde(rename = "staff")]
    Staff,
    #[serde(rename = "private")]
    Private,
}

impl From<Trust> for Display {
    fn from(t: Trust) -> Self {
        match t {
            Trust::Staff => Self::Staff,
            Trust::Ndaed => Self::Ndaed,
            Trust::Vouched => Self::Vouched,
            Trust::Authenticated => Self::Authenticated,
            Trust::Public => Self::Public,
        }
    }
}

impl Display {
    pub fn as_str(&self) -> &str {
        match self {
            Display::Public => "public",
            Display::Authenticated => "authenticated",
            Display::Vouched => "vouched",
            Display::Ndaed => "ndaed",
            Display::Staff => "staff",
            Display::Private => "private",
        }
    }
}

impl TryFrom<&str> for Display {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value.to_lowercase().as_str() {
            "public" => Display::Public,
            "authenticated" => Display::Authenticated,
            "vouched" => Display::Vouched,
            "ndaed" => Display::Ndaed,
            "staff" => Display::Staff,
            "private" => Display::Private,
            _ => return Err(format_err!("invalid display value: {}", value)),
        })
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Metadata {
    pub classification: Classification,
    #[serde(serialize_with = "serialize_datetime")]
    #[serde(deserialize_with = "deserialize_datetime")]
    pub created: DateTime<Utc>,
    pub display: Option<Display>,
    #[serde(serialize_with = "serialize_datetime")]
    #[serde(deserialize_with = "deserialize_datetime")]
    pub last_modified: DateTime<Utc>,
    pub verified: bool,
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata::with(None, Classification::default())
    }
}

impl Metadata {
    fn with(display: Option<Display>, classification: Classification) -> Self {
        Metadata {
            classification,
            created: *ZERO,
            display,
            last_modified: *ZERO,
            verified: false,
        }
    }
}

/// Publisher authorities in the IAM project.
#[cfg_attr(feature = "graphql", derive(GraphQLEnum))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum PublisherAuthority {
    #[serde(rename = "ldap")]
    Ldap,
    #[serde(rename = "mozilliansorg")]
    Mozilliansorg,
    #[serde(rename = "hris")]
    Hris,
    #[serde(rename = "cis")]
    Cis,
    #[serde(rename = "access_provider")]
    AccessProvider,
}

impl PublisherAuthority {
    pub fn as_str(&self) -> &str {
        match *self {
            PublisherAuthority::Ldap => "ldap",
            PublisherAuthority::Mozilliansorg => "mozilliansorg",
            PublisherAuthority::Hris => "hris",
            PublisherAuthority::Cis => "cis",
            PublisherAuthority::AccessProvider => "access_provider",
        }
    }
}

impl TryFrom<&str> for PublisherAuthority {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value.to_lowercase().as_str() {
            "ldap" => PublisherAuthority::Ldap,
            "mozilliansorg" => PublisherAuthority::Mozilliansorg,
            "hris" => PublisherAuthority::Hris,
            "cis" => PublisherAuthority::Cis,
            "access_provider" => PublisherAuthority::AccessProvider,
            _ => return Err(format_err!("invalid publisher value: {}", value)),
        })
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AdditionalPublisher {
    pub alg: Alg,
    pub name: Option<String>,
    pub typ: Typ,
    pub value: String,
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Publisher {
    pub alg: Alg,
    pub name: PublisherAuthority,
    pub typ: Typ,
    pub value: String,
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Signature {
    pub additional: Vec<AdditionalPublisher>,
    pub publisher: Publisher,
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            additional: vec![],
            publisher: Publisher {
                alg: Alg::Rs256,
                name: PublisherAuthority::Mozilliansorg,
                typ: Typ::Jws,
                value: String::default(),
            },
        }
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct StandardAttributeBoolean {
    pub metadata: Metadata,
    pub signature: Signature,
    pub value: Option<bool>,
}

impl StandardAttributeBoolean {
    fn with(value: Option<bool>, display: Option<Display>, classification: Classification) -> Self {
        StandardAttributeBoolean {
            metadata: Metadata::with(display, classification),
            signature: Signature::default(),
            value,
        }
    }
}

impl WithPublisher for StandardAttributeBoolean {
    fn set_publisher(&mut self, publisher: Publisher) {
        self.signature.publisher = publisher;
    }
    fn get_publisher(&self) -> &Publisher {
        &self.signature.publisher
    }
    fn data(&self) -> Result<Value, Error> {
        let mut c = match to_value(self) {
            Ok(Value::Object(o)) => o,
            _ => return Err(SignerVerifierError::NonObjectAttribute.into()),
        };
        c.remove("signature");
        Ok(Value::from(c))
    }
    fn is_empty(&self) -> bool {
        self.value.is_none()
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct StandardAttributeString {
    pub metadata: Metadata,
    pub signature: Signature,
    #[serde(default)]
    pub value: Option<String>,
}

impl StandardAttributeString {
    fn with(display: Option<Display>, classification: Classification) -> Self {
        StandardAttributeString {
            metadata: Metadata::with(display, classification),
            signature: Signature::default(),
            value: None,
        }
    }
}

impl WithPublisher for StandardAttributeString {
    fn set_publisher(&mut self, publisher: Publisher) {
        self.signature.publisher = publisher;
    }
    fn get_publisher(&self) -> &Publisher {
        &self.signature.publisher
    }
    fn data(&self) -> Result<Value, Error> {
        let mut c = match serde_json::to_value(self) {
            Ok(Value::Object(o)) => o,
            _ => return Err(SignerVerifierError::NonObjectAttribute.into()),
        };
        c.remove("signature");
        Ok(Value::from(c))
    }
    fn is_empty(&self) -> bool {
        self.value.is_none()
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct StandardAttributeValues {
    pub metadata: Metadata,
    pub signature: Signature,
    pub values: Option<KeyValue>,
}

impl StandardAttributeValues {
    fn with(display: Option<Display>, classification: Classification) -> Self {
        StandardAttributeValues {
            metadata: Metadata::with(display, classification),
            signature: Signature::default(),
            values: None,
        }
    }
}

impl WithPublisher for StandardAttributeValues {
    fn set_publisher(&mut self, publisher: Publisher) {
        self.signature.publisher = publisher;
    }
    fn get_publisher(&self) -> &Publisher {
        &self.signature.publisher
    }
    fn data(&self) -> Result<Value, Error> {
        let mut c = match to_value(self) {
            Ok(Value::Object(o)) => o,
            _ => return Err(SignerVerifierError::NonObjectAttribute.into()),
        };
        c.remove("signature");
        Ok(Value::from(c))
    }
    fn is_empty(&self) -> bool {
        self.values.is_none()
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLEnum))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum Typ {
    #[serde(rename = "JWS")]
    Jws,
    #[serde(rename = "PGP")]
    Pgp,
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AccessInformationProviderSubObject {
    pub metadata: Metadata,
    pub signature: Signature,
    pub values: Option<KeyValue>,
}

impl Default for AccessInformationProviderSubObject {
    fn default() -> Self {
        AccessInformationProviderSubObject::with(None, Classification::default())
    }
}

impl AccessInformationProviderSubObject {
    fn with(display: Option<Display>, classification: Classification) -> Self {
        AccessInformationProviderSubObject {
            metadata: Metadata::with(display, classification),
            signature: Signature::default(),
            values: None,
        }
    }
}

impl WithPublisher for AccessInformationProviderSubObject {
    fn set_publisher(&mut self, publisher: Publisher) {
        self.signature.publisher = publisher;
    }
    fn get_publisher(&self) -> &Publisher {
        &self.signature.publisher
    }
    fn data(&self) -> Result<Value, Error> {
        let mut c = match to_value(self) {
            Ok(Value::Object(o)) => o,
            _ => return Err(SignerVerifierError::NonObjectAttribute.into()),
        };
        c.remove("signature");
        Ok(Value::from(c))
    }
    fn is_empty(&self) -> bool {
        self.values.is_none()
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AccessInformationValuesArray {
    #[serde(default)]
    pub access_provider: AccessInformationProviderSubObject,
    #[serde(default)]
    pub hris: AccessInformationProviderSubObject,
    #[serde(default)]
    pub ldap: AccessInformationProviderSubObject,
    #[serde(default)]
    pub mozilliansorg: AccessInformationProviderSubObject,
}

impl Default for AccessInformationValuesArray {
    fn default() -> Self {
        AccessInformationValuesArray {
            access_provider: AccessInformationProviderSubObject::default(),
            hris: AccessInformationProviderSubObject::with(
                None,
                Classification::WorkgroupConfidentialStaffOnly,
            ),
            ldap: AccessInformationProviderSubObject::with(None, Classification::Public),
            mozilliansorg: AccessInformationProviderSubObject::with(None, Classification::Public),
        }
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct IdentitiesAttributesValuesArray {
    #[serde(default)]
    pub github_id_v3: StandardAttributeString,
    #[serde(default)]
    pub github_id_v4: StandardAttributeString,
    #[serde(default)]
    pub github_primary_email: StandardAttributeString,
    #[serde(default)]
    pub mozilliansorg_id: StandardAttributeString,
    #[serde(default)]
    pub bugzilla_mozilla_org_id: StandardAttributeString,
    #[serde(default)]
    pub bugzilla_mozilla_org_primary_email: StandardAttributeString,
    #[serde(default)]
    pub mozilla_ldap_id: StandardAttributeString,
    #[serde(default)]
    pub mozilla_ldap_primary_email: StandardAttributeString,
    #[serde(default)]
    pub mozilla_posix_id: StandardAttributeString,
    #[serde(default)]
    pub google_oauth2_id: StandardAttributeString,
    #[serde(default)]
    pub google_primary_email: StandardAttributeString,
    #[serde(default)]
    pub firefox_accounts_id: StandardAttributeString,
    #[serde(default)]
    pub firefox_accounts_primary_email: StandardAttributeString,
    #[serde(default)]
    pub custom_1_primary_email: StandardAttributeString,
    #[serde(default)]
    pub custom_2_primary_email: StandardAttributeString,
    #[serde(default)]
    pub custom_3_primary_email: StandardAttributeString,
}

impl Default for IdentitiesAttributesValuesArray {
    fn default() -> Self {
        IdentitiesAttributesValuesArray {
            github_id_v3: StandardAttributeString::default(),
            github_id_v4: StandardAttributeString::default(),
            github_primary_email: StandardAttributeString::default(),
            mozilliansorg_id: StandardAttributeString::default(),
            bugzilla_mozilla_org_id: StandardAttributeString::default(),
            bugzilla_mozilla_org_primary_email: StandardAttributeString::default(),
            mozilla_ldap_id: StandardAttributeString::with(
                Some(Display::Staff),
                Classification::default(),
            ),
            mozilla_ldap_primary_email: StandardAttributeString::with(
                Some(Display::Staff),
                Classification::default(),
            ),
            mozilla_posix_id: StandardAttributeString::with(
                Some(Display::Staff),
                Classification::default(),
            ),
            google_oauth2_id: StandardAttributeString::default(),
            google_primary_email: StandardAttributeString::default(),
            firefox_accounts_id: StandardAttributeString::default(),
            firefox_accounts_primary_email: StandardAttributeString::default(),
            custom_1_primary_email: StandardAttributeString::default(),
            custom_2_primary_email: StandardAttributeString::default(),
            custom_3_primary_email: StandardAttributeString::default(),
        }
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct StaffInformationValuesArray {
    #[serde(default)]
    pub manager: StandardAttributeBoolean,
    #[serde(default)]
    pub director: StandardAttributeBoolean,
    #[serde(default)]
    pub staff: StandardAttributeBoolean,
    #[serde(default)]
    pub title: StandardAttributeString,
    #[serde(default)]
    pub team: StandardAttributeString,
    #[serde(default)]
    pub cost_center: StandardAttributeString,
    #[serde(default)]
    pub worker_type: StandardAttributeString,
    #[serde(default)]
    pub wpr_desk_number: StandardAttributeString,
    #[serde(default)]
    pub office_location: StandardAttributeString,
}

impl Default for StaffInformationValuesArray {
    fn default() -> Self {
        StaffInformationValuesArray {
            manager: StandardAttributeBoolean::with(
                None,
                Some(Display::Ndaed),
                Classification::MozillaConfidential,
            ),
            director: StandardAttributeBoolean::with(
                None,
                Some(Display::Ndaed),
                Classification::MozillaConfidential,
            ),
            staff: StandardAttributeBoolean::with(
                None,
                Some(Display::Ndaed),
                Classification::MozillaConfidential,
            ),
            title: StandardAttributeString::with(
                Some(Display::Ndaed),
                Classification::MozillaConfidential,
            ),
            team: StandardAttributeString::with(
                Some(Display::Ndaed),
                Classification::MozillaConfidential,
            ),
            cost_center: StandardAttributeString::with(
                Some(Display::Staff),
                Classification::WorkgroupConfidentialStaffOnly,
            ),
            worker_type: StandardAttributeString::with(
                Some(Display::Staff),
                Classification::WorkgroupConfidentialStaffOnly,
            ),
            wpr_desk_number: StandardAttributeString::with(
                Some(Display::Ndaed),
                Classification::MozillaConfidential,
            ),
            office_location: StandardAttributeString::with(
                Some(Display::Ndaed),
                Classification::MozillaConfidential,
            ),
        }
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Profile {
    #[serde(default)]
    pub access_information: AccessInformationValuesArray,
    #[serde(default)]
    pub active: StandardAttributeBoolean,
    #[serde(default)]
    pub alternative_name: StandardAttributeString,
    #[serde(default)]
    pub created: StandardAttributeString,
    #[serde(default)]
    pub description: StandardAttributeString,
    #[serde(default)]
    pub first_name: StandardAttributeString,
    #[serde(default)]
    pub fun_title: StandardAttributeString,
    #[serde(default)]
    pub identities: IdentitiesAttributesValuesArray,
    #[serde(default)]
    pub languages: StandardAttributeValues,
    #[serde(default)]
    pub last_modified: StandardAttributeString,
    #[serde(default)]
    pub last_name: StandardAttributeString,
    #[serde(default)]
    pub location: StandardAttributeString,
    #[serde(default)]
    pub login_method: StandardAttributeString,
    #[serde(default)]
    pub pgp_public_keys: StandardAttributeValues,
    #[serde(default)]
    pub phone_numbers: StandardAttributeValues,
    #[serde(default)]
    pub picture: StandardAttributeString,
    #[serde(default)]
    pub primary_email: StandardAttributeString,
    #[serde(default)]
    pub primary_username: StandardAttributeString,
    #[serde(default)]
    pub pronouns: StandardAttributeString,
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub ssh_public_keys: StandardAttributeValues,
    #[serde(default)]
    pub staff_information: StaffInformationValuesArray,
    #[serde(default)]
    pub tags: StandardAttributeValues,
    #[serde(default)]
    pub timezone: StandardAttributeString,
    #[serde(default)]
    pub uris: StandardAttributeValues,
    #[serde(default)]
    pub user_id: StandardAttributeString,
    #[serde(default)]
    pub usernames: StandardAttributeValues,
    #[serde(default)]
    pub uuid: StandardAttributeString,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            access_information: AccessInformationValuesArray::default(),
            active: StandardAttributeBoolean::with(Some(true), None, Classification::default()),
            alternative_name: StandardAttributeString::default(),
            created: StandardAttributeString::with(None, Classification::Public),
            description: StandardAttributeString::default(),
            first_name: StandardAttributeString::with(None, Classification::Public),
            fun_title: StandardAttributeString::default(),
            identities: IdentitiesAttributesValuesArray::default(),
            languages: StandardAttributeValues::default(),
            last_modified: StandardAttributeString::with(None, Classification::Public),
            last_name: StandardAttributeString::with(None, Classification::Public),
            location: StandardAttributeString::default(),
            login_method: StandardAttributeString::with(None, Classification::Public),
            pgp_public_keys: StandardAttributeValues::with(None, Classification::Public),
            phone_numbers: StandardAttributeValues::default(),
            picture: StandardAttributeString::with(None, Classification::Public),
            primary_email: StandardAttributeString::with(None, Classification::Public),
            primary_username: StandardAttributeString::with(
                Some(Display::Public),
                Classification::Public,
            ),
            pronouns: StandardAttributeString::default(),
            schema: String::from("https://person-api.sso.mozilla.com/schema/v2/profile"),
            ssh_public_keys: StandardAttributeValues::with(None, Classification::Public),
            staff_information: StaffInformationValuesArray::default(),
            tags: StandardAttributeValues::default(),
            timezone: StandardAttributeString::default(),
            uris: StandardAttributeValues::default(),
            user_id: StandardAttributeString::with(None, Classification::Public),
            usernames: StandardAttributeValues::with(
                Some(Display::Public),
                Classification::default(),
            ),
            uuid: StandardAttributeString::with(Some(Display::Public), Classification::Public),
        }
    }
}

#[cfg(feature = "graphql")]
#[cfg(test)]
mod graphql_test {
    use super::*;
    use juniper::parser::Spanning;
    use juniper::FromInputValue;
    use juniper::InputValue;

    #[test]
    fn key_val() {
        let object = vec![
            (
                Spanning::unlocated("foo".to_owned()),
                Spanning::unlocated(InputValue::scalar("foobar1".to_owned())),
            ),
            (
                Spanning::unlocated("bar".to_owned()),
                Spanning::unlocated(InputValue::scalar("foobar2".to_owned())),
            ),
        ];
        let value: InputValue = InputValue::parsed_object(object);
        let kv = KeyValue::from_input_value(&value).unwrap();
        assert_eq!(kv.0.get("foo"), Some(&Some("foobar1".to_owned())));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use failure::Error;
    use valico::json_schema;

    #[test]
    fn basic_profile() {
        let _ = Profile::default();
    }

    #[test]
    fn default_profile_validates() -> Result<(), Error> {
        let profile = Profile::default();
        let schema: Value = serde_json::from_str(include_str!("../data/profile.schema"))?;
        let mut scope = json_schema::Scope::new();
        let schema = scope.compile_and_return(schema, false)?;
        let valid = schema.validate(&to_value(&profile)?);
        assert!(valid.is_valid());
        Ok(())
    }

    #[test]
    fn test_fake_profile() {
        let p = include_str!("../data/user_profile_null.json");
        let profile: Result<Profile, _> = serde_json::from_str(p);
        assert!(profile.is_ok());
    }

    #[test]
    fn test_broken_tz() {
        let p = include_str!("../data/broken_tz.json");
        let profile: Result<Profile, _> = serde_json::from_str(p);
        assert!(profile.is_ok());
    }

    #[test]
    fn test_partial_profile() {
        let p = include_str!("../data/user_profile_partial.json");
        let profile: Result<Profile, _> = serde_json::from_str(p);
        assert!(profile.is_ok());
        assert_eq!(
            profile.unwrap().primary_username.value,
            Some(String::from("fiji"))
        );
    }

    #[test]
    fn test_display_to_str() -> Result<(), Error> {
        assert_eq!(
            format!(r#""{}""#, Display::Public.as_str()),
            serde_json::to_string(&Display::Public)?
        );
        assert_eq!(
            format!(r#""{}""#, Display::Authenticated.as_str()),
            serde_json::to_string(&Display::Authenticated)?
        );
        assert_eq!(
            format!(r#""{}""#, Display::Vouched.as_str()),
            serde_json::to_string(&Display::Vouched)?
        );
        assert_eq!(
            format!(r#""{}""#, Display::Ndaed.as_str()),
            serde_json::to_string(&Display::Ndaed)?
        );
        assert_eq!(
            format!(r#""{}""#, Display::Staff.as_str()),
            serde_json::to_string(&Display::Staff)?
        );
        assert_eq!(
            format!(r#""{}""#, Display::Private.as_str()),
            serde_json::to_string(&Display::Private)?
        );
        Ok(())
    }

    #[test]
    fn test_display_from_str() -> Result<(), Error> {
        assert_eq!(Display::try_from("public")?, Display::Public);
        assert_eq!(Display::try_from("AUTHENTICATED")?, Display::Authenticated);
        assert_eq!(Display::try_from("Vouched")?, Display::Vouched);
        assert_eq!(Display::try_from("ndaed")?, Display::Ndaed);
        assert_eq!(Display::try_from("staff")?, Display::Staff);
        assert_eq!(Display::try_from("private")?, Display::Private);
        assert!(Display::try_from("foobar").is_err());
        Ok(())
    }

    #[test]
    fn test_display_from_trust() {
        assert_eq!(Display::from(Trust::Public), Display::Public);
        assert_eq!(Display::from(Trust::Authenticated), Display::Authenticated);
        assert_eq!(Display::from(Trust::Vouched), Display::Vouched);
        assert_eq!(Display::from(Trust::Ndaed), Display::Ndaed);
        assert_eq!(Display::from(Trust::Staff), Display::Staff);
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_display_order() {
        assert!(Display::Private > Display::Staff);
        assert!(Display::Staff >= Display::Staff);
        assert!(Display::Staff > Display::Ndaed);
        assert!(Display::Public < Display::Staff);
        assert!(Display::Public < Display::Ndaed);
        assert!(Display::Public < Display::Vouched);
        assert!(Display::Public < Display::Authenticated);
        assert!(Display::Public <= Display::Public);
    }

    #[test]
    fn test_publisher_authority_to_from_str() -> Result<(), Error> {
        assert_eq!(
            PublisherAuthority::AccessProvider.as_str(),
            "access_provider"
        );
        assert_eq!(PublisherAuthority::Cis.as_str(), "cis");
        assert_eq!(PublisherAuthority::Hris.as_str(), "hris");
        assert_eq!(PublisherAuthority::Ldap.as_str(), "ldap");
        assert_eq!(PublisherAuthority::Mozilliansorg.as_str(), "mozilliansorg");
        assert_eq!(
            PublisherAuthority::try_from("access_provider")?,
            PublisherAuthority::AccessProvider
        );
        assert_eq!(
            PublisherAuthority::try_from("Cis")?,
            PublisherAuthority::Cis
        );
        assert_eq!(
            PublisherAuthority::try_from("HRIS")?,
            PublisherAuthority::Hris
        );
        assert_eq!(
            PublisherAuthority::try_from("ldap")?,
            PublisherAuthority::Ldap
        );
        assert_eq!(
            PublisherAuthority::try_from("mozilliansorg")?,
            PublisherAuthority::Mozilliansorg
        );
        assert!(PublisherAuthority::try_from("foobar").is_err());
        Ok(())
    }
}
