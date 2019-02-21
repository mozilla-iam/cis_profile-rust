#[cfg(feature = "graphql")]
use juniper::{GraphQLEnum, GraphQLObject, ParseScalarValue, Value};
#[cfg(feature = "graphql")]
use std::iter::FromIterator;

use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub trait Sign {
    fn sign(&mut self, publisher: Publisher);
}

#[derive(Default, Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct KeyValue(pub BTreeMap<String, serde_json::Value>);

// this uses strings to convert between juniper and json: FIXME
#[cfg(feature = "graphql")]
graphql_scalar!(KeyValue as "KeyValue" where Scalar = <S> {
    resolve(&self) -> Value {
        Value::Object(
            juniper::Object::from_iter(
                self.0.iter()
                    .map(|(k, v)| (k.clone(), juniper::Value::from(serde_json::to_string(v).unwrap())))))
    }
    from_input_value(v: &InputValue) -> Option<KeyValue> {
        v.to_object_value().map(|o| KeyValue(BTreeMap::from_iter(o.iter().map(|(k,v)| (String::from(*k), {
            serde_json::from_str(&v.to_string()).unwrap()
        })))))
    }
    from_str<'a>(value: ScalarToken<'a>) -> juniper::ParseScalarResult<'a, S> {
        <String as ParseScalarValue<S>>::from_str(value)
    }
});

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
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

impl Sign for AccessInformationProviderSubObject {
    fn sign(&mut self, publisher: Publisher) {
        self.signature.publisher = publisher;
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLEnum))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum Alg {
    #[serde(rename = "HS256")]
    Hs256,
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "RSA")]
    Rsa,
    #[serde(rename = "ED25519")]
    Ed25519,
}

#[cfg_attr(feature = "graphql", derive(GraphQLEnum))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
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

#[cfg_attr(feature = "graphql", derive(GraphQLEnum))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
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

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct Metadata {
    pub classification: Classification,
    pub created: String,
    pub display: Option<Display>,
    pub last_modified: String,
    pub verified: bool,
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata::with(Some(Display::Staff), Classification::default())
    }
}

impl Metadata {
    fn with(display: Option<Display>, classification: Classification) -> Self {
        Metadata {
            classification,
            created: String::default(),
            display,
            last_modified: String::default(),
            verified: false,
        }
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLEnum))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
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

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct AdditionalPublisher {
    pub alg: Alg,
    pub name: Option<String>,
    pub typ: Typ,
    pub value: String,
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct Publisher {
    pub alg: Alg,
    pub name: PublisherAuthority,
    pub typ: Typ,
    pub value: String,
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct Signature {
    pub additional: Vec<AdditionalPublisher>,
    pub publisher: Publisher,
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            additional: vec![],
            publisher: Publisher {
                alg: Alg::Hs256,
                name: PublisherAuthority::Mozilliansorg,
                typ: Typ::Jws,
                value: String::default(),
            },
        }
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
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

impl Sign for StandardAttributeBoolean {
    fn sign(&mut self, publisher: Publisher) {
        self.signature.publisher = publisher;
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
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

impl Sign for StandardAttributeString {
    fn sign(&mut self, publisher: Publisher) {
        self.signature.publisher = publisher;
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
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

impl Sign for StandardAttributeValues {
    fn sign(&mut self, publisher: Publisher) {
        self.signature.publisher = publisher;
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLEnum))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum Typ {
    #[serde(rename = "JWS")]
    Jws,
    #[serde(rename = "PGP")]
    Pgp,
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
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
            mozilliansorg: AccessInformationProviderSubObject::with(
                Some(Display::Staff),
                Classification::Public,
            ),
        }
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
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
}

impl Default for IdentitiesAttributesValuesArray {
    fn default() -> Self {
        IdentitiesAttributesValuesArray {
            github_id_v3: StandardAttributeString::default(),
            github_id_v4: StandardAttributeString::default(),
            github_primary_email: StandardAttributeString::with(
                Some(Display::Public),
                Classification::default(),
            ),
            mozilliansorg_id: StandardAttributeString::with(
                Some(Display::Staff),
                Classification::default(),
            ),
            bugzilla_mozilla_org_id: StandardAttributeString::default(),
            bugzilla_mozilla_org_primary_email: StandardAttributeString::with(
                Some(Display::Public),
                Classification::default(),
            ),
            mozilla_ldap_id: StandardAttributeString::with(
                Some(Display::Staff),
                Classification::default(),
            ),
            mozilla_ldap_primary_email: StandardAttributeString::with(
                Some(Display::Public),
                Classification::default(),
            ),
            mozilla_posix_id: StandardAttributeString::default(),
            google_oauth2_id: StandardAttributeString::default(),
            google_primary_email: StandardAttributeString::with(
                Some(Display::Public),
                Classification::default(),
            ),
            firefox_accounts_id: StandardAttributeString::default(),
            firefox_accounts_primary_email: StandardAttributeString::with(
                Some(Display::Public),
                Classification::default(),
            ),
        }
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
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
            manager: StandardAttributeBoolean::default(),
            director: StandardAttributeBoolean::default(),
            staff: StandardAttributeBoolean::default(),
            title: StandardAttributeString::default(),
            team: StandardAttributeString::default(),
            cost_center: StandardAttributeString::with(
                Some(Display::Staff),
                Classification::WorkgroupConfidentialStaffOnly,
            ),
            worker_type: StandardAttributeString::with(
                Some(Display::Staff),
                Classification::WorkgroupConfidentialStaffOnly,
            ),
            wpr_desk_number: StandardAttributeString::default(),
            office_location: StandardAttributeString::default(),
        }
    }
}

#[cfg_attr(feature = "graphql", derive(GraphQLObject))]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
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
            created: StandardAttributeString::with(Some(Display::Private), Classification::Public),
            description: StandardAttributeString::default(),
            first_name: StandardAttributeString::with(Some(Display::Staff), Classification::Public),
            fun_title: StandardAttributeString::default(),
            identities: IdentitiesAttributesValuesArray::default(),
            languages: StandardAttributeValues::default(),
            last_modified: StandardAttributeString::with(
                Some(Display::Staff),
                Classification::Public,
            ),
            last_name: StandardAttributeString::with(Some(Display::Staff), Classification::Public),
            location: StandardAttributeString::default(),
            login_method: StandardAttributeString::with(
                Some(Display::Staff),
                Classification::Public,
            ),
            pgp_public_keys: StandardAttributeValues::with(
                Some(Display::Staff),
                Classification::Public,
            ),
            phone_numbers: StandardAttributeValues::default(),
            picture: StandardAttributeString::with(Some(Display::Staff), Classification::Public),
            primary_email: StandardAttributeString::with(
                Some(Display::Staff),
                Classification::Public,
            ),
            primary_username: StandardAttributeString::with(
                Some(Display::Public),
                Classification::Public,
            ),
            pronouns: StandardAttributeString::default(),
            schema: String::from("https://person-api.sso.mozilla.com/schema/v2/profile"),
            ssh_public_keys: StandardAttributeValues::with(
                Some(Display::Staff),
                Classification::Public,
            ),
            staff_information: StaffInformationValuesArray::default(),
            tags: StandardAttributeValues::default(),
            timezone: StandardAttributeString::default(),
            uris: StandardAttributeValues::default(),
            user_id: StandardAttributeString::with(Some(Display::Staff), Classification::Public),
            usernames: StandardAttributeValues::with(
                Some(Display::Public),
                Classification::default(),
            ),
            uuid: StandardAttributeString::with(Some(Display::Public), Classification::Public),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic_profile() {
        let _ = Profile::default();
    }

    #[test]
    fn test_fake_profile() {
        let p = include_str!("../data/user_profile_null.json");
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
}
