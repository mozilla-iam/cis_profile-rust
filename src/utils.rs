use crate::crypto::Signer;
use crate::schema::AccessInformationValuesArray;
use crate::schema::IdentitiesAttributesValuesArray;
use crate::schema::Profile;
use crate::schema::StaffInformationValuesArray;

pub fn sign_full_profile(profile: &mut Profile, store: &impl Signer) -> Result<(), String> {
    store.sign_attribute(&mut profile.active)?;
    store.sign_attribute(&mut profile.alternative_name)?;
    store.sign_attribute(&mut profile.created)?;
    store.sign_attribute(&mut profile.description)?;
    store.sign_attribute(&mut profile.first_name)?;
    store.sign_attribute(&mut profile.fun_title)?;
    store.sign_attribute(&mut profile.languages)?;
    store.sign_attribute(&mut profile.last_modified)?;
    store.sign_attribute(&mut profile.last_name)?;
    store.sign_attribute(&mut profile.location)?;
    store.sign_attribute(&mut profile.login_method)?;
    store.sign_attribute(&mut profile.pgp_public_keys)?;
    store.sign_attribute(&mut profile.phone_numbers)?;
    store.sign_attribute(&mut profile.picture)?;
    store.sign_attribute(&mut profile.primary_email)?;
    store.sign_attribute(&mut profile.primary_username)?;
    store.sign_attribute(&mut profile.pronouns)?;
    store.sign_attribute(&mut profile.ssh_public_keys)?;
    store.sign_attribute(&mut profile.tags)?;
    store.sign_attribute(&mut profile.timezone)?;
    store.sign_attribute(&mut profile.uris)?;
    store.sign_attribute(&mut profile.user_id)?;
    store.sign_attribute(&mut profile.usernames)?;
    store.sign_attribute(&mut profile.uuid)?;

    sign_accessinformation(&mut profile.access_information, store)?;
    sign_identities(&mut profile.identities, store)?;
    sign_staff_information(&mut profile.staff_information, store)?;
    Ok(())
}

fn sign_accessinformation(
    attr: &mut AccessInformationValuesArray,
    store: &impl Signer,
) -> Result<(), String> {
    store.sign_attribute(&mut attr.access_provider)?;
    store.sign_attribute(&mut attr.hris)?;
    store.sign_attribute(&mut attr.ldap)?;
    store.sign_attribute(&mut attr.mozilliansorg)?;
    Ok(())
}

fn sign_identities(
    attr: &mut IdentitiesAttributesValuesArray,
    store: &impl Signer,
) -> Result<(), String> {
    store.sign_attribute(&mut attr.github_id_v3)?;
    store.sign_attribute(&mut attr.github_id_v4)?;
    store.sign_attribute(&mut attr.github_primary_email)?;
    store.sign_attribute(&mut attr.mozilliansorg_id)?;
    store.sign_attribute(&mut attr.bugzilla_mozilla_org_id)?;
    store.sign_attribute(&mut attr.bugzilla_mozilla_org_primary_email)?;
    store.sign_attribute(&mut attr.mozilla_ldap_id)?;
    store.sign_attribute(&mut attr.mozilla_ldap_primary_email)?;
    store.sign_attribute(&mut attr.mozilla_posix_id)?;
    store.sign_attribute(&mut attr.google_oauth2_id)?;
    store.sign_attribute(&mut attr.google_primary_email)?;
    store.sign_attribute(&mut attr.firefox_accounts_id)?;
    store.sign_attribute(&mut attr.firefox_accounts_primary_email)?;
    Ok(())
}

fn sign_staff_information(
    attr: &mut StaffInformationValuesArray,
    store: &impl Signer,
) -> Result<(), String> {
    store.sign_attribute(&mut attr.manager)?;
    store.sign_attribute(&mut attr.director)?;
    store.sign_attribute(&mut attr.staff)?;
    store.sign_attribute(&mut attr.title)?;
    store.sign_attribute(&mut attr.team)?;
    store.sign_attribute(&mut attr.cost_center)?;
    store.sign_attribute(&mut attr.worker_type)?;
    store.sign_attribute(&mut attr.wpr_desk_number)?;
    store.sign_attribute(&mut attr.office_location)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::SecretStore;

    fn get_fake_store() -> SecretStore {
        let key = include_str!("../data/fake_key.json");
        SecretStore::default()
            .with_sign_keys_from_inline_iter(vec![
                (String::from("mozilliansorg"), key.to_owned()),
                (String::from("hris"), key.to_owned()),
                (String::from("ldap"), key.to_owned()),
                (String::from("cis"), key.to_owned()),
                (String::from("access_provider"), key.to_owned()),
            ])
            .unwrap()
    }

    #[test]
    fn test_sign_full_profile() -> Result<(), String> {
        let store = get_fake_store();
        let mut profile: Profile =
            serde_json::from_str(include_str!("../data/user_profile_null.json")).unwrap();
        sign_full_profile(&mut profile, &store)?;
        Ok(())
    }
}

#[cfg(feature = "aws")]
#[cfg(test)]
mod test_make {
    use super::*;
    use crate::crypto::SecretStore;

    use std::env;

    fn get_store() -> Option<SecretStore> {
        if let (
            Ok(mozillians_key_ssm_name),
            Ok(hris_key_ssm_name),
            Ok(ldap_key_ssm_name),
            Ok(cis_key_ssm_name),
            Ok(access_provider_key_ssm_name),
        ) = (
            env::var("CIS_SSM_MOZILLIANSORG_KEY"),
            env::var("CIS_SSM_HRIS_KEY"),
            env::var("CIS_SSM_LDAP_KEY"),
            env::var("CIS_SSM_CIS_KEY"),
            env::var("CIS_SSM_ACCESS_PROVIDER_KEY"),
        ) {
            Some(
                SecretStore::default()
                    .with_sign_keys_from_ssm_iter(vec![
                        (String::from("mozilliansorg"), mozillians_key_ssm_name),
                        (String::from("hris"), hris_key_ssm_name),
                        (String::from("ldap"), ldap_key_ssm_name),
                        (String::from("cis"), cis_key_ssm_name),
                        (
                            String::from("access_provider"),
                            access_provider_key_ssm_name,
                        ),
                    ])
                    .unwrap(),
            )
        } else {
            None
        }
    }

    #[test]
    fn test_make_profile() -> Result<(), String> {
        if let Some(store) = get_store() {
            let mut profile: Profile =
                serde_json::from_str(include_str!("../data/user_profile_null_create.json"))
                    .unwrap();
            profile.primary_email.value = Some(String::from("hknall@mozilla.com"));
            profile.user_id.value = Some(String::from("ad|Mozilla-LDAP|hknall"));
            profile.primary_username.value = Some(String::from("hknall"));
            profile.uuid.value = Some(String::from("746dad92-3f94-4eed-9e25-7bc20e0041ec"));
            sign_full_profile(&mut profile, &store)?;
        }
        Ok(())
    }
}
