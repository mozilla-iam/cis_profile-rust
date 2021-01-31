use crate::crypto::Signer;
use crate::crypto::Verifier;
use crate::error::KeyError;
use crate::schema::AccessInformationValuesArray;
use crate::schema::IdentitiesAttributesValuesArray;
use crate::schema::Profile;
use crate::schema::StaffInformationValuesArray;

/// Sign all fields of a profile with the given `Signer`.
pub fn verify_full_profile(profile: &Profile, store: &impl Verifier) -> Result<(), KeyError> {
    store.verify_attribute(&profile.active)?;
    store.verify_attribute(&profile.alternative_name)?;
    store.verify_attribute(&profile.created)?;
    store.verify_attribute(&profile.description)?;
    store.verify_attribute(&profile.first_name)?;
    store.verify_attribute(&profile.fun_title)?;
    store.verify_attribute(&profile.languages)?;
    store.verify_attribute(&profile.last_modified)?;
    store.verify_attribute(&profile.last_name)?;
    store.verify_attribute(&profile.location)?;
    store.verify_attribute(&profile.login_method)?;
    store.verify_attribute(&profile.pgp_public_keys)?;
    store.verify_attribute(&profile.phone_numbers)?;
    store.verify_attribute(&profile.picture)?;
    store.verify_attribute(&profile.primary_email)?;
    store.verify_attribute(&profile.primary_username)?;
    store.verify_attribute(&profile.pronouns)?;
    store.verify_attribute(&profile.ssh_public_keys)?;
    store.verify_attribute(&profile.tags)?;
    store.verify_attribute(&profile.timezone)?;
    store.verify_attribute(&profile.uris)?;
    store.verify_attribute(&profile.user_id)?;
    store.verify_attribute(&profile.usernames)?;
    store.verify_attribute(&profile.uuid)?;

    verify_accessinformation(&profile.access_information, store)?;
    verify_identities(&profile.identities, store)?;
    verify_staff_information(&profile.staff_information, store)?;
    Ok(())
}

fn verify_accessinformation(
    attr: &AccessInformationValuesArray,
    store: &impl Verifier,
) -> Result<(), KeyError> {
    store.verify_attribute(&attr.access_provider)?;
    store.verify_attribute(&attr.hris)?;
    store.verify_attribute(&attr.ldap)?;
    store.verify_attribute(&attr.mozilliansorg)?;
    Ok(())
}

fn verify_identities(
    attr: &IdentitiesAttributesValuesArray,
    store: &impl Verifier,
) -> Result<(), KeyError> {
    store.verify_attribute(&attr.github_id_v3)?;
    store.verify_attribute(&attr.github_id_v4)?;
    store.verify_attribute(&attr.github_primary_email)?;
    store.verify_attribute(&attr.mozilliansorg_id)?;
    store.verify_attribute(&attr.bugzilla_mozilla_org_id)?;
    store.verify_attribute(&attr.bugzilla_mozilla_org_primary_email)?;
    store.verify_attribute(&attr.mozilla_ldap_id)?;
    store.verify_attribute(&attr.mozilla_ldap_primary_email)?;
    store.verify_attribute(&attr.mozilla_posix_id)?;
    store.verify_attribute(&attr.google_oauth2_id)?;
    store.verify_attribute(&attr.google_primary_email)?;
    store.verify_attribute(&attr.firefox_accounts_id)?;
    store.verify_attribute(&attr.firefox_accounts_primary_email)?;
    store.verify_attribute(&attr.custom_1_primary_email)?;
    store.verify_attribute(&attr.custom_2_primary_email)?;
    store.verify_attribute(&attr.custom_3_primary_email)?;
    Ok(())
}

fn verify_staff_information(
    attr: &StaffInformationValuesArray,
    store: &impl Verifier,
) -> Result<(), KeyError> {
    store.verify_attribute(&attr.manager)?;
    store.verify_attribute(&attr.director)?;
    store.verify_attribute(&attr.staff)?;
    store.verify_attribute(&attr.title)?;
    store.verify_attribute(&attr.team)?;
    store.verify_attribute(&attr.cost_center)?;
    store.verify_attribute(&attr.worker_type)?;
    store.verify_attribute(&attr.wpr_desk_number)?;
    store.verify_attribute(&attr.office_location)?;
    Ok(())
}

pub fn sign_full_profile(profile: &mut Profile, store: &impl Signer) -> Result<(), KeyError> {
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
) -> Result<(), KeyError> {
    store.sign_attribute(&mut attr.access_provider)?;
    store.sign_attribute(&mut attr.hris)?;
    store.sign_attribute(&mut attr.ldap)?;
    store.sign_attribute(&mut attr.mozilliansorg)?;
    Ok(())
}

fn sign_identities(
    attr: &mut IdentitiesAttributesValuesArray,
    store: &impl Signer,
) -> Result<(), KeyError> {
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
    store.sign_attribute(&mut attr.custom_1_primary_email)?;
    store.sign_attribute(&mut attr.custom_2_primary_email)?;
    store.sign_attribute(&mut attr.custom_3_primary_email)?;
    Ok(())
}

fn sign_staff_information(
    attr: &mut StaffInformationValuesArray,
    store: &impl Signer,
) -> Result<(), KeyError> {
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
    use anyhow::Error;

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
    fn test_sign_full_profile() -> Result<(), Error> {
        let store = get_fake_store();
        let mut profile: Profile =
            serde_json::from_str(include_str!("../data/user_profile_null.json"))?;
        sign_full_profile(&mut profile, &store)?;
        Ok(())
    }
}

#[cfg(feature = "aws")]
#[cfg(test)]
mod test_make {
    use super::*;
    use crate::crypto::SecretStore;
    use anyhow::Error;

    use std::env;

    async fn get_store() -> Option<SecretStore> {
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
                    .await
                    .unwrap(),
            )
        } else {
            None
        }
    }

    #[tokio::test]
    async fn test_make_profile() -> Result<(), Error> {
        if let Some(store) = get_store().await {
            let mut profile: Profile =
                serde_json::from_str(include_str!("../data/user_profile_null.json")).unwrap();
            profile.primary_email.value = Some(String::from("hknall@mozilla.com"));
            profile.user_id.value = Some(String::from("ad|Mozilla-LDAP|hknall"));
            profile.primary_username.value = Some(String::from("hknall"));
            profile.uuid.value = Some(String::from("746dad92-3f94-4eed-9e25-7bc20e0041ec"));
            sign_full_profile(&mut profile, &store)?;
            verify_full_profile(&profile, &store)?;
        }
        Ok(())
    }
}
