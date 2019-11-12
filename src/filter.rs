use crate::schema::*;

macro_rules! impl_with_display {
    ($t:ident) => {
        impl WithDisplay for $t {
            fn display(self: &Self) -> &Option<Display> {
                &self.metadata.display
            }
        }
    };
}

pub trait WithDisplay {
    fn display(self: &Self) -> &Option<Display>;
}

pub trait Filtered {
    fn filtered(self: &Self, default: Self, display: &Display) -> Self;
}

impl_with_display!(StandardAttributeString);
impl_with_display!(StandardAttributeBoolean);
impl_with_display!(StandardAttributeValues);
impl_with_display!(AccessInformationProviderSubObject);

impl<T: WithDisplay + Default + Clone> Filtered for T {
    fn filtered(self: &Self, default: Self, display: &Display) -> Self {
        match self.display() {
            None => default,
            Some(ref d) if d > display => default,
            _ => self.clone(),
        }
    }
}

impl Filtered for AccessInformationValuesArray {
    fn filtered(self: &Self, default: Self, display: &Display) -> Self {
        AccessInformationValuesArray {
            access_provider: self
                .access_provider
                .filtered(default.access_provider, display),
            hris: self.hris.filtered(default.hris, display),
            ldap: self.ldap.filtered(default.ldap, display),
            mozilliansorg: self.mozilliansorg.filtered(default.mozilliansorg, display),
        }
    }
}

impl Filtered for StaffInformationValuesArray {
    fn filtered(self: &Self, default: Self, display: &Display) -> Self {
        StaffInformationValuesArray {
            manager: self.manager.filtered(default.manager, display),
            director: self.director.filtered(default.director, display),
            staff: self.staff.filtered(default.staff, display),
            title: self.title.filtered(default.title, display),
            team: self.team.filtered(default.team, display),
            cost_center: self.cost_center.filtered(default.cost_center, display),
            worker_type: self.cost_center.filtered(default.worker_type, display),
            wpr_desk_number: self
                .wpr_desk_number
                .filtered(default.wpr_desk_number, display),
            office_location: self
                .office_location
                .filtered(default.office_location, display),
        }
    }
}

impl Filtered for IdentitiesAttributesValuesArray {
    fn filtered(self: &Self, default: Self, display: &Display) -> Self {
        IdentitiesAttributesValuesArray {
            github_id_v3: self.github_id_v3.filtered(default.github_id_v3, display),
            github_id_v4: self.github_id_v4.filtered(default.github_id_v4, display),
            github_primary_email: self
                .github_primary_email
                .filtered(default.github_primary_email, display),
            mozilliansorg_id: self
                .mozilliansorg_id
                .filtered(default.mozilliansorg_id, display),
            bugzilla_mozilla_org_id: self
                .bugzilla_mozilla_org_id
                .filtered(default.bugzilla_mozilla_org_id, display),
            bugzilla_mozilla_org_primary_email: self
                .bugzilla_mozilla_org_primary_email
                .filtered(default.bugzilla_mozilla_org_primary_email, display),
            mozilla_ldap_id: self
                .mozilla_ldap_id
                .filtered(default.mozilla_ldap_id, display),
            mozilla_ldap_primary_email: self
                .mozilla_ldap_primary_email
                .filtered(default.mozilla_ldap_primary_email, display),
            mozilla_posix_id: self
                .mozilla_posix_id
                .filtered(default.mozilla_posix_id, display),
            google_oauth2_id: self
                .google_oauth2_id
                .filtered(default.google_oauth2_id, display),
            google_primary_email: self
                .google_primary_email
                .filtered(default.google_primary_email, display),
            firefox_accounts_id: self
                .firefox_accounts_id
                .filtered(default.firefox_accounts_id, display),
            firefox_accounts_primary_email: self
                .firefox_accounts_primary_email
                .filtered(default.firefox_accounts_primary_email, display),
            custom_1_primary_email: self
                .custom_1_primary_email
                .filtered(default.custom_1_primary_email, display),
            custom_2_primary_email: self
                .custom_2_primary_email
                .filtered(default.custom_2_primary_email, display),
            custom_3_primary_email: self
                .custom_3_primary_email
                .filtered(default.custom_3_primary_email, display),
        }
    }
}

impl Filtered for Profile {
    fn filtered(self: &Self, default: Self, display: &Display) -> Self {
        Profile {
            access_information: self
                .access_information
                .filtered(default.access_information, display),
            active: self.active.filtered(default.active, display),
            alternative_name: self
                .alternative_name
                .filtered(default.alternative_name, display),
            created: self.created.filtered(default.created, display),
            description: self.description.filtered(default.description, display),
            first_name: self.first_name.filtered(default.first_name, display),
            fun_title: self.fun_title.filtered(default.fun_title, display),
            identities: self.identities.filtered(default.identities, display),
            languages: self.languages.filtered(default.languages, display),
            last_modified: self.last_modified.filtered(default.last_modified, display),
            last_name: self.last_name.filtered(default.last_name, display),
            location: self.location.filtered(default.location, display),
            login_method: self.login_method.filtered(default.login_method, display),
            pgp_public_keys: self
                .pgp_public_keys
                .filtered(default.pgp_public_keys, display),
            phone_numbers: self.phone_numbers.filtered(default.phone_numbers, display),
            picture: self.picture.filtered(default.picture, display),
            primary_email: self.primary_email.filtered(default.primary_email, display),
            primary_username: self
                .primary_username
                .filtered(default.primary_username, display),
            pronouns: self.pronouns.filtered(default.pronouns, display),
            schema: self.schema.clone(),
            ssh_public_keys: self
                .ssh_public_keys
                .filtered(default.ssh_public_keys, display),
            staff_information: self
                .staff_information
                .filtered(default.staff_information, display),
            tags: self.tags.filtered(default.tags, display),
            timezone: self.timezone.filtered(default.timezone, display),
            uris: self.uris.filtered(default.uris, display),
            user_id: self.user_id.filtered(default.user_id, display),
            usernames: self.usernames.filtered(default.usernames, display),
            uuid: self.uuid.filtered(default.uuid, display),
        }
    }
}

impl Profile {
    pub fn filtered_default(self: &Self, display: &Display) -> Self {
        self.filtered(Profile::default(), display)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic_filter() {
        let mut p = Profile::default();
        p.first_name.metadata.display = Some(Display::Private);
        p.first_name.value = Some(String::from("Hans"));

        let private = p.filtered_default(&Display::Private);
        assert_eq!(p, private);
        assert_eq!(private.first_name.value, Some(String::from("Hans")));

        let staff = p.filtered_default(&Display::Staff);
        assert_eq!(staff, Profile::default());
        assert_eq!(staff.first_name.value, None);

        let public = p.filtered_default(&Display::Public);
        assert_eq!(public, Profile::default());
        assert_eq!(public.first_name.value, None);
    }
}
