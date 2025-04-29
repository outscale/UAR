use std::collections::HashMap;

use crate::error::Error;
use outscale_api::apis::configuration::Configuration;

use outscale_api::apis::account_api::read_accounts;
use outscale_api::apis::user_api::read_users;
use outscale_api::apis::user_group_api::read_user_groups_per_user;
use outscale_api::models::{ReadAccountsRequest, ReadUserGroupsPerUserRequest, ReadUsersRequest};

#[derive(Clone, serde::Serialize)]
pub struct RootAccount {
    pub id: String,
    pub name: String,
    pub e_mail: String,
}

#[derive(Clone, serde::Serialize)]
pub struct IamUser {
    pub name: String,
    pub e_mail: String,
}

#[derive(Clone, serde::Serialize)]
pub struct IamUserGroup {
    pub name: String,
}

pub fn get_root_account(configuration: &Configuration) -> Result<RootAccount, Error> {
    let request = ReadAccountsRequest::new();
    let response = read_accounts(&configuration, Some(request))
        .map_err(|e| Error::ReadAccounts(e.to_string()))?;
    let root_accounts: Vec<RootAccount> = response
        .accounts
        .into_iter()
        .flatten()
        .map(|account| {
            Ok(RootAccount {
                id: account
                    .account_id
                    .clone()
                    .ok_or(Error::MissingRootAccountId(
                        account.account_id.unwrap_or_default(),
                    ))?,
                name: format!(
                    "{} {}",
                    account
                        .first_name
                        .clone()
                        .ok_or(Error::MissingRootAccountName(
                            account.first_name.unwrap_or_default()
                        ))?,
                    account
                        .last_name
                        .clone()
                        .ok_or(Error::MissingRootAccountName(
                            account.last_name.unwrap_or_default()
                        ))?
                ),
                e_mail: account.email.clone().ok_or(Error::MissingRootAccountEmail(
                    account.email.unwrap_or_default(),
                ))?,
            })
        })
        .collect::<Result<_, Error>>()?;
    let root_account = root_accounts
        .first()
        .cloned()
        .ok_or(Error::MissingRootAccount("Empty Vec".to_string()))?;
    Ok(root_account)
}

pub fn list_iam_users(configuration: &Configuration) -> Result<Vec<IamUser>, Error> {
    let request = ReadUsersRequest::new();
    let response =
        read_users(&configuration, Some(request)).map_err(|e| Error::ReadUsers(e.to_string()))?;
    response
        .users
        .into_iter()
        .flatten()
        .map(|user| {
            Ok(IamUser {
                name: user
                    .user_name
                    .ok_or(Error::MissingUserName(user.user_id.unwrap_or_default()))?,
                e_mail: user.user_email.ok_or(Error::MissingUserEmail())?,
            })
        })
        .collect()
}

pub fn list_iam_user_group_assignments(
    configuration: &Configuration,
    iam_users: &[IamUser],
) -> Result<HashMap<String, Vec<IamUserGroup>>, Error> {
    let mut iam_user_group_assignments: HashMap<String, Vec<IamUserGroup>> = HashMap::new();
    for iam_user in iam_users.iter() {
        let request = ReadUserGroupsPerUserRequest::new(iam_user.name.clone());
        let response = read_user_groups_per_user(&configuration, Some(request))
            .map_err(|e| Error::ReadUserGroupsPerUser(e.to_string()))?;
        let iam_user_groups: Vec<IamUserGroup> = response
            .user_groups
            .into_iter()
            .flatten()
            .map(|user_group| {
                Ok(IamUserGroup {
                    name: user_group.name.clone().ok_or(Error::MissingUserGroupName(
                        user_group.name.unwrap_or_default(),
                    ))?,
                })
            })
            .collect::<Result<_, Error>>()?;
        iam_user_group_assignments.insert(iam_user.name.clone(), iam_user_groups);
    }
    Ok(iam_user_group_assignments)
}
