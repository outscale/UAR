use std::collections::HashMap;

use crate::{error::Error, user_inventory};
use itertools::Itertools;
use outscale_api::apis::api_access_rule_api::read_api_access_rules;
use outscale_api::apis::configuration::Configuration;
use outscale_api::apis::policy_api::{
    read_linked_policies, read_managed_policies_linked_to_user_group, read_policy,
    read_policy_version, read_user_group_policies, read_user_policies, read_user_policy,
};
use outscale_api::models::{
    ReadApiAccessRulesRequest, ReadLinkedPoliciesRequest,
    ReadManagedPoliciesLinkedToUserGroupRequest, ReadPolicyRequest, ReadPolicyVersionRequest,
    ReadUserGroupPoliciesRequest, ReadUserPoliciesRequest, ReadUserPolicyRequest,
};

use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(try_from = "AuthorizationStatementRaw")]
pub struct AuthorizationStatement {
    pub effect: String,
    pub actions_clause: ActionsClause,
}

#[derive(Clone)]
pub enum ActionsClause {
    Actions(Vec<String>),
    NotActions(Vec<String>),
}

#[derive(Clone, Deserialize)]
struct AuthorizationStatementRaw {
    #[serde(rename = "Effect")]
    pub effect: String,
    #[serde(rename = "Action", default)]
    pub actions: Vec<String>,
    #[serde(rename = "NotAction", default)]
    pub not_actions: Vec<String>,
}

impl TryFrom<AuthorizationStatementRaw> for AuthorizationStatement {
    type Error = String;

    fn try_from(value: AuthorizationStatementRaw) -> Result<Self, Self::Error> {
        Ok(AuthorizationStatement {
            effect: value.effect,
            actions_clause: match (value.actions.is_empty(), value.not_actions.is_empty()) {
                (true, true) => {
                    return Err("Neither Action nor NotAction have been defined".to_string())
                }
                (false, false) => {
                    return Err("Both Action and NotAction have been defined".to_string())
                }
                (true, false) => ActionsClause::NotActions(value.not_actions),
                (false, true) => ActionsClause::Actions(value.actions),
            },
        })
    }
}

#[derive(Deserialize)]
pub struct AuthorizationPolicy {
    #[serde(rename = "Statement")]
    pub statements: Vec<AuthorizationStatement>,
}

pub struct FetchedPolicies {
    pub authorized_ip_addresses: Vec<String>,
    pub authorized_cas: Vec<String>,
    pub authorized_cns: Vec<String>,
    pub user_inline_policies: HashMap<String, Vec<IamInlinePolicy>>,
    pub user_group_inline_policies: HashMap<String, Vec<IamInlinePolicy>>,
    pub user_managed_policy_assignments: HashMap<String, Vec<String>>,
    pub user_group_managed_policy_assignments: HashMap<String, Vec<String>>,
    pub managed_policies: HashMap<String, IamManagedPolicy>,
}

pub struct IamInlinePolicy {
    pub name: String,
    pub authorization_policy: AuthorizationPolicy,
}

pub struct IamManagedPolicy {
    pub name: String,
    pub orn: String,
    pub version: String,
    pub authorization_policy: AuthorizationPolicy,
}

pub fn retrieve_policies(
    configuration: &Configuration,
    iam_users: &[user_inventory::IamUser],
    iam_user_groups: &[user_inventory::IamUserGroup],
) -> Result<FetchedPolicies, Error> {
    let authorized_ip_addresses = retrieve_authorized_ip_addresses(configuration)?;
    let authorized_cas = retrieve_authorized_cas(configuration)?;
    let authorized_cns = retrieve_authorized_cns(configuration)?;
    let user_inline_policies = retrieve_user_inline_policies(configuration, iam_users)?;
    let user_group_inline_policies =
        retrieve_user_group_inline_policies(configuration, iam_user_groups)?;
    let user_managed_policy_assignments =
        retrieve_user_managed_policy_assignments(configuration, iam_users)?;
    let user_group_managed_policy_assignments =
        retrieve_user_group_managed_policy_assignments(configuration, iam_user_groups)?;
    //get a vector of unique managed policy orns
    let user_assigned_managed_policy_orns = user_managed_policy_assignments
        .values()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    let user_group_assigned_managed_policy_orns = user_group_managed_policy_assignments
        .values()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    let managed_policy_orns = user_assigned_managed_policy_orns
        .into_iter()
        .chain(user_group_assigned_managed_policy_orns.into_iter())
        .sorted()
        .dedup()
        .collect();
    //
    let managed_policies = retrieve_managed_policies(configuration, managed_policy_orns)?;
    let authorization_policy_inventory = FetchedPolicies {
        authorized_ip_addresses,
        authorized_cas,
        authorized_cns,
        user_inline_policies,
        user_group_inline_policies,
        user_managed_policy_assignments,
        user_group_managed_policy_assignments,
        managed_policies,
    };
    Ok(authorization_policy_inventory)
}

fn retrieve_authorized_ip_addresses(configuration: &Configuration) -> Result<Vec<String>, Error> {
    let mut authorized_ip_addresses: Vec<String> = Vec::new();
    let request = ReadApiAccessRulesRequest::new();
    let response = read_api_access_rules(&configuration, Some(request))
        .map_err(|e| Error::ReadApiAccessRules(e.to_string()))?;
    if let Some(api_access_rules) = response.api_access_rules {
        for api_access_rule in api_access_rules {
            if let Some(ip_ranges) = api_access_rule.ip_ranges {
                for ip_range in ip_ranges {
                    authorized_ip_addresses.push(ip_range);
                }
            }
        }
    }
    Ok(authorized_ip_addresses)
}

fn retrieve_authorized_cas(configuration: &Configuration) -> Result<Vec<String>, Error> {
    let mut authorized_cas: Vec<String> = Vec::new();
    let request = ReadApiAccessRulesRequest::new();
    let response = read_api_access_rules(&configuration, Some(request))
        .map_err(|e| Error::ReadApiAccessRules(e.to_string()))?;
    if let Some(api_access_rules) = response.api_access_rules {
        for api_access_rule in api_access_rules {
            if let Some(ca_ids) = api_access_rule.ca_ids {
                for ca_id in ca_ids {
                    authorized_cas.push(ca_id);
                }
            }
        }
    }
    Ok(authorized_cas)
}

fn retrieve_authorized_cns(configuration: &Configuration) -> Result<Vec<String>, Error> {
    let mut authorized_cns: Vec<String> = Vec::new();
    let request = ReadApiAccessRulesRequest::new();
    let response = read_api_access_rules(&configuration, Some(request))
        .map_err(|e| Error::ReadApiAccessRules(e.to_string()))?;
    if let Some(api_access_rules) = response.api_access_rules {
        for api_access_rule in api_access_rules {
            if let Some(cns) = api_access_rule.cns {
                for cn in cns {
                    authorized_cns.push(cn);
                }
            }
        }
    }
    Ok(authorized_cns)
}

fn retrieve_user_inline_policies(
    configuration: &Configuration,
    iam_users: &[user_inventory::IamUser],
) -> Result<HashMap<String, Vec<IamInlinePolicy>>, Error> {
    let mut user_inline_policies: HashMap<String, Vec<IamInlinePolicy>> = HashMap::new();
    for iam_user in iam_users.iter() {
        let request = ReadUserPoliciesRequest::new(iam_user.name.clone());
        let response = read_user_policies(&configuration, Some(request))
            .map_err(|e| Error::ReadUserPolicies(e.to_string()))?;
        if let Some(iam_inline_policy_names) = response.policy_names {
            let mut iam_inline_policies: Vec<IamInlinePolicy> = Vec::new();
            for iam_inline_policy_name in iam_inline_policy_names.iter() {
                let request = ReadUserPolicyRequest::new(
                    iam_inline_policy_name.clone(),
                    iam_user.name.clone(),
                );
                let response = read_user_policy(&configuration, Some(request))
                    .map_err(|e| Error::ReadUserPolicy(e.to_string()))?;
                let iam_inline_policy = IamInlinePolicy {
                    name: response
                        .policy_name
                        .clone()
                        .ok_or(Error::MissingInlinePolicyName)?,
                    authorization_policy: serde_json::from_str(
                        response
                            .policy_document
                            .as_ref()
                            .ok_or(Error::MissingInlinePolicyBody(
                                response.policy_name.clone().unwrap_or_default(),
                            ))?,
                    )
                    .map_err(Error::InvalidInlinePolicyBody)?,
                };
                iam_inline_policies.push(iam_inline_policy);
            }
            user_inline_policies.insert(iam_user.name.clone(), iam_inline_policies);
        }
    }
    Ok(user_inline_policies)
}

fn retrieve_user_group_inline_policies(
    configuration: &Configuration,
    iam_user_groups: &[user_inventory::IamUserGroup],
) -> Result<HashMap<String, Vec<IamInlinePolicy>>, Error> {
    let mut user_group_inline_policies: HashMap<String, Vec<IamInlinePolicy>> = HashMap::new();
    for iam_user_group in iam_user_groups.iter() {
        let request = ReadUserGroupPoliciesRequest::new(iam_user_group.name.clone());
        let response = read_user_group_policies(&configuration, Some(request))
            .map_err(|e| Error::ReadUserGroupPolicies(e.to_string()))?;
        let iam_inline_policies: Vec<IamInlinePolicy> = response
            .policies
            .into_iter()
            .flatten()
            .map(|policy| {
                Ok(IamInlinePolicy {
                    name: policy.name.clone().ok_or(Error::MissingInlinePolicyName)?,
                    authorization_policy: serde_json::from_str(policy.body.as_ref().ok_or(
                        Error::MissingInlinePolicyBody(policy.name.clone().unwrap_or_default()),
                    )?)
                    .map_err(Error::InvalidInlinePolicyBody)?,
                })
            })
            .collect::<Result<_, Error>>()?;
        user_group_inline_policies.insert(iam_user_group.name.clone(), iam_inline_policies);
    }
    Ok(user_group_inline_policies)
}

fn retrieve_user_managed_policy_assignments(
    configuration: &Configuration,
    iam_users: &[user_inventory::IamUser],
) -> Result<HashMap<String, Vec<String>>, Error> {
    let mut user_managed_policy_assignments: HashMap<String, Vec<String>> = HashMap::new();
    for iam_user in iam_users.iter() {
        let request = ReadLinkedPoliciesRequest::new(iam_user.name.clone());
        let response = read_linked_policies(&configuration, Some(request))
            .map_err(|e| Error::ReadLinkedPolicies(e.to_string()))?;
        let iam_managed_policies_orns: Vec<String> = response
            .policies
            .into_iter()
            .flatten()
            .map(|policy| {
                Ok(policy
                    .orn
                    .as_ref()
                    .ok_or(Error::MissingManagedPolicyOrn)?
                    .clone())
            })
            .collect::<Result<_, Error>>()?;
        user_managed_policy_assignments.insert(iam_user.name.clone(), iam_managed_policies_orns);
    }
    Ok(user_managed_policy_assignments)
}

fn retrieve_user_group_managed_policy_assignments(
    configuration: &Configuration,
    iam_user_groups: &[user_inventory::IamUserGroup],
) -> Result<HashMap<String, Vec<String>>, Error> {
    let mut user_group_managed_policy_assignments: HashMap<String, Vec<String>> = HashMap::new();
    for iam_user_group in iam_user_groups.iter() {
        let request = ReadManagedPoliciesLinkedToUserGroupRequest::new(iam_user_group.name.clone());
        let response = read_managed_policies_linked_to_user_group(&configuration, Some(request))
            .map_err(|e| Error::ReadManagedPoliciesLinkedToUserGroup(e.to_string()))?;
        let iam_managed_policies_orns: Vec<String> = response
            .policies
            .into_iter()
            .flatten()
            .map(|policy| {
                Ok(policy
                    .orn
                    .as_ref()
                    .ok_or(Error::MissingManagedPolicyOrn)?
                    .clone())
            })
            .collect::<Result<_, Error>>()?;
        user_group_managed_policy_assignments
            .insert(iam_user_group.name.clone(), iam_managed_policies_orns);
    }
    Ok(user_group_managed_policy_assignments)
}

fn retrieve_managed_policies(
    configuration: &Configuration,
    managed_policy_orns: Vec<String>,
) -> Result<HashMap<String, IamManagedPolicy>, Error> {
    let mut iam_managed_policies: HashMap<String, IamManagedPolicy> = HashMap::new();
    for managed_policy_orn in managed_policy_orns.iter() {
        let request = ReadPolicyRequest::new(managed_policy_orn.clone());
        let response = read_policy(&configuration, Some(request))
            .map_err(|e| Error::ReadPolicy(e.to_string()))?;
        let managed_policy_name = response
            .clone()
            .policy
            .ok_or(Error::MissingManagedPolicy)?
            .policy_name
            .as_ref()
            .ok_or(Error::MissingManagedPolicyName)?
            .clone();
        let managed_policy_version = response
            .policy
            .ok_or(Error::MissingManagedPolicy)?
            .policy_default_version_id
            .as_ref()
            .ok_or(Error::MissingManagedPolicyDefaultVersionId)?
            .clone();
        let request = ReadPolicyVersionRequest::new(
            managed_policy_orn.clone(),
            managed_policy_version.clone(),
        );
        let response = read_policy_version(&configuration, Some(request))
            .map_err(|e| Error::ReadPolicyVersion(e.to_string()))?;

        let iam_authorization_policy: AuthorizationPolicy = serde_json::from_str(
            &response
                .policy_version
                .ok_or(Error::MissingManagedPolicyVersion)?
                .body
                .ok_or(Error::MissingManagedPolicyBody(
                    managed_policy_orn.clone(),
                    managed_policy_version.clone(),
                ))?,
        )
        .map_err(Error::InvalidManagedPolicyBody)?;

        let iam_managed_policy = IamManagedPolicy {
            name: managed_policy_name.clone(),
            orn: managed_policy_orn.clone(),
            version: managed_policy_version,
            authorization_policy: iam_authorization_policy,
        };
        iam_managed_policies.insert(managed_policy_orn.clone(), iam_managed_policy);
    }
    Ok(iam_managed_policies)
}
