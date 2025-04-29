use csv::{self};
use itertools::Itertools;
use regex::Regex;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::{collections::HashMap, path::PathBuf};

use crate::{
    apis_ref,
    authorization_policy_inventory::{
        self, AuthorizationStatement, IamInlinePolicy, IamManagedPolicy,
    },
    cli::Options,
    error::Error,
    user_inventory::{self, IamUserGroup, RootAccount},
};

#[derive(serde::Serialize)]
pub struct GlobalReport {
    root_account: RootAccount,
    iam_user_reports: Vec<IamUserReport>,
    iam_user_group_reports: HashMap<String, IamUserGroupReport>,
    authorized_ip_addresses: Vec<String>,
    authorized_cas: Vec<String>,
    authorized_cns: Vec<String>,
    user_inline_policy_reports: HashMap<String, Vec<InlinePolicyReport>>,
    user_group_inline_policy_reports: HashMap<String, Vec<InlinePolicyReport>>,
    managed_policy_reports: HashMap<String, ManagedPolicyReport>,
    resources: HashMap<String, Vec<String>>,
    resource_tags: HashMap<String, Vec<(String, String)>>,
}

#[derive(Clone, serde::Serialize)]
pub struct IamUserReport {
    user: user_inventory::IamUser,
    user_groups: Vec<IamUserGroupReport>,
    inline_policies: Vec<InlinePolicyReport>,
    managed_policies: Vec<ManagedPolicyReport>,
}

#[derive(Clone, serde::Serialize)]
pub struct IamUserGroupReport {
    group: user_inventory::IamUserGroup,
    inline_policies: Vec<InlinePolicyReport>,
    managed_policies: Vec<ManagedPolicyReport>,
}

#[derive(Clone, serde::Serialize)]
pub struct OperationReport {
    operation: String,
    resources: HashMap<String, Vec<String>>,
}

#[derive(Clone, serde::Serialize)]
pub struct ActionReport {
    action: String,
    operations: Vec<OperationReport>,
}

#[derive(Clone, serde::Serialize)]
pub struct StatementReport {
    effect: String,
    actions: Vec<ActionReport>,
}

#[derive(Clone, serde::Serialize)]
pub struct PolicyReport {
    statements: Vec<StatementReport>,
}

#[derive(Clone, serde::Serialize)]
pub struct InlinePolicyReport {
    name: String,
    policy_report: PolicyReport,
}

#[derive(Clone, serde::Serialize)]
pub struct ManagedPolicyReport {
    name: String,
    orn: String,
    version: String,
    policy_report: PolicyReport,
}

pub fn compute_report(
    root_account: &user_inventory::RootAccount,
    iam_users: &[user_inventory::IamUser],
    iam_user_group_assignments: &HashMap<String, Vec<user_inventory::IamUserGroup>>,
    policies: &authorization_policy_inventory::FetchedPolicies,
    resources: &HashMap<String, Vec<String>>,
    resource_tags: &HashMap<String, Vec<(String, String)>>,
) -> Result<GlobalReport, Error> {
    let user_inline_policy_reports = policies
        .user_inline_policies
        .iter()
        .map(|(user_name, inline_policies)| {
            Ok((
                user_name.clone(),
                inline_policies
                    .iter()
                    .map(|inline_policy| compute_inline_policy_report(inline_policy, resources))
                    .collect::<Result<_, Error>>()?,
            ))
        })
        .collect::<Result<_, Error>>()?;
    let user_group_inline_policy_reports = policies
        .user_group_inline_policies
        .iter()
        .map(|(user_group_name, inline_policies)| {
            Ok((
                user_group_name.clone(),
                inline_policies
                    .iter()
                    .map(|inline_policy| compute_inline_policy_report(inline_policy, resources))
                    .collect::<Result<_, Error>>()?,
            ))
        })
        .collect::<Result<_, Error>>()?;
    let managed_policy_reports = policies
        .managed_policies
        .iter()
        .map(|(managed_policy_orn, managed_policy)| {
            Ok((
                managed_policy_orn.clone(),
                compute_managed_policy_report(managed_policy, resources)?,
            ))
        })
        .collect::<Result<_, Error>>()?;
    let iam_user_groups: Vec<IamUserGroup> = iam_user_group_assignments
        .iter()
        .flat_map(|(_, iam_user_groups)| iam_user_groups)
        .unique_by(|iam_user_group| iam_user_group.name.clone())
        .cloned()
        .collect();
    let iam_user_group_reports = iam_user_groups
        .iter()
        .map(|iam_user_group| {
            Ok((
                iam_user_group.name.clone(),
                compute_iam_user_group_report(iam_user_group, policies, resources)?,
            ))
        })
        .collect::<Result<_, Error>>()?;
    let authorized_ip_addresses = policies.authorized_ip_addresses.clone();
    let authorized_cas = policies.authorized_cas.clone();
    let authorized_cns = policies.authorized_cns.clone();
    Ok(GlobalReport {
        root_account: root_account.clone(),
        iam_user_reports: iam_users
            .into_iter()
            .map(|iam_user| {
                compute_iam_user_report(
                    iam_user,
                    iam_user_group_assignments,
                    policies,
                    &iam_user_group_reports,
                    resources,
                )
            })
            .collect::<Result<_, Error>>()?,
        iam_user_group_reports,
        authorized_ip_addresses,
        authorized_cas,
        authorized_cns,
        user_inline_policy_reports,
        user_group_inline_policy_reports,
        managed_policy_reports,
        resources: resources.clone(),
        resource_tags: resource_tags.clone(),
    })
}

fn compute_iam_user_group_report(
    iam_user_group: &user_inventory::IamUserGroup,
    policies: &authorization_policy_inventory::FetchedPolicies,
    resources: &HashMap<String, Vec<String>>,
) -> Result<IamUserGroupReport, Error> {
    let inline_policies: Vec<InlinePolicyReport> = policies
        .user_group_inline_policies
        .get(&iam_user_group.name)
        .into_iter()
        .flatten()
        .map(|iam_inline_policy| compute_inline_policy_report(iam_inline_policy, resources))
        .collect::<Result<_, Error>>()?;
    let managed_policies: Vec<ManagedPolicyReport> = policies
        .user_group_managed_policy_assignments
        .get(&iam_user_group.name)
        .into_iter()
        .flatten()
        .map(|managed_policy_orn| {
            compute_managed_policy_report(
                policies.managed_policies.get(managed_policy_orn).ok_or(
                    Error::MissingManagedPolicyRecord(managed_policy_orn.to_string()),
                )?,
                resources,
            )
        })
        .collect::<Result<_, Error>>()?;
    Ok(IamUserGroupReport {
        group: iam_user_group.clone(),
        inline_policies,
        managed_policies,
    })
}

fn compute_iam_user_report(
    iam_user: &user_inventory::IamUser,
    iam_user_group_assignments: &HashMap<String, Vec<user_inventory::IamUserGroup>>,
    policies: &authorization_policy_inventory::FetchedPolicies,
    iam_user_group_reports: &HashMap<String, IamUserGroupReport>,
    resources: &HashMap<String, Vec<String>>,
) -> Result<IamUserReport, Error> {
    let assigned_user_groups: Vec<String> = iam_user_group_assignments
        .get(&iam_user.name)
        .into_iter()
        .flatten()
        .map(|iam_user_group| iam_user_group.name.clone())
        .collect();
    let user_groups: Vec<IamUserGroupReport> = assigned_user_groups
        .into_iter()
        .map(|iam_user_group_name| {
            Ok(iam_user_group_reports
                .get(&iam_user_group_name)
                .ok_or(Error::MissingUserGroupReport(iam_user_group_name))?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    let inline_policies: Vec<InlinePolicyReport> = policies
        .user_inline_policies
        .get(&iam_user.name)
        .into_iter()
        .flatten()
        .map(|iam_inline_policy| compute_inline_policy_report(iam_inline_policy, resources))
        .collect::<Result<_, Error>>()?;
    let managed_policies: Vec<ManagedPolicyReport> = policies
        .user_managed_policy_assignments
        .get(&iam_user.name)
        .into_iter()
        .flatten()
        .map(|managed_policy_orn| {
            compute_managed_policy_report(
                policies.managed_policies.get(managed_policy_orn).ok_or(
                    Error::MissingManagedPolicyRecord(managed_policy_orn.to_string()),
                )?,
                resources,
            )
        })
        .collect::<Result<_, Error>>()?;
    Ok(IamUserReport {
        user: iam_user.clone(),
        user_groups,
        inline_policies,
        managed_policies,
    })
}

fn compute_inline_policy_report(
    inline_policy: &IamInlinePolicy,
    resources: &HashMap<String, Vec<String>>,
) -> Result<InlinePolicyReport, Error> {
    Ok(InlinePolicyReport {
        name: inline_policy.name.clone(),
        policy_report: compute_policy_report(&inline_policy.authorization_policy, resources)?,
    })
}

fn compute_managed_policy_report(
    managed_policy: &IamManagedPolicy,
    resources: &HashMap<String, Vec<String>>,
) -> Result<ManagedPolicyReport, Error> {
    Ok(ManagedPolicyReport {
        name: managed_policy.name.clone(),
        orn: managed_policy.orn.clone(),
        version: managed_policy.version.clone(),
        policy_report: compute_policy_report(&managed_policy.authorization_policy, resources)?,
    })
}

fn compute_policy_report(
    authorization_policy: &authorization_policy_inventory::AuthorizationPolicy,
    resources: &HashMap<String, Vec<String>>,
) -> Result<PolicyReport, Error> {
    Ok(PolicyReport {
        statements: authorization_policy
            .statements
            .iter()
            .map(|statement| compute_statement_report(statement, resources))
            .collect::<Result<_, Error>>()?,
    })
}

fn compute_statement_report(
    statement: &AuthorizationStatement,
    resources: &HashMap<String, Vec<String>>,
) -> Result<StatementReport, Error> {
    let actions = match &statement.actions_clause {
        authorization_policy_inventory::ActionsClause::Actions(items) => items,
        authorization_policy_inventory::ActionsClause::NotActions(items) => {
            &actions_not_matching(items)?
        }
    };
    Ok(StatementReport {
        effect: statement.effect.clone(),
        actions: actions
            .iter()
            .map(|action| compute_action_report(action, resources))
            .collect::<Result<_, Error>>()?,
    })
}

fn actions_not_matching(not_actions: &[String]) -> Result<Vec<String>, Error> {
    let res = not_actions
        .iter()
        .map(|action| {
            Ok(Regex::new(
                &format!(
                    "^{}$",
                    action
                        .to_string()
                        .replace("?", ".")
                        .replace("*", "[a-zA-Z0-9]*")
                )
                .to_string(),
            )
            .map_err(|e| Error::InvalidRegularExpression(e.to_string()))?)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(apis_ref::API_CALLS
        .keys()
        .filter(|api_call| !res.iter().any(|re| re.is_match(api_call)))
        .map(|api_call| api_call.to_string())
        .collect())
}

fn compute_action_report(
    action: &String,
    resources: &HashMap<String, Vec<String>>,
) -> Result<ActionReport, Error> {
    let matching_api_calls = collect_matching_api_calls(action)?;
    Ok(ActionReport {
        action: action.clone(),
        operations: matching_api_calls
            .iter()
            .map(|matching_api_call| compute_operation_report(matching_api_call, resources))
            .collect(),
    })
}

fn collect_matching_api_calls(action: &String) -> Result<Vec<String>, Error> {
    let re = Regex::new(
        &format!(
            "^{}$",
            &action
                .to_string()
                .replace("?", ".")
                .replace("*", "[a-zA-Z0-9]*")
        )
        .to_string(),
    )
    .map_err(|e| Error::InvalidRegularExpression(e.to_string()))?;
    Ok(apis_ref::API_CALLS
        .keys()
        .filter(|api_call| re.is_match(api_call))
        .map(|api_call| api_call.to_string())
        .collect())
}

fn compute_operation_report(
    operation: &String,
    resources: &HashMap<String, Vec<String>>,
) -> OperationReport {
    let related_resources = apis_ref::API_CALLS
        .get(operation)
        .iter()
        .flat_map(|resource_types| resource_types.to_vec())
        .map(|resource_type| {
            (
                resource_type.to_string(),
                resources.get(resource_type).unwrap_or(&Vec::new()).clone(),
            )
        })
        .collect();
    OperationReport {
        operation: operation.clone(),
        resources: related_resources,
    }
}

#[derive(Debug, Serialize)]
pub struct CSVReportLine {
    user: String,
    user_email: String,
    user_type: String,
    authorized_ip_addresses: String,
    authorized_cas: String,
    authorized_cns: String,
    inherited_from_user_group: bool,
    user_group: Option<String>,
    policy_type: String,
    policy_name: String,
    policy_orn: Option<String>,
    policy_version: Option<String>,
    effect: String,
    actions_pattern: String,
    matching_operation: String,
    resource_type: String,
    resources: String,
}

pub fn output_global_report(options: &Options, global_report: &GlobalReport) -> Result<(), Error> {
    let mut csv_path = PathBuf::from(&options.report_path);
    csv_path.set_extension("csv");
    let mut csv_writer = csv::Writer::from_path(&csv_path)?;
    match options.osc_user_id {
        //optional osc_user_id has been specified
        Some(ref osc_user_id) => {
            println!("USER ACCESS REVIEW for user {}", osc_user_id);
        }
        //all other cases (i.e. optional osc_user_id wasn't specified)
        _ => {
            println!("USER ACCESS REVIEW for all users");
        }
    }
    match options.osc_resource_id {
        //optional osc_resource_id has been specified
        Some(ref osc_resource_id) => {
            println!(
                "(to resource '{}' in Outscale account_id '{}')",
                osc_resource_id, global_report.root_account.id
            );
            println!("---------------------------------------------------------------");
        }
        //all other cases (i.e. optional osc_resource_id wasn't specified)
        _ => {
            println!(
                "(to all resources in Outscale account_id '{}')",
                global_report.root_account.id
            );
            println!("---------------------------------------------------------------");
        }
    }

    //API access rules
    println!("API access rules:");
    println!(
        "    > API calls may be issued from IP addresses in: {}",
        global_report.authorized_ip_addresses.join(",")
    );
    if !global_report.authorized_cas.is_empty() {
        println!(
            "    > clients issuing API calls need a TLS certificate issued by a CA in: {}",
            global_report.authorized_cas.join(",")
        );
    }
    if !global_report.authorized_cns.is_empty() {
        println!(
            "    > clients issuing API calls need a TLS certificate with a CN in: {}",
            global_report.authorized_cns.join(",")
        );
    }

    //Root account
    match options.osc_user_id {
        //optional osc_user_id has been specified and it doesn't match with this root account ID -> elude this root account's access rights
        Some(ref osc_user_id) if *osc_user_id != global_report.root_account.name => {}
        //all other cases (i.e. optional osc_user_id wasn't specified OR it matches with this EIM user ID) -> report this EIM user's access rights
        _ => {
            let records: Vec<CSVReportLine> = output_root_account_report(
                options,
                &global_report.root_account,
                global_report.authorized_ip_addresses.clone(),
                global_report.authorized_cas.clone(),
                global_report.authorized_cns.clone(),
                &global_report.resources,
            )?;
            for record in records.iter() {
                csv_writer.serialize(record)?;
            }
        }
    }

    //EIM users
    for iam_user_report in global_report.iam_user_reports.iter() {
        match options.osc_user_id {
            //optional osc_user_id has been specified and it doesn't match with this EIM user ID -> elude this EIM user's access rights
            Some(ref osc_user_id) if *osc_user_id != iam_user_report.user.name => {}
            //all other cases (i.e. optional osc_user_id wasn't specified OR it matches with this EIM user ID) -> report this EIM user's access rights
            _ => {
                let records: Vec<CSVReportLine> = output_iam_user_report(
                    options,
                    iam_user_report,
                    global_report.authorized_ip_addresses.clone(),
                    global_report.authorized_cas.clone(),
                    global_report.authorized_cns.clone(),
                )?;
                for record in records.iter() {
                    csv_writer.serialize(record)?;
                }
            }
        }
    }
    csv_writer.flush()?;

    //cypher report
    let _ = output_cypher_report(options, &global_report)?;

    //json report
    let _ = output_json_report(options, &global_report)?;

    Ok(())
}

pub fn output_root_account_report(
    options: &Options,
    root_account: &RootAccount,
    authorized_ip_addresses: Vec<String>,
    authorized_cas: Vec<String>,
    authorized_cns: Vec<String>,
    resources: &HashMap<String, Vec<String>>,
) -> Result<Vec<CSVReportLine>, Error> {
    let mut record: Vec<CSVReportLine> = Vec::new();
    println!("---------------------------------------------------------------");
    println!("Root account '{}' ({})", root_account.id, root_account.name);

    //built-in policies
    println!("    BUILT-IN POLICIES");
    for api_ref_entry in apis_ref::API_CALLS.into_iter() {
        let api_call = api_ref_entry.0.to_string();
        let resource_types: Vec<String> = api_ref_entry
            .1
            .to_vec()
            .into_iter()
            .map(|resource_type| resource_type.to_string())
            .collect();
        for resource_type in resource_types.iter() {
            let inventoried_resources = resources
                .get(resource_type)
                .ok_or(Error::UnavailableResourceType(resource_type.clone()))?
                .clone();
            match options.osc_resource_id {
                //optional osc_resource_id has been specified and it doesn't match with no resource of this resource type -> elude this resource type
                Some(ref osc_resource_id) if !inventoried_resources.contains(&osc_resource_id) => {}
                //all other cases (i.e. optional osc_resource_id wasn't specified OR it matches with a resource of this resource type) -> report this resource type
                _ => {
                    let mut resource_instances: Vec<String> = Vec::new();
                    match options.osc_resource_id {
                        //optional osc_resource_id has been specified and it matches with a resource of this resource type
                        Some(ref osc_resource_id)
                            if inventoried_resources.contains(&osc_resource_id) =>
                        {
                            resource_instances = vec![osc_resource_id.clone()];
                        }
                        //all other cases (i.e. optional osc_resource_id wasn't specified
                        _ => {
                            resource_instances = inventoried_resources.clone();
                        }
                    }
                    //report to CLI
                    let cli_display_resources =
                        cli_output_resources(options, resource_instances.clone());
                    println!("        'Allow' ACTION PATTERN '*:*' MATCHING WITH API CALL '{}' -> RESOURCE_TYPE '{}' (RESOURCE(S): '{}')", api_call, resource_type, cli_display_resources);
                    //report to CSV
                    let new_line = CSVReportLine {
                        user: format!("{} ({})", root_account.id, root_account.name),
                        user_email: root_account.e_mail.clone(),
                        user_type: "ROOT ACCOUNT".to_string(),
                        authorized_ip_addresses: authorized_ip_addresses.join(","),
                        authorized_cas: authorized_cas.join(","),
                        authorized_cns: authorized_cns.join(","),
                        inherited_from_user_group: false,
                        user_group: Some("n/a".to_string()),
                        policy_type: "BUILT-IN POLICY".to_string(),
                        policy_name: "n/a".to_string(),
                        policy_orn: Some("n/a".to_string()),
                        policy_version: Some("n/a".to_string()),
                        effect: "Allow".to_string(),
                        actions_pattern: "*:*".to_string(),
                        matching_operation: api_call.clone(),
                        resource_type: resource_type.clone(),
                        resources: resource_instances.clone().join(","),
                    };
                    record.push(new_line);
                }
            }
        }
    }

    Ok(record)
}

pub fn output_iam_user_report(
    options: &Options,
    iam_user_report: &IamUserReport,
    authorized_ip_addresses: Vec<String>,
    authorized_cas: Vec<String>,
    authorized_cns: Vec<String>,
) -> Result<Vec<CSVReportLine>, Error> {
    let mut record: Vec<CSVReportLine> = Vec::new();
    println!("---------------------------------------------------------------");
    println!("EIM user '{}'", iam_user_report.user.name);

    //user-assigned inline policies
    println!(
        "    USER INLINE POLICIES ({} assigned to this EIM user)",
        iam_user_report.inline_policies.len()
    );
    for inline_policy in iam_user_report.inline_policies.iter() {
        println!("      POLICY '{}'", inline_policy.name);
        for statement in inline_policy.policy_report.statements.iter() {
            for action in statement.actions.iter() {
                for operation in action.operations.iter() {
                    for resource in operation.resources.iter() {
                        match options.osc_resource_id {
                            //optional osc_resource_id has been specified and it doesn't match with no resource of this resource type -> elude this resource type
                            Some(ref osc_resource_id) if !resource.1.contains(&osc_resource_id) => {
                            }
                            //all other cases (i.e. optional osc_resource_id wasn't specified OR it matches with a resource of this resource type) -> report this resource type
                            _ => {
                                let mut resource_instances: Vec<String> = Vec::new();
                                match options.osc_resource_id {
                                    //optional osc_resource_id has been specified and it matches with a resource of this resource type
                                    Some(ref osc_resource_id)
                                        if resource.1.contains(&osc_resource_id) =>
                                    {
                                        resource_instances = vec![osc_resource_id.clone()];
                                    }
                                    //all other cases (i.e. optional osc_resource_id wasn't specified
                                    _ => {
                                        resource_instances = resource.1.clone();
                                    }
                                }
                                //report to CLI
                                let cli_display_resources =
                                    cli_output_resources(options, resource_instances.clone());
                                println!("        '{}' ACTION PATTERN '{}' MATCHING WITH API CALL '{}' -> RESOURCE_TYPE '{}' (RESOURCE(S): '{}')", statement.effect, action.action, operation.operation, resource.0, cli_display_resources);
                                //report to CSV
                                let new_line = CSVReportLine {
                                    user: iam_user_report.user.name.clone(),
                                    user_email: iam_user_report.user.e_mail.clone(),
                                    user_type: "EIM USER".to_string(),
                                    authorized_ip_addresses: authorized_ip_addresses.join(","),
                                    authorized_cas: authorized_cas.join(","),
                                    authorized_cns: authorized_cns.join(","),
                                    inherited_from_user_group: false,
                                    user_group: Some("n/a".to_string()),
                                    policy_type: "INLINE POLICY".to_string(),
                                    policy_name: inline_policy.name.clone(),
                                    policy_orn: Some("n/a".to_string()),
                                    policy_version: Some("n/a".to_string()),
                                    effect: statement.effect.clone(),
                                    actions_pattern: action.action.clone(),
                                    matching_operation: operation.operation.clone(),
                                    resource_type: resource.0.clone(),
                                    resources: resource_instances.clone().join(","),
                                };
                                record.push(new_line);
                            }
                        }
                    }
                }
            }
        }
    }

    //user-assigned managed policies
    println!(
        "    MANAGED POLICIES ({} assigned to this EIM user)",
        iam_user_report.managed_policies.len()
    );
    for managed_policy in iam_user_report.managed_policies.iter() {
        println!(
            "      POLICY '{}' [ORN: {}] -> policy version currently in use is '{}'",
            managed_policy.name, managed_policy.orn, managed_policy.version
        );
        for statement in managed_policy.policy_report.statements.iter() {
            for action in statement.actions.iter() {
                for operation in action.operations.iter() {
                    for resource in operation.resources.iter() {
                        match options.osc_resource_id {
                            //optional osc_resource_id has been specified and it doesn't match with no resource of this resource type -> elude this resource type
                            Some(ref osc_resource_id) if !resource.1.contains(&osc_resource_id) => {
                            }
                            //all other cases (i.e. optional osc_resource_id wasn't specified OR it matches with a resource of this resource type) -> report this resource type
                            _ => {
                                let mut resource_instances: Vec<String> = Vec::new();
                                match options.osc_resource_id {
                                    //optional osc_resource_id has been specified and it matches with a resource of this resource type
                                    Some(ref osc_resource_id)
                                        if resource.1.contains(&osc_resource_id) =>
                                    {
                                        resource_instances = vec![osc_resource_id.clone()];
                                    }
                                    //all other cases (i.e. optional osc_resource_id wasn't specified
                                    _ => {
                                        resource_instances = resource.1.clone();
                                    }
                                }
                                //report to CLI
                                let cli_display_resources =
                                    cli_output_resources(options, resource_instances.clone());
                                println!("        '{}' ACTION PATTERN '{}' MATCHING WITH API CALL '{}' -> RESOURCE_TYPE '{}' (RESOURCE(S): '{}')", statement.effect, action.action, operation.operation, resource.0, cli_display_resources);
                                //report to CSV
                                let new_line = CSVReportLine {
                                    user: iam_user_report.user.name.clone(),
                                    user_email: iam_user_report.user.e_mail.clone(),
                                    user_type: "EIM USER".to_string(),
                                    authorized_ip_addresses: authorized_ip_addresses
                                        .clone()
                                        .join(","),
                                    authorized_cas: authorized_cas.clone().join(","),
                                    authorized_cns: authorized_cns.clone().join(","),
                                    inherited_from_user_group: false,
                                    user_group: Some("n/a".to_string()),
                                    policy_type: "MANAGED POLICY".to_string(),
                                    policy_name: managed_policy.name.clone(),
                                    policy_orn: Some(managed_policy.orn.clone()),
                                    policy_version: Some(managed_policy.version.clone()),
                                    effect: statement.effect.clone(),
                                    actions_pattern: action.action.clone(),
                                    matching_operation: operation.operation.clone(),
                                    resource_type: resource.0.clone(),
                                    resources: resource_instances.clone().join(","),
                                };
                                record.push(new_line);
                            }
                        }
                    }
                }
            }
        }
    }

    //user_groups inheritance
    for iam_user_group_report in iam_user_report.user_groups.iter() {
        println!(
            "  AS A MEMBER OF USER_GROUP '{}'",
            iam_user_group_report.group.name
        );

        //user_group-assigned inline policies
        println!(
            "    USER_GROUP INLINE POLICIES ({} assigned to this EIM user_group)",
            iam_user_group_report.inline_policies.len()
        );
        for inline_policy in iam_user_group_report.inline_policies.iter() {
            println!("      POLICY '{}'", inline_policy.name);
            for statement in inline_policy.policy_report.statements.iter() {
                for action in statement.actions.iter() {
                    for operation in action.operations.iter() {
                        for resource in operation.resources.iter() {
                            match options.osc_resource_id {
                                //optional osc_resource_id has been specified and it doesn't match with no resource of this resource type -> elude this resource type
                                Some(ref osc_resource_id)
                                    if !resource.1.contains(&osc_resource_id) => {}
                                //all other cases (i.e. optional osc_resource_id wasn't specified OR it matches with a resource of this resource type) -> report this resource type
                                _ => {
                                    let mut resource_instances: Vec<String> = Vec::new();
                                    match options.osc_resource_id {
                                        //optional osc_resource_id has been specified and it matches with a resource of this resource type
                                        Some(ref osc_resource_id)
                                            if resource.1.contains(&osc_resource_id) =>
                                        {
                                            resource_instances = vec![osc_resource_id.clone()];
                                        }
                                        //all other cases (i.e. optional osc_resource_id wasn't specified
                                        _ => {
                                            resource_instances = resource.1.clone();
                                        }
                                    }
                                    //report to CLI
                                    let cli_display_resources =
                                        cli_output_resources(options, resource_instances.clone());
                                    println!("        '{}' ACTION PATTERN '{}' MATCHING WITH API CALL '{}' -> RESOURCE_TYPE '{}' (RESOURCE(S): '{}')", statement.effect, action.action, operation.operation, resource.0, cli_display_resources);
                                    //report to CSV
                                    let new_line = CSVReportLine {
                                        user: iam_user_report.user.name.clone(),
                                        user_email: iam_user_report.user.e_mail.clone(),
                                        user_type: "EIM USER".to_string(),
                                        authorized_ip_addresses: authorized_ip_addresses
                                            .clone()
                                            .join(","),
                                        authorized_cas: authorized_cas.clone().join(","),
                                        authorized_cns: authorized_cns.clone().join(","),
                                        inherited_from_user_group: true,
                                        user_group: Some(iam_user_group_report.group.name.clone()),
                                        policy_type: "INLINE POLICY".to_string(),
                                        policy_name: inline_policy.name.clone(),
                                        policy_orn: Some("n/a".to_string()),
                                        policy_version: Some("n/a".to_string()),
                                        effect: statement.effect.clone(),
                                        actions_pattern: action.action.clone(),
                                        matching_operation: operation.operation.clone(),
                                        resource_type: resource.0.clone(),
                                        resources: resource_instances.clone().join(","),
                                    };
                                    record.push(new_line);
                                }
                            }
                        }
                    }
                }
            }
        }

        //user_group-assigned managed policies
        println!(
            "    MANAGED POLICIES ({} assigned to this EIM user_group)",
            iam_user_group_report.managed_policies.len()
        );
        for managed_policy in iam_user_group_report.managed_policies.iter() {
            println!(
                "      POLICY '{}' [ORN: {}] -> policy version currently in use is '{}'",
                managed_policy.name, managed_policy.orn, managed_policy.version
            );
            for statement in managed_policy.policy_report.statements.iter() {
                for action in statement.actions.iter() {
                    for operation in action.operations.iter() {
                        for resource in operation.resources.iter() {
                            match options.osc_resource_id {
                                //optional osc_resource_id has been specified and it doesn't match with no resource of this resource type -> elude this resource type
                                Some(ref osc_resource_id)
                                    if !resource.1.contains(&osc_resource_id) => {}
                                //all other cases (i.e. optional osc_resource_id wasn't specified OR it matches with a resource of this resource type) -> report this resource type
                                _ => {
                                    let mut resource_instances: Vec<String> = Vec::new();
                                    match options.osc_resource_id {
                                        //optional osc_resource_id has been specified and it matches with a resource of this resource type
                                        Some(ref osc_resource_id)
                                            if resource.1.contains(&osc_resource_id) =>
                                        {
                                            resource_instances = vec![osc_resource_id.clone()];
                                        }
                                        //all other cases (i.e. optional osc_resource_id wasn't specified
                                        _ => {
                                            resource_instances = resource.1.clone();
                                        }
                                    }
                                    //report to CLI
                                    let cli_display_resources =
                                        cli_output_resources(options, resource_instances.clone());
                                    println!("        '{}' ACTION PATTERN '{}' MATCHING WITH API CALL '{}' -> RESOURCE_TYPE '{}' (RESOURCE(S): '{}')", statement.effect, action.action, operation.operation, resource.0, cli_display_resources);
                                    //report to CSV
                                    let new_line = CSVReportLine {
                                        user: iam_user_report.user.name.clone(),
                                        user_email: iam_user_report.user.e_mail.clone(),
                                        user_type: "EIM USER".to_string(),
                                        authorized_ip_addresses: authorized_ip_addresses
                                            .clone()
                                            .join(","),
                                        authorized_cas: authorized_cas.clone().join(","),
                                        authorized_cns: authorized_cns.clone().join(","),
                                        inherited_from_user_group: true,
                                        user_group: Some(iam_user_group_report.group.name.clone()),
                                        policy_type: "MANAGED POLICY".to_string(),
                                        policy_name: managed_policy.name.clone(),
                                        policy_orn: Some(managed_policy.orn.clone()),
                                        policy_version: Some(managed_policy.version.clone()),
                                        effect: statement.effect.clone(),
                                        actions_pattern: action.action.clone(),
                                        matching_operation: operation.operation.clone(),
                                        resource_type: resource.0.clone(),
                                        resources: resource_instances.clone().join(","),
                                    };
                                    record.push(new_line);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(record)
}

fn cli_output_resources(options: &Options, resources: Vec<String>) -> String {
    let mut cli_display_resources = "".to_string();
    if resources.len() > options.max_resources_display_on_cli {
        cli_display_resources = resources[0..options.max_resources_display_on_cli]
            .to_vec()
            .join(",");
        cli_display_resources.push_str(&format!(",... too many items ({}) for displaying them all, but they were all assessed and recorded in the CSV report file.", resources.len()));
    } else {
        cli_display_resources.push_str(&resources.join(","));
    }
    return cli_display_resources;
}

pub fn output_cypher_report(options: &Options, global_report: &GlobalReport) -> Result<(), Error> {
    let mut cypher_path = PathBuf::from(&options.report_path);
    cypher_path.set_extension("cypher");
    let mut file = File::create(&cypher_path).expect("Cannot create file");
    //ROOT ACCOUNT
    writeln!(
        file,
        "CREATE (ROOT_ACCOUNT_{0}:ROOT_ACCOUNT {{name:\"{0}\", mail:\"{1}\", authorized_ip_addresses:\"{2}\", authorized_cas:\"{3}\", authorized_cns:\"{4}\"}})",
        global_report.root_account.id, global_report.root_account.e_mail, global_report.authorized_ip_addresses.join(","), global_report.authorized_cns.join(","), global_report.authorized_cns.join(",")
    )
    .expect("Cannot write to file");
    // BUILT_IN POLICY
    writeln!(
        file,
        "CREATE (BUILT_IN_POLICY_Default:BUILT_IN_POLICY {{name:\"Built-in\"}})"
    )
    .expect("Cannot write to file");
    // BUILT_IN_POLICY -[:APPLIES_TO]-> ROOT_ACCOUNT
    writeln!(
        file,
        "CREATE (BUILT_IN_POLICY_Default)-[:APPLIES_TO]->(ROOT_ACCOUNT_{})",
        global_report.root_account.id,
    )
    .expect("Cannot write to file");
    //EIM USER GROUPS
    for iam_user_group_report in global_report.iam_user_group_reports.iter() {
        writeln!(
            file,
            "CREATE (EIM_USER_GROUP_{}:EIM_USER_GROUP {{name:\"{}\"}})",
            iam_user_group_report.0.replace("-", "_"),
            iam_user_group_report.0
        )
        .expect("Cannot write to file");
    }
    //EIM USERS
    for iam_user_report in global_report.iam_user_reports.iter() {
        writeln!(
            file,
            "CREATE (EIM_USER_{0}:EIM_USER {{name:\"{1}\", mail:\"{2}\", authorized_ip_addresses:\"{3}\", authorized_cas:\"{4}\", authorized_cns:\"{5}\"}})",
            iam_user_report.user.name.replace("-", "_"),
            iam_user_report.user.name,
            iam_user_report.user.e_mail,
            global_report.authorized_ip_addresses.join(","),
            global_report.authorized_cns.join(","),
            global_report.authorized_cns.join(",")
        )
        .expect("Cannot write to file");
        for user_group in iam_user_report.user_groups.iter() {
            // EIM_USER_GROUP -[:CONTAINS]-> EIM_USER
            writeln!(
                file,
                "CREATE (EIM_USER_GROUP_{})-[:CONTAINS]->(EIM_USER_{})",
                user_group.group.name.replace("-", "_"),
                iam_user_report.user.name.replace("-", "_")
            )
            .expect("Cannot write to file");
        }
    }
    // RESOURCE_TYPES
    for resource_type in global_report.resources.iter() {
        writeln!(
            file,
            "CREATE (RESOURCE_TYPE_{}:RESOURCE_TYPE {{name:\"{}\"}})",
            resource_type.0.replace("-", "_"),
            resource_type.0
        )
        .expect("Cannot write to file");
        //there are too many product types for cypher export
        if resource_type.0 != "ProductType" {
            // RESOURCES
            let inventoried_resources = global_report
                .resources
                .get(resource_type.0)
                .ok_or(Error::UnavailableResourceType(resource_type.0.clone()))?
                .clone();
            for inventoried_resource in inventoried_resources.iter() {
                //
                let mut tag_data = "".to_string();
                match global_report.resource_tags.get(inventoried_resource) {
                    Some(tags) => {
                        for tag in tags {
                            tag_data.push_str(&format!(
                                ", tag_{0}: \"{1}\"",
                                tag.0.to_lowercase(),
                                tag.1
                            ));
                        }
                    }
                    None => {}
                };
                //
                writeln!(
                file,
                "CREATE (RESOURCE_{2}_{0}:RESOURCE {{name:\"{1}\", id:\"{1}\", resource_type:\"{2}\"{3}}})",
                inventoried_resource.replace("-", "_"),
                inventoried_resource,
                resource_type.0,
                tag_data
            )
            .expect("Cannot write to file");
                // RESOURCE_TYPE -[:CONTAINS]-> RESOURCE
                writeln!(
                    file,
                    "CREATE (RESOURCE_TYPE_{0})-[:CONTAINS]->(RESOURCE_{0}_{1})",
                    resource_type.0.replace("-", "_"),
                    inventoried_resource.replace("-", "_")
                )
                .expect("Cannot write to file");
            }
        }
    }
    // OPERATIONS
    for api_call in apis_ref::API_CALLS.entries() {
        writeln!(
            file,
            "CREATE (OPERATION_{0}:OPERATION {{name:\"{1}\"}})",
            api_call.0.replace(":", "_"),
            api_call.0
        )
        .expect("Cannot write to file");
        // BUILT_IN_POLICY -[:ALLOWS]-> OPERATION
        writeln!(
            file,
            "CREATE (BUILT_IN_POLICY_Default)-[:ALLOWS]->(OPERATION_{})",
            api_call.0.replace(":", "_"),
        )
        .expect("Cannot write to file");
        // OPERATION -[:IS_APPLICABLE_TO]-> RESOURCE_TYPE
        for resource_type in api_call.1.iter() {
            writeln!(
                file,
                "CREATE (OPERATION_{0})-[:IS_APPLICABLE_TO]->(RESOURCE_TYPE_{1})",
                api_call.0.replace(":", "_"),
                resource_type.replace("-", "_")
            )
            .expect("Cannot write to file");
        }
    }

    // USER INLINE POLICIES
    for iam_user_inline_policy_report in global_report.user_inline_policy_reports.iter() {
        let user_name = String::from(iam_user_inline_policy_report.0);
        for inline_policy in iam_user_inline_policy_report.1.iter() {
            writeln!(
                file,
                "CREATE (INLINE_POLICY_User_{0}:INLINE_POLICY {{name:\"{1}\"}})",
                inline_policy.name.replace("-", "_"),
                inline_policy.name
            )
            .expect("Cannot write to file");
            // INLINE_POLICY -[:APPLIES_TO]-> EIM_USER
            writeln!(
                file,
                "CREATE (INLINE_POLICY_User_{0})-[:APPLIES_TO]->(EIM_USER_{1})",
                inline_policy.name.replace("-", "_"),
                user_name.replace("-", "_"),
            )
            .expect("Cannot write to file");
            // POLICY -[:ALLOWS/DENIES]-> OPERATION
            for statement in inline_policy.policy_report.statements.iter() {
                for action in statement.actions.iter() {
                    for operation in action.operations.iter() {
                        writeln!(
                            file,
                            "CREATE (INLINE_POLICY_User_{0})-[:{1}]->(OPERATION_{2})",
                            inline_policy.name.replace("-", "_"),
                            statement
                                .effect
                                .replace("Allow", "ALLOWS")
                                .replace("Deny", "DENIES"),
                            operation.operation.replace(":", "_"),
                        )
                        .expect("Cannot write to file");
                    }
                }
            }
        }
    }
    // USER_GROUP INLINE POLICIES
    for iam_user_group_inline_policy_report in global_report.user_group_inline_policy_reports.iter()
    {
        let user_group_name = String::from(iam_user_group_inline_policy_report.0);
        for inline_policy in iam_user_group_inline_policy_report.1.iter() {
            writeln!(
                file,
                "CREATE (INLINE_POLICY_UserGroup_{0}:INLINE_POLICY {{name:\"{1}\"}})",
                inline_policy.name.replace("-", "_"),
                inline_policy.name
            )
            .expect("Cannot write to file");
            // INLINE_POLICY -[:APPLIES_TO]-> EIM_USER
            writeln!(
                file,
                "CREATE (INLINE_POLICY_UserGroup_{0})-[:APPLIES_TO]->(EIM_USER_GROUP_{1})",
                inline_policy.name.replace("-", "_"),
                user_group_name.replace("-", "_"),
            )
            .expect("Cannot write to file");
            // POLICY -[:ALLOWS/DENIES]-> OPERATION
            for statement in inline_policy.policy_report.statements.iter() {
                for action in statement.actions.iter() {
                    for operation in action.operations.iter() {
                        writeln!(
                            file,
                            "CREATE (INLINE_POLICY_UserGroup_{0})-[:{1}]->(OPERATION_{2})",
                            inline_policy.name.replace("-", "_"),
                            statement
                                .effect
                                .replace("Allow", "ALLOWS")
                                .replace("Deny", "DENIES"),
                            operation.operation.replace(":", "_"),
                        )
                        .expect("Cannot write to file");
                    }
                }
            }
        }
    }
    // MANAGED POLICIES
    for managed_policy in global_report.managed_policy_reports.iter() {
        writeln!(
            file,
            "CREATE (MANAGED_POLICY_{0}:MANAGED_POLICY {{name:\"{1}\", orn:\"{2}\", version:\"{3}\"}})",
            managed_policy.1.name.replace("-", "_"),
            managed_policy.1.name,
            managed_policy.1.orn,
            managed_policy.1.version
        )
        .expect("Cannot write to file");
        // POLICY -[:ALLOWS/DENIES]-> OPERATION
        for statement in managed_policy.1.policy_report.statements.iter() {
            for action in statement.actions.iter() {
                for operation in action.operations.iter() {
                    writeln!(
                        file,
                        "CREATE (MANAGED_POLICY_{0})-[:{1}]->(OPERATION_{2})",
                        managed_policy.1.name.replace("-", "_"),
                        statement
                            .effect
                            .replace("Allow", "ALLOWS")
                            .replace("Deny", "DENIES"),
                        operation.operation.replace(":", "_"),
                    )
                    .expect("Cannot write to file");
                }
            }
        }
    }
    // POLICY -[:APPLIES_TO]-> EIM_USER
    for iam_user_report in global_report.iam_user_reports.iter() {
        for managed_policy in iam_user_report.managed_policies.iter() {
            writeln!(
                file,
                "CREATE (MANAGED_POLICY_{0})-[:APPLIES_TO]->(EIM_USER_{1})",
                managed_policy.name.replace("-", "_"),
                iam_user_report.user.name.replace("-", "_"),
            )
            .expect("Cannot write to file");
        }
    }
    // POLICY -[:APPLIES_TO]-> EIM_USER_GROUP
    for iam_user_group_report in global_report.iam_user_group_reports.iter() {
        for managed_policy in iam_user_group_report.1.managed_policies.iter() {
            writeln!(
                file,
                "CREATE (MANAGED_POLICY_{0})-[:APPLIES_TO]->(EIM_USER_GROUP_{1})",
                managed_policy.name.replace("-", "_"),
                iam_user_group_report.1.group.name.replace("-", "_"),
            )
            .expect("Cannot write to file");
        }
    }

    Ok(())
}

pub fn output_json_report(options: &Options, global_report: &GlobalReport) -> Result<(), Error> {
    let mut json_path = PathBuf::from(&options.report_path);
    json_path.set_extension("json");
    let mut file = File::create(&json_path).expect("Cannot create file");
    let global_report_in_json_format = serde_json::to_string(global_report)
        .map_err(|e| Error::JsonSerializationError(e.to_string()))?;
    writeln!(file, "{}", global_report_in_json_format).expect("Cannot write to file");

    Ok(())
}
