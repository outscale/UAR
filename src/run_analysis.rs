use crate::{
    authorization_policy_inventory, cli::Options, error::Error, report, resource_inventory,
    user_inventory,
};
use itertools::Itertools;
use outscale_api::apis::configuration::Configuration;

pub fn run_analysis(configuration: &Configuration, options: &Options) -> Result<(), Error> {
    let resources = resource_inventory::list_resources(configuration)?;
    let resource_tags = resource_inventory::list_resource_tags(configuration)?;
    let root_account = user_inventory::get_root_account(configuration)?;
    let iam_users = user_inventory::list_iam_users(configuration)?;
    let iam_user_group_assignments =
        user_inventory::list_iam_user_group_assignments(configuration, &iam_users)?;
    let iam_user_groups = iam_user_group_assignments
        .values()
        .flatten()
        .cloned()
        .unique_by(|group| group.name.clone())
        .collect::<Vec<_>>();
    let policies = authorization_policy_inventory::retrieve_policies(
        configuration,
        &iam_users,
        &iam_user_groups,
    )?;
    let global_report = report::compute_report(
        &root_account,
        &iam_users,
        &iam_user_group_assignments,
        &policies,
        &resources,
        &resource_tags,
    )?;
    report::output_global_report(&options, &global_report)
}
