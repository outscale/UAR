use clap::Parser;
use outscale_api::apis::configuration::Configuration;

mod apis_ref;
mod authorization_policy_inventory;
mod banner;
mod cli;
mod error;
mod report;
mod resource_inventory;
mod run_analysis;
mod user_inventory;

/* Assess user access rights for a specific Outscale account and issue reports in CSV, JSON and CYPHER formats */
fn main() {
    //set API request parameters
    let options = cli::Options::parse();
    let config: Configuration = options.clone().into();

    banner::print_banner();

    run_analysis::run_analysis(&config, &options).unwrap();
}
