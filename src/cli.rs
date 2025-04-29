use clap::Parser;
use std::path::PathBuf;

use outscale_api::apis::configuration::{AWSv4Key, Configuration};
use secrecy::SecretString;

#[derive(Parser, Debug, Clone)]
pub struct Options {
    /// mandatory OSC_REGION (e.g. `eu-west-2`)
    #[arg(long, env)]
    pub osc_region: String,
    /// mandatory OSC_ACCESS_KEY
    #[arg(long, env)]
    pub osc_access_key: String,
    /// mandatory OSC_SECRET_KEY
    #[arg(long, env)]
    pub osc_secret_key: String,
    /// optional OSC_USER_ID
    #[arg(long)]
    pub osc_user_id: Option<String>,
    /// optional OSC_RESOURCE_ID
    #[arg(long)]
    pub osc_resource_id: Option<String>,
    /// optional REPORT_PATH
    #[arg(long, env, default_value = "uar_report")]
    pub report_path: PathBuf,
    /// optional MAX_RESOURCES_DISPLAY_ON_CLI - max number of resources to display in CLI (all resources will be recorded in the CSV file report nonetheless)
    #[arg(long, env, default_value = "10")]
    pub max_resources_display_on_cli: usize,
}

impl From<Options> for Configuration {
    fn from(options: Options) -> Configuration {
        let mut config = Configuration::new();
        config.base_path = format!("https://api.{}.outscale.com/api/v1", &options.osc_region);
        config.aws_v4_key = Some(AWSv4Key {
            access_key: options.osc_access_key,
            secret_key: SecretString::new(options.osc_secret_key),
            region: options.osc_region,
            service: "oapi".to_string(),
        });
        config
    }
}
