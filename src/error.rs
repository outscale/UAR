use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    //Root account
    #[error("Could not read Root account: {0}")]
    ReadAccounts(String),
    #[error("Root_account is missing: {0}")]
    MissingRootAccount(String),
    #[error("Root_account_id is missing: {0}")]
    MissingRootAccountId(String),
    #[error("Root_account_name is missing: {0}")]
    MissingRootAccountName(String),
    #[error("Root_account_e_mail is missing: {0}")]
    MissingRootAccountEmail(String),
    //EIM user
    #[error("Could not read EIM users: {0}")]
    ReadUsers(String),
    #[error("User_email is missing")]
    MissingUserEmail(),
    #[error("User_name is missing: {0}")]
    MissingUserName(String),
    //EIM user_group
    #[error("Could not read user_groups per EIM user: {0}")]
    ReadUserGroupsPerUser(String),
    #[error("UserGroup_name is missing: {0}")]
    MissingUserGroupName(String),
    //Inline policy
    #[error("Could not read inline_policy for EIM user: {0}")]
    ReadUserPolicy(String),
    #[error("Could not read inline_policies for EIM user: {0}")]
    ReadUserPolicies(String),
    #[error("Could not read inline_policies for EIM user_group: {0}")]
    ReadUserGroupPolicies(String),
    #[error("InlinePolicy_name is missing")]
    MissingInlinePolicyName,
    #[error("InlinePolicy_body is missing: {0}")]
    MissingInlinePolicyBody(String),
    #[error("InlinePolicy_body is not valid: {0}")]
    InvalidInlinePolicyBody(serde_json::Error),
    //Report
    #[error("Regular expression is not valid: {0}")]
    InvalidRegularExpression(String),
    #[error("Json serialization error: {0}")]
    JsonSerializationError(String),
    #[error("Managed policy is missing in records: {0}")]
    MissingManagedPolicyRecord(String),
    #[error("GroupReport is missing: {0}")]
    MissingUserGroupReport(String),
    #[error("CSV writing issue: {0}")]
    CSVWritingIssue(#[from] csv::Error),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    //Managed policy
    #[error("ManagedPolicy is missing")]
    MissingManagedPolicy,
    #[error("ManagedPolicy_body is missing: {0} {1}")]
    MissingManagedPolicyBody(String, String),
    #[error("ManagedPolicy_orn is missing")]
    MissingManagedPolicyOrn,
    #[error("ManagedPolicy_default_version_id is missing")]
    MissingManagedPolicyDefaultVersionId,
    #[error("ManagedPolicyName is missing")]
    MissingManagedPolicyName,
    #[error("ManagedPolicyVersion is missing")]
    MissingManagedPolicyVersion,
    #[error("Could not read managed policies assigned to EIM user: {0}")]
    ReadLinkedPolicies(String),
    #[error("Could not read managed policies assigned to EIM user_group: {0}")]
    ReadManagedPoliciesLinkedToUserGroup(String),
    #[error("Could not read managed policy: {0}")]
    ReadPolicy(String),
    #[error("Could not read managed policy version: {0}")]
    ReadPolicyVersion(String),
    #[error("ManagedPolicy_body is not valid: {0}")]
    InvalidManagedPolicyBody(serde_json::Error),
    //Resources
    #[error("Unknown resource type: {0}")]
    UnavailableResourceType(String),
    #[error("Could not read access keys: {0}")]
    ReadAccessKeys(String),
    #[error("AccessKey_id is missing")]
    MissingAccessKeyId,
    #[error("Account_id is missing")]
    MissingAccountId,
    #[error("Could not read API access rules: {0}")]
    ReadApiAccessRules(String),
    #[error("ApiAccessRule_id is missing")]
    MissingApiAccessRuleId,
    #[error("Could not read CAs: {0}")]
    ReadCas(String),
    #[error("Ca_id is missing")]
    MissingCaId,
    #[error("Could not read ClientGateways: {0}")]
    ReadClientGateways(String),
    #[error("ClientGateway_id is missing")]
    MissingClientGatewayId,
    #[error("Could not read DedicatedGroups: {0}")]
    ReadDedicatedGroups(String),
    #[error("DedicatedGroup_id is missing")]
    MissingDedicatedGroupId,
    #[error("Could not read DhcpOptions: {0}")]
    ReadDhcpOptions(String),
    #[error("DhcpOptionsSet_id is missing")]
    MissingDhcpOptionsSetId,
    #[error("Could not read DirectLinks: {0}")]
    ReadDirectLinks(String),
    #[error("DirectLink_id is missing")]
    MissingDirectLinkId,
    #[error("Could not read DirectLinkInterfaces: {0}")]
    ReadDirectLinkInterfaces(String),
    #[error("DirectLinkInterface_id is missing")]
    MissingDirectLinkInterfaceId,
    #[error("Could not read FlexibleGpus: {0}")]
    ReadFlexibleGpus(String),
    #[error("FlexibleGpu_id is missing")]
    MissingFlexibleGpuId,
    #[error("Could not read Images: {0}")]
    ReadImages(String),
    #[error("Image_id is missing")]
    MissingImageId,
    #[error("Could not read InternetServices: {0}")]
    ReadInternetServices(String),
    #[error("InternetService_id is missing")]
    MissingInternetServiceId,
    #[error("Could not read Keypairs: {0}")]
    ReadKeypairs(String),
    #[error("Keypair_name is missing")]
    MissingKeypairName,
    #[error("Could not read ListenerRules: {0}")]
    ReadListenerRules(String),
    #[error("ListenerRule_name is missing")]
    MissingListenerRuleName,
    #[error("Could not read LoadBalancers: {0}")]
    ReadLoadBalancers(String),
    #[error("LoadBalancer_name is missing")]
    MissingLoadBalancerName,
    #[error("Could not read Locations: {0}")]
    ReadLocations(String),
    #[error("Location_code is missing")]
    MissingLocationCode,
    #[error("Could not read NatServices: {0}")]
    ReadNatServices(String),
    #[error("NatService_id is missing")]
    MissingNatServiceId,
    #[error("Could not read Nets: {0}")]
    ReadNets(String),
    #[error("Net_id is missing")]
    MissingNetId,
    #[error("Could not read NetAccessPoints: {0}")]
    ReadNetAccessPoints(String),
    #[error("NetAccessPoint_id is missing")]
    MissingNetAccessPointId,
    #[error("Could not read NetPeerings: {0}")]
    ReadNetPeerings(String),
    #[error("NetPeering_id is missing")]
    MissingNetPeeringId,
    #[error("Could not read Nics: {0}")]
    ReadNics(String),
    #[error("Nic_id is missing")]
    MissingNicId,
    #[error("Could not read Managed Policies: {0}")]
    ReadManagedPolicies(String),
    #[error("Managed Policy_id is missing")]
    MissingManagedPolicyId,
    #[error("Could not read ProductTypes: {0}")]
    ReadProductTypes(String),
    #[error("ProductType_id is missing")]
    MissingProductTypeId,
    #[error("Could not read PublicIps: {0}")]
    ReadPublicIps(String),
    #[error("PublicIp_id is missing")]
    MissingPublicIpId,
    #[error("Could not read Quotas: {0}")]
    ReadQuotas(String),
    #[error("Quota_type is missing")]
    MissingQuotaType,
    #[error("Could not read Regions: {0}")]
    ReadRegions(String),
    #[error("Region_name is missing")]
    MissingRegionName,
    #[error("ResourceId is missing")]
    MissingResourceId,
    #[error("Could not read RouteTables: {0}")]
    ReadRouteTables(String),
    #[error("RouteTable_id is missing")]
    MissingRouteTableId,
    #[error("Could not read SecurityGroups: {0}")]
    ReadSecurityGroups(String),
    #[error("SecurityGroup_id is missing")]
    MissingSecurityGroupId,
    #[error("Could not read ServerCertificates: {0}")]
    ReadServerCertificates(String),
    #[error("ServerCertificate_id is missing")]
    MissingServerCertificateId,
    #[error("Could not read Snapshots: {0}")]
    ReadSnapshots(String),
    #[error("Snapshot_id is missing")]
    MissingSnapshotId,
    #[error("Could not read Subnets: {0}")]
    ReadSubnets(String),
    #[error("Subnet_id is missing")]
    MissingSubnetId,
    #[error("Could not read Subregions: {0}")]
    ReadSubregions(String),
    #[error("Subregion_name is missing")]
    MissingSubregionName,
    #[error("Could not read Tags: {0}")]
    ReadTags(String),
    #[error("Tag_key is missing")]
    MissingTagKey,
    #[error("Tag_value is missing")]
    MissingTagValue,
    #[error("User_id is missing")]
    MissingUserId,
    #[error("Could not read UserGroups: {0}")]
    ReadUserGroups(String),
    #[error("UserGroup_id is missing")]
    MissingUserGroupId,
    #[error("Could not read VirtualGateways: {0}")]
    ReadVirtualGateways(String),
    #[error("VirtualGateway_id is missing")]
    MissingVirtualGatewayId,
    #[error("Could not read Vms: {0}")]
    ReadVms(String),
    #[error("Vm_id is missing")]
    MissingVmId,
    #[error("Could not read VmGroups: {0}")]
    ReadVmGroups(String),
    #[error("VmGroup_id is missing")]
    MissingVmGroupId,
    #[error("Could not read VmTemplates: {0}")]
    ReadVmTemplates(String),
    #[error("Could not read Volumes: {0}")]
    ReadVolumes(String),
    #[error("Volume_id is missing")]
    MissingVolumeId,
    #[error("Could not read VpnConnections: {0}")]
    ReadVpnConnections(String),
    #[error("VpnConnection_id is missing")]
    MissingVpnConnectionId,
}
