use std::collections::HashMap;

use crate::error::Error;

use outscale_api::apis::access_key_api::read_access_keys;
use outscale_api::apis::account_api::read_accounts;
use outscale_api::apis::api_access_rule_api::read_api_access_rules;
use outscale_api::apis::ca_api::read_cas;
use outscale_api::apis::client_gateway_api::read_client_gateways;
use outscale_api::apis::configuration::Configuration;
use outscale_api::apis::dedicated_group_api::read_dedicated_groups;
use outscale_api::apis::dhcp_option_api::read_dhcp_options;
use outscale_api::apis::direct_link_api::read_direct_links;
use outscale_api::apis::direct_link_interface_api::read_direct_link_interfaces;
use outscale_api::apis::flexible_gpu_api::read_flexible_gpus;
use outscale_api::apis::image_api::read_images;
use outscale_api::apis::internet_service_api::read_internet_services;
use outscale_api::apis::keypair_api::read_keypairs;
use outscale_api::apis::listener_api::read_listener_rules;
use outscale_api::apis::load_balancer_api::read_load_balancers;
use outscale_api::apis::location_api::read_locations;
use outscale_api::apis::nat_service_api::read_nat_services;
use outscale_api::apis::net_access_point_api::read_net_access_points;
use outscale_api::apis::net_api::read_nets;
use outscale_api::apis::net_peering_api::read_net_peerings;
use outscale_api::apis::nic_api::read_nics;
use outscale_api::apis::policy_api::{read_policies, read_user_group_policies, read_user_policies};
use outscale_api::apis::product_type_api::read_product_types;
use outscale_api::apis::public_ip_api::read_public_ips;
use outscale_api::apis::quota_api::read_quotas;
use outscale_api::apis::region_api::read_regions;
use outscale_api::apis::route_table_api::read_route_tables;
use outscale_api::apis::security_group_api::read_security_groups;
use outscale_api::apis::server_certificate_api::read_server_certificates;
use outscale_api::apis::snapshot_api::read_snapshots;
use outscale_api::apis::subnet_api::read_subnets;
use outscale_api::apis::subregion_api::read_subregions;
use outscale_api::apis::tag_api::read_tags;
use outscale_api::apis::user_api::read_users;
use outscale_api::apis::user_group_api::read_user_groups;
use outscale_api::apis::virtual_gateway_api::read_virtual_gateways;
use outscale_api::apis::vm_api::read_vms;
use outscale_api::apis::vm_group_api::read_vm_groups;
use outscale_api::apis::vm_template_api::read_vm_templates;
use outscale_api::apis::volume_api::read_volumes;
use outscale_api::apis::vpn_connection_api::read_vpn_connections;
use outscale_api::models::{
    ReadAccessKeysRequest, ReadAccountsRequest, ReadApiAccessRulesRequest, ReadCasRequest,
    ReadClientGatewaysRequest, ReadDedicatedGroupsRequest, ReadDhcpOptionsRequest,
    ReadDirectLinkInterfacesRequest, ReadDirectLinksRequest, ReadFlexibleGpusRequest,
    ReadImagesRequest, ReadInternetServicesRequest, ReadKeypairsRequest, ReadListenerRulesRequest,
    ReadLoadBalancersRequest, ReadLocationsRequest, ReadNatServicesRequest,
    ReadNetAccessPointsRequest, ReadNetPeeringsRequest, ReadNetsRequest, ReadNicsRequest,
    ReadPoliciesRequest, ReadProductTypesRequest, ReadPublicIpsRequest, ReadQuotasRequest,
    ReadRegionsRequest, ReadRouteTablesRequest, ReadSecurityGroupsRequest,
    ReadServerCertificatesRequest, ReadSnapshotsRequest, ReadSubnetsRequest, ReadSubregionsRequest,
    ReadTagsRequest, ReadUserGroupPoliciesRequest, ReadUserGroupsRequest, ReadUserPoliciesRequest,
    ReadUsersRequest, ReadVirtualGatewaysRequest, ReadVmGroupsRequest, ReadVmTemplatesRequest,
    ReadVmsRequest, ReadVolumesRequest, ReadVpnConnectionsRequest,
};

pub fn list_resources(
    configuration: &Configuration,
) -> Result<HashMap<String, Vec<String>>, Error> {
    let mut resources: HashMap<String, Vec<String>> = HashMap::new();

    //get resources with resource type 'AccessKey'
    let resource_type = "AccessKey".to_string();
    let request = ReadAccessKeysRequest::new();
    let response = read_access_keys(&configuration, Some(request))
        .map_err(|e| Error::ReadAccessKeys(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .access_keys
        .into_iter()
        .flatten()
        .map(|access_key| {
            Ok(access_key
                .access_key_id
                .as_ref()
                .ok_or(Error::MissingAccessKeyId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Account'
    let resource_type = "Account".to_string();
    let request = ReadAccountsRequest::new();
    let response = read_accounts(&configuration, Some(request))
        .map_err(|e| Error::ReadAccounts(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .accounts
        .into_iter()
        .flatten()
        .map(|account| {
            Ok(account
                .account_id
                .as_ref()
                .ok_or(Error::MissingAccountId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'ApiAccessPolicy'
    let resource_type = "ApiAccessPolicy".to_string();
    let resource_instances: Vec<String> = vec!["ApiAccessPolicy".to_string()];
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'ApiAccessRule'
    let resource_type = "ApiAccessRule".to_string();
    let request = ReadApiAccessRulesRequest::new();
    let response = read_api_access_rules(&configuration, Some(request))
        .map_err(|e| Error::ReadApiAccessRules(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .api_access_rules
        .into_iter()
        .flatten()
        .map(|api_access_rule| {
            Ok(api_access_rule
                .api_access_rule_id
                .as_ref()
                .ok_or(Error::MissingApiAccessRuleId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'ApiLog'
    let resource_type = "ApiLog".to_string();
    let resource_instances: Vec<String> = vec![];
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Ca'
    let resource_type = "Ca".to_string();
    let request = ReadCasRequest::new();
    let response =
        read_cas(&configuration, Some(request)).map_err(|e| Error::ReadCas(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .cas
        .into_iter()
        .flatten()
        .map(|ca| Ok(ca.ca_id.as_ref().ok_or(Error::MissingCaId)?.clone()))
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Catalog'
    let resource_type = "Catalog".to_string();
    let resource_instances: Vec<String> = vec!["Catalog".to_string()];
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'ClientGateway'
    let resource_type = "ClientGateway".to_string();
    let request = ReadClientGatewaysRequest::new();
    let response = read_client_gateways(&configuration, Some(request))
        .map_err(|e| Error::ReadClientGateways(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .client_gateways
        .into_iter()
        .flatten()
        .map(|client_gateway| {
            Ok(client_gateway
                .client_gateway_id
                .as_ref()
                .ok_or(Error::MissingClientGatewayId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'DedicatedGroup'
    let resource_type = "DedicatedGroup".to_string();
    let request = ReadDedicatedGroupsRequest::new();
    let response = read_dedicated_groups(&configuration, Some(request))
        .map_err(|e| Error::ReadDedicatedGroups(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .dedicated_groups
        .into_iter()
        .flatten()
        .map(|dedicated_group| {
            Ok(dedicated_group
                .dedicated_group_id
                .as_ref()
                .ok_or(Error::MissingDedicatedGroupId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'DhcpOptionsSet'
    let resource_type = "DhcpOptionsSet".to_string();
    let request = ReadDhcpOptionsRequest::new();
    let response = read_dhcp_options(&configuration, Some(request))
        .map_err(|e| Error::ReadDhcpOptions(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .dhcp_options_sets
        .into_iter()
        .flatten()
        .map(|dhcp_options_set| {
            Ok(dhcp_options_set
                .dhcp_options_set_id
                .as_ref()
                .ok_or(Error::MissingDhcpOptionsSetId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'DirectLink'
    let resource_type = "DirectLink".to_string();
    let request = ReadDirectLinksRequest::new();
    let response = read_direct_links(&configuration, Some(request))
        .map_err(|e| Error::ReadDirectLinks(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .direct_links
        .into_iter()
        .flatten()
        .map(|direct_link| {
            Ok(direct_link
                .direct_link_id
                .as_ref()
                .ok_or(Error::MissingDirectLinkId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'DirectLinkInterface'
    let resource_type = "DirectLinkInterface".to_string();
    let request = ReadDirectLinkInterfacesRequest::new();
    let response = read_direct_link_interfaces(&configuration, Some(request))
        .map_err(|e| Error::ReadDirectLinkInterfaces(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .direct_link_interfaces
        .into_iter()
        .flatten()
        .map(|direct_link_interface| {
            Ok(direct_link_interface
                .direct_link_interface_id
                .as_ref()
                .ok_or(Error::MissingDirectLinkInterfaceId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'FlexibleGpu'
    let resource_type = "FlexibleGpu".to_string();
    let request = ReadFlexibleGpusRequest::new();
    let response = read_flexible_gpus(&configuration, Some(request))
        .map_err(|e| Error::ReadFlexibleGpus(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .flexible_gpus
        .into_iter()
        .flatten()
        .map(|flexible_gpu| {
            Ok(flexible_gpu
                .flexible_gpu_id
                .as_ref()
                .ok_or(Error::MissingFlexibleGpuId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Image'
    let resource_type = "Image".to_string();
    let request = ReadImagesRequest::new();
    let response =
        read_images(&configuration, Some(request)).map_err(|e| Error::ReadImages(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .images
        .into_iter()
        .flatten()
        .map(|image| {
            Ok(image
                .image_id
                .as_ref()
                .ok_or(Error::MissingImageId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'InternetService'
    let resource_type = "InternetService".to_string();
    let request = ReadInternetServicesRequest::new();
    let response = read_internet_services(&configuration, Some(request))
        .map_err(|e| Error::ReadInternetServices(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .internet_services
        .into_iter()
        .flatten()
        .map(|internet_service| {
            Ok(internet_service
                .internet_service_id
                .as_ref()
                .ok_or(Error::MissingInternetServiceId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Keypair'
    let resource_type = "Keypair".to_string();
    let request = ReadKeypairsRequest::new();
    let response = read_keypairs(&configuration, Some(request))
        .map_err(|e| Error::ReadKeypairs(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .keypairs
        .into_iter()
        .flatten()
        .map(|keypair| {
            Ok(keypair
                .keypair_name
                .as_ref()
                .ok_or(Error::MissingKeypairName)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'ListenerRule'
    let resource_type = "ListenerRule".to_string();
    let request = ReadListenerRulesRequest::new();
    let response = read_listener_rules(&configuration, Some(request))
        .map_err(|e| Error::ReadListenerRules(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .listener_rules
        .into_iter()
        .flatten()
        .map(|listener_rule| {
            Ok(listener_rule
                .listener_rule_name
                .as_ref()
                .ok_or(Error::MissingListenerRuleName)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'LoadBalancer'
    let resource_type = "LoadBalancer".to_string();
    let request = ReadLoadBalancersRequest::new();
    let response = read_load_balancers(&configuration, Some(request))
        .map_err(|e| Error::ReadLoadBalancers(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .load_balancers
        .into_iter()
        .flatten()
        .map(|load_balancer| {
            Ok(load_balancer
                .load_balancer_name
                .as_ref()
                .ok_or(Error::MissingLoadBalancerName)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Location'
    let resource_type = "Location".to_string();
    let request = ReadLocationsRequest::new();
    let response = read_locations(&configuration, Some(request))
        .map_err(|e| Error::ReadLocations(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .locations
        .into_iter()
        .flatten()
        .map(|location| {
            Ok(location
                .code
                .as_ref()
                .ok_or(Error::MissingLocationCode)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'NatService'
    let resource_type = "NatService".to_string();
    let request = ReadNatServicesRequest::new();
    let response = read_nat_services(&configuration, Some(request))
        .map_err(|e| Error::ReadNatServices(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .nat_services
        .into_iter()
        .flatten()
        .map(|nat_service| {
            Ok(nat_service
                .nat_service_id
                .as_ref()
                .ok_or(Error::MissingNatServiceId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Net'
    let resource_type = "Net".to_string();
    let request = ReadNetsRequest::new();
    let response =
        read_nets(&configuration, Some(request)).map_err(|e| Error::ReadNets(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .nets
        .into_iter()
        .flatten()
        .map(|net| Ok(net.net_id.as_ref().ok_or(Error::MissingNetId)?.clone()))
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'NetAccessPoint'
    let resource_type = "NetAccessPoint".to_string();
    let request = ReadNetAccessPointsRequest::new();
    let response = read_net_access_points(&configuration, Some(request))
        .map_err(|e| Error::ReadNetAccessPoints(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .net_access_points
        .into_iter()
        .flatten()
        .map(|net_access_point| {
            Ok(net_access_point
                .net_access_point_id
                .as_ref()
                .ok_or(Error::MissingNetAccessPointId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'NetPeering'
    let resource_type = "NetPeering".to_string();
    let request = ReadNetPeeringsRequest::new();
    let response = read_net_peerings(&configuration, Some(request))
        .map_err(|e| Error::ReadNetPeerings(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .net_peerings
        .into_iter()
        .flatten()
        .map(|net_peering| {
            Ok(net_peering
                .net_peering_id
                .as_ref()
                .ok_or(Error::MissingNetPeeringId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Nic'
    let resource_type = "Nic".to_string();
    let request = ReadNicsRequest::new();
    let response =
        read_nics(&configuration, Some(request)).map_err(|e| Error::ReadNics(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .nics
        .into_iter()
        .flatten()
        .map(|nic| Ok(nic.nic_id.as_ref().ok_or(Error::MissingNicId)?.clone()))
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'ManagedPolicy'
    let resource_type = "ManagedPolicy".to_string();
    let request = ReadPoliciesRequest::new();
    let response = read_policies(&configuration, Some(request))
        .map_err(|e| Error::ReadManagedPolicies(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .policies
        .into_iter()
        .flatten()
        .map(|policy| {
            Ok(policy
                .policy_id
                .as_ref()
                .ok_or(Error::MissingManagedPolicyId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'UserInlinePolicy'
    let resource_type = "UserInlinePolicy".to_string();
    let mut resource_instances: Vec<String> = Vec::new();
    let request = ReadUsersRequest::new();
    let response =
        read_users(&configuration, Some(request)).map_err(|e| Error::ReadUsers(e.to_string()))?;
    let iam_user_names: Vec<String> = response
        .users
        .into_iter()
        .flatten()
        .map(|user| {
            Ok(user
                .user_name
                .as_ref()
                .ok_or(Error::MissingUserName(
                    user.user_name.clone().unwrap_or_default(),
                ))?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    for iam_user_name in iam_user_names.iter() {
        let request = ReadUserPoliciesRequest::new(iam_user_name.to_string());
        let response = read_user_policies(&configuration, Some(request))
            .map_err(|e| Error::ReadUserPolicies(e.to_string()))?;
        let mut inline_policy_names: Vec<String> =
            response.policy_names.into_iter().flatten().collect();
        resource_instances.append(&mut inline_policy_names);
    }
    //
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'UserGroupInlinePolicy'
    let resource_type = "UserGroupInlinePolicy".to_string();
    let mut resource_instances: Vec<String> = Vec::new();
    let request = ReadUserGroupsRequest::new();
    let response = read_user_groups(&configuration, Some(request))
        .map_err(|e| Error::ReadUserGroups(e.to_string()))?;
    let iam_user_group_names: Vec<String> = response
        .user_groups
        .into_iter()
        .flatten()
        .map(|user_group| {
            Ok(user_group
                .name
                .as_ref()
                .ok_or(Error::MissingUserGroupName(
                    user_group.name.clone().unwrap_or_default(),
                ))?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    for iam_user_group_name in iam_user_group_names.iter() {
        let request = ReadUserGroupPoliciesRequest::new(iam_user_group_name.to_string());
        let response = read_user_group_policies(&configuration, Some(request))
            .map_err(|e| Error::ReadUserGroupPolicies(e.to_string()))?;
        let mut inline_policy_names: Vec<String> = response
            .policies
            .into_iter()
            .flatten()
            .map(|inline_policy| {
                Ok(inline_policy
                    .name
                    .as_ref()
                    .ok_or(Error::MissingInlinePolicyName)?
                    .clone())
            })
            .collect::<Result<_, Error>>()?;
        resource_instances.append(&mut inline_policy_names);
    }
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'ProductType'
    let resource_type = "ProductType".to_string();
    let request = ReadProductTypesRequest::new();
    let response = read_product_types(&configuration, Some(request))
        .map_err(|e| Error::ReadProductTypes(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .product_types
        .into_iter()
        .flatten()
        .map(|product_type| {
            Ok(product_type
                .product_type_id
                .as_ref()
                .ok_or(Error::MissingProductTypeId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'PublicCatalog'
    let resource_type = "PublicCatalog".to_string();
    let resource_instances: Vec<String> = vec!["PublicCatalog".to_string()];
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'PublicIp'
    let resource_type = "PublicIp".to_string();
    let request = ReadPublicIpsRequest::new();
    let response = read_public_ips(&configuration, Some(request))
        .map_err(|e| Error::ReadPublicIps(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .public_ips
        .into_iter()
        .flatten()
        .map(|public_ip| {
            Ok(public_ip
                .public_ip_id
                .as_ref()
                .ok_or(Error::MissingPublicIpId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Quota'
    let resource_type = "Quota".to_string();
    let request = ReadQuotasRequest::new();
    let response =
        read_quotas(&configuration, Some(request)).map_err(|e| Error::ReadQuotas(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .quota_types
        .into_iter()
        .flatten()
        .map(|quota_types| {
            Ok(format!(
                "quota_type_{}",
                quota_types
                    .quota_type
                    .as_ref()
                    .ok_or(Error::MissingQuotaType)?
            ))
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Region'
    let resource_type = "Region".to_string();
    let request = ReadRegionsRequest::new();
    let response = read_regions(&configuration, Some(request))
        .map_err(|e| Error::ReadRegions(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .regions
        .into_iter()
        .flatten()
        .map(|region| {
            Ok(region
                .region_name
                .as_ref()
                .ok_or(Error::MissingRegionName)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'RouteTable'
    let resource_type = "RouteTable".to_string();
    let request = ReadRouteTablesRequest::new();
    let response = read_route_tables(&configuration, Some(request))
        .map_err(|e| Error::ReadRouteTables(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .route_tables
        .into_iter()
        .flatten()
        .map(|route_table| {
            Ok(route_table
                .route_table_id
                .as_ref()
                .ok_or(Error::MissingRouteTableId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'SecurityGroup'
    let resource_type = "SecurityGroup".to_string();
    let request = ReadSecurityGroupsRequest::new();
    let response = read_security_groups(&configuration, Some(request))
        .map_err(|e| Error::ReadSecurityGroups(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .security_groups
        .into_iter()
        .flatten()
        .map(|security_group| {
            Ok(security_group
                .security_group_id
                .as_ref()
                .ok_or(Error::MissingSecurityGroupId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'ServerCertificate'
    let resource_type = "ServerCertificate".to_string();
    let request = ReadServerCertificatesRequest::new();
    let response = read_server_certificates(&configuration, Some(request))
        .map_err(|e| Error::ReadServerCertificates(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .server_certificates
        .into_iter()
        .flatten()
        .map(|server_certificate| {
            Ok(server_certificate
                .id
                .as_ref()
                .ok_or(Error::MissingServerCertificateId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Snapshot'
    let resource_type = "Snapshot".to_string();
    let request = ReadSnapshotsRequest::new();
    let response = read_snapshots(&configuration, Some(request))
        .map_err(|e| Error::ReadSnapshots(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .snapshots
        .into_iter()
        .flatten()
        .map(|snapshot| {
            Ok(snapshot
                .snapshot_id
                .as_ref()
                .ok_or(Error::MissingSnapshotId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Subnet'
    let resource_type = "Subnet".to_string();
    let request = ReadSubnetsRequest::new();
    let response = read_subnets(&configuration, Some(request))
        .map_err(|e| Error::ReadSubnets(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .subnets
        .into_iter()
        .flatten()
        .map(|subnet| {
            Ok(subnet
                .subnet_id
                .as_ref()
                .ok_or(Error::MissingSubnetId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Subregion'
    let resource_type = "Subregion".to_string();
    let request = ReadSubregionsRequest::new();
    let response = read_subregions(&configuration, Some(request))
        .map_err(|e| Error::ReadSubregions(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .subregions
        .into_iter()
        .flatten()
        .map(|subregion| {
            Ok(subregion
                .subregion_name
                .as_ref()
                .ok_or(Error::MissingSubregionName)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Tag'
    let resource_type = "Tag".to_string();
    let request = ReadTagsRequest::new();
    let response =
        read_tags(&configuration, Some(request)).map_err(|e| Error::ReadTags(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .tags
        .into_iter()
        .flatten()
        .map(|tag| {
            Ok(format!(
                "{}_{}",
                tag.resource_id.as_ref().ok_or(Error::MissingResourceId)?,
                &tag.key.as_ref().ok_or(Error::MissingTagKey)?
            ))
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'User'
    let resource_type = "User".to_string();
    let request = ReadUsersRequest::new();
    let response =
        read_users(&configuration, Some(request)).map_err(|e| Error::ReadUsers(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .users
        .into_iter()
        .flatten()
        .map(|user| Ok(user.user_id.as_ref().ok_or(Error::MissingUserId)?.clone()))
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'UserGroup'
    let resource_type = "UserGroup".to_string();
    let request = ReadUserGroupsRequest::new();
    let response = read_user_groups(&configuration, Some(request))
        .map_err(|e| Error::ReadUserGroups(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .user_groups
        .into_iter()
        .flatten()
        .map(|user_group| {
            Ok(user_group
                .user_group_id
                .as_ref()
                .ok_or(Error::MissingUserGroupId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'VirtualGateway'
    let resource_type = "VirtualGateway".to_string();
    let request = ReadVirtualGatewaysRequest::new();
    let response = read_virtual_gateways(&configuration, Some(request))
        .map_err(|e| Error::ReadVirtualGateways(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .virtual_gateways
        .into_iter()
        .flatten()
        .map(|virtual_gateway| {
            Ok(virtual_gateway
                .virtual_gateway_id
                .as_ref()
                .ok_or(Error::MissingVirtualGatewayId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Vm'
    let resource_type = "Vm".to_string();
    let request = ReadVmsRequest::new();
    let response =
        read_vms(&configuration, Some(request)).map_err(|e| Error::ReadVms(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .vms
        .into_iter()
        .flatten()
        .map(|vm| Ok(vm.vm_id.as_ref().ok_or(Error::MissingVmId)?.clone()))
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'VmGroup'
    let resource_type = "VmGroup".to_string();
    let request = ReadVmGroupsRequest::new();
    let response = read_vm_groups(&configuration, Some(request))
        .map_err(|e| Error::ReadVmGroups(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .vm_groups
        .into_iter()
        .flatten()
        .map(|vm_group| {
            Ok(vm_group
                .vm_group_id
                .as_ref()
                .ok_or(Error::MissingVmGroupId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'VmTemplate'
    let resource_type = "VmTemplate".to_string();
    let request = ReadVmTemplatesRequest::new();
    let response = read_vm_templates(&configuration, Some(request))
        .map_err(|e| Error::ReadVmTemplates(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .vm_templates
        .into_iter()
        .flatten()
        .map(|vm_template| Ok(vm_template.vm_template_id.clone()))
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'Volume'
    let resource_type = "Volume".to_string();
    let request = ReadVolumesRequest::new();
    let response = read_volumes(&configuration, Some(request))
        .map_err(|e| Error::ReadVolumes(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .volumes
        .into_iter()
        .flatten()
        .map(|volume| {
            Ok(volume
                .volume_id
                .as_ref()
                .ok_or(Error::MissingVolumeId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    //get resources with resource type 'VpnConnection'
    let resource_type = "VpnConnection".to_string();
    let request = ReadVpnConnectionsRequest::new();
    let response = read_vpn_connections(&configuration, Some(request))
        .map_err(|e| Error::ReadVpnConnections(e.to_string()))?;
    let resource_instances: Vec<String> = response
        .vpn_connections
        .into_iter()
        .flatten()
        .map(|vpn_connection| {
            Ok(vpn_connection
                .vpn_connection_id
                .as_ref()
                .ok_or(Error::MissingVpnConnectionId)?
                .clone())
        })
        .collect::<Result<_, Error>>()?;
    resources.insert(resource_type, resource_instances);

    Ok(resources)
}

pub fn list_resource_tags(
    configuration: &Configuration,
) -> Result<HashMap<String, Vec<(String, String)>>, Error> {
    let mut resource_tags: HashMap<String, Vec<(String, String)>> = HashMap::new();

    //get resource tags
    let request = ReadTagsRequest::new();
    let response =
        read_tags(&configuration, Some(request)).map_err(|e| Error::ReadTags(e.to_string()))?;
    for tag in response.tags.into_iter().flatten() {
        let resource_id = tag.resource_id.ok_or(Error::MissingResourceId)?;
        let key = tag.key.ok_or(Error::MissingTagKey)?;
        let value = tag.value.ok_or(Error::MissingTagValue)?;
        let mut updated_tags: Vec<(String, String)> = Vec::new();
        match resource_tags.get(&resource_id) {
            Some(recorded_tags) => {
                updated_tags = recorded_tags.clone();
            }
            None => {}
        };
        updated_tags.push((key, value));
        resource_tags.insert(resource_id, updated_tags);
    }

    Ok(resource_tags)
}
