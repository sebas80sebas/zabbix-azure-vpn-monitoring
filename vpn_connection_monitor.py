#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import sys
import json
import argparse
from datetime import datetime, timedelta, timezone

# ====================================================================
# Obtain an Azure access token using Managed Identity (MSI)
# ====================================================================
def get_token():
    TOKEN_URL = "http://169.254.169.254/metadata/identity/oauth2/token"
    params = {
        "api-version": "2018-02-01",
        "resource": "https://management.azure.com/"
    }
    headers = {"Metadata": "true"}

    try:
        # Call the Azure Instance Metadata Service to get an access token
        response = requests.get(TOKEN_URL, params=params, headers=headers, timeout=5)
        response.raise_for_status()
        return response.json().get("access_token")
    except Exception as e:
        # Return a JSON-formatted error if token retrieval fails
        print(json.dumps({"error": f"Error getting token: {e}"}))
        return None

# ====================================================================
# Query VPN Connection details (API version 2024-01-01)
# ====================================================================
def get_vpn_connection(subscription_id, resource_group, connection_name):
    token = get_token()
    if not token:
        return None, 1  # Token error

    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Network/connections/{connection_name}"
    )
    params = {"api-version": "2024-01-01"}
    headers = {"Authorization": f"Bearer {token}"}

    try:
        # Query VPN connection properties
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json(), 0
    except Exception as e:
        # Return error code 2 if the API call fails
        return {"error": f"Error querying VPN Connection: {e}"}, 2

# ====================================================================
# Query Azure Resource Health for the VPN Connection
# ====================================================================
def get_resource_health(subscription_id, resource_group, connection_name):
    token = get_token()
    if not token:
        return None

    resource_uri = (
        f"/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Network/connections/{connection_name}"
    )
    url = (
        f"https://management.azure.com{resource_uri}"
        f"/providers/Microsoft.ResourceHealth/availabilityStatuses/current"
    )
    params = {"api-version": "2023-07-01"}
    headers = {"Authorization": f"Bearer {token}"}

    try:
        # Retrieve current resource health status
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception:
        # Fail silently to allow fallback using metrics-based health
        return None

# ====================================================================
# Query Azure Monitor metrics for the VPN Connection
# ====================================================================
def get_vpn_connection_metrics(subscription_id, resource_group, connection_name):
    token = get_token()
    if not token:
        return {}

    resource_id = (
        f"/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Network/connections/{connection_name}"
    )
    url = f"https://management.azure.com{resource_id}/providers/microsoft.insights/metrics"

    # Define a 5-minute time window ending now (UTC)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=5)
    timespan = "{}/{}".format(
        start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    params = {
        "api-version": "2018-01-01",
        "timespan": timespan,
        "interval": "PT1M",
        "metricnames": "BitsInPerSecond,BitsOutPerSecond",
        "aggregation": "Average"
    }
    headers = {"Authorization": f"Bearer {token}"}

    try:
        # Retrieve Azure Monitor metrics
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        # Log warning but do not fail execution
        print(json.dumps({"warning": f"Error querying metrics: {e}"}), file=sys.stderr)
        return {}

# ====================================================================
# Parse Azure Monitor metrics and extract latest values
# ====================================================================
def parse_metrics(metrics_data):
    if not metrics_data or "value" not in metrics_data:
        return {}

    parsed_metrics = {}

    for metric in metrics_data.get("value", []):
        metric_name = metric.get("name", {}).get("value")
        timeseries = metric.get("timeseries", [])

        if not timeseries:
            continue

        # Use the most recent available data point (average preferred, total second, maximum as fallback)
        data_points = timeseries[0].get("data", [])
        if data_points:
            latest_value = None
            for point in reversed(data_points):
                if point.get("average") is not None:
                    latest_value = point.get("average")
                    break
                elif point.get("total") is not None:
                    latest_value = point.get("total")
                    break
                elif point.get("maximum") is not None:
                    latest_value = point.get("maximum")
                    break

            if latest_value is not None:
                parsed_metrics[metric_name] = latest_value

    return parsed_metrics

# ====================================================================
# Parse Azure Resource Health status
# ====================================================================
def parse_health_status(health_data):
    if not health_data:
        return None

    properties = health_data.get("properties", {})
    availability_state = properties.get("availabilityState", "Unknown")

    # Map Azure availability states to simplified health states
    health_mapping = {
        "Available": "Connected",
        "Unavailable": "NotConnected",
        "Degraded": "Degraded",
        "Unknown": "Unknown"
    }

    return health_mapping.get(availability_state, "Unknown")

# ====================================================================
# Calculate health status based on connection state and metrics
# ====================================================================
def calculate_health_from_connection(connection_data, metrics):
    if not connection_data:
        return "Unknown"

    props = connection_data.get("properties", {})
    connection_status = props.get("connectionStatus", "Unknown")
    provisioning_state = props.get("provisioningState", "Unknown")

    # Check provisioning state first
    if provisioning_state != "Succeeded":
        return "Provisioning"

    # Map connection status
    status_mapping = {
        "Connected": "Connected",
        "NotConnected": "NotConnected",
        "Connecting": "Connecting",
        "Unknown": "Unknown"
    }

    mapped_status = status_mapping.get(connection_status, "Unknown")

    # If connected, check metrics for potential degradation
    if mapped_status == "Connected" and metrics:
        # Check for low bandwidth (might indicate issues)
        avg_bandwidth = metrics.get("AverageBandwidth", 0)

        # If bandwidth is consistently very low (less than 100 Kbps) and connection
        # shows as connected, it might indicate degradation
        if avg_bandwidth > 0 and avg_bandwidth < 100000:
            return "Degraded"

    return mapped_status

# ====================================================================
# Parse all relevant VPN Connection properties
# ====================================================================
def parse_vpn_connection_data(data):
    if not data or isinstance(data, dict) and data.get("error"):
        return data if isinstance(data, dict) else {}

    props = data.get("properties", {})

    # Parse IPsec policies if present
    ipsec_policies = []
    for policy in props.get("ipsecPolicies", []):
        ipsec_policies.append({
            "saLifeTimeSeconds": policy.get("saLifeTimeSeconds"),
            "saDataSizeKilobytes": policy.get("saDataSizeKilobytes"),
            "ipsecEncryption": policy.get("ipsecEncryption"),
            "ipsecIntegrity": policy.get("ipsecIntegrity"),
            "ikeEncryption": policy.get("ikeEncryption"),
            "ikeIntegrity": policy.get("ikeIntegrity"),
            "dhGroup": policy.get("dhGroup"),
            "pfsGroup": policy.get("pfsGroup")
        })

    # Parse traffic selector policies if present
    traffic_selector_policies = []
    for policy in props.get("trafficSelectorPolicies", []):
        traffic_selector_policies.append({
            "localAddressRanges": policy.get("localAddressRanges", []),
            "remoteAddressRanges": policy.get("remoteAddressRanges", [])
        })

    return {
        "name": data.get("name"),
        "location": data.get("location"),
        "type": data.get("type"),
        "connectionType": props.get("connectionType"),
        "connectionStatus": props.get("connectionStatus"),
        "provisioningState": props.get("provisioningState"),
        "connectionProtocol": props.get("connectionProtocol"),
        "routingWeight": props.get("routingWeight"),
        "dpdTimeoutSeconds": props.get("dpdTimeoutSeconds"),
        "connectionMode": props.get("connectionMode"),
        "sharedKey": "***" if props.get("sharedKey") else None,  # Never expose actual shared key
        "enableBgp": props.get("enableBgp"),
        "usePolicyBasedTrafficSelectors": props.get("usePolicyBasedTrafficSelectors"),
        "useLocalAzureIpAddress": props.get("useLocalAzureIpAddress"),
        "enablePrivateLinkFastPath": props.get("enablePrivateLinkFastPath"),
        "expressRouteGatewayBypass": props.get("expressRouteGatewayBypass"),
        "virtualNetworkGateway1": {
            "id": props.get("virtualNetworkGateway1", {}).get("id")
        },
        "virtualNetworkGateway2": {
            "id": props.get("virtualNetworkGateway2", {}).get("id")
        } if props.get("virtualNetworkGateway2") else None,
        "localNetworkGateway2": {
            "id": props.get("localNetworkGateway2", {}).get("id")
        } if props.get("localNetworkGateway2") else None,
        "peer": {
            "id": props.get("peer", {}).get("id")
        } if props.get("peer") else None,
        "ingressBytesTransferred": props.get("ingressBytesTransferred"),
        "egressBytesTransferred": props.get("egressBytesTransferred"),
        "ipsecPolicies": ipsec_policies,
        "trafficSelectorPolicies": traffic_selector_policies,
        "connectionStatusDetails": props.get("connectionStatusDetails")
    }

# ====================================================================
# Main execution logic
# ====================================================================
def main():
    parser = argparse.ArgumentParser(
        description="VPN Connection monitor: returns JSON with properties, metrics, and connection status."
    )
    parser.add_argument("subscription_id", help="Subscription ID (GUID)")
    parser.add_argument("resource_group", help="Resource Group name")
    parser.add_argument("connection_name", help="VPN Connection name")

    args = parser.parse_args()

    # 1) Retrieve VPN connection information
    raw, rc = get_vpn_connection(
        args.subscription_id,
        args.resource_group,
        args.connection_name
    )

    if rc == 1:
        # Token acquisition error
        print(json.dumps({"error": "Failed to obtain MSI token."}))
        sys.exit(1)
    elif rc == 2 and isinstance(raw, dict) and raw.get("error"):
        print(json.dumps(raw))
        sys.exit(2)

    parsed = parse_vpn_connection_data(raw)

    # 2) Retrieve and parse metrics
    metrics_raw = get_vpn_connection_metrics(
        args.subscription_id,
        args.resource_group,
        args.connection_name
    )
    metrics = parse_metrics(metrics_raw)
    parsed["metrics"] = metrics

    # 3) Determine health status (API first, connection state/metrics as fallback)
    health_raw = get_resource_health(
        args.subscription_id,
        args.resource_group,
        args.connection_name
    )
    health_status_from_api = parse_health_status(health_raw)
    health_status_from_connection = calculate_health_from_connection(raw, metrics)

    parsed["healthStatus"] = (
        health_status_from_api if health_status_from_api else health_status_from_connection
    )

    # Output JSON formatted for Zabbix consumption
    json_output = json.dumps({"data": parsed}, indent=4)
    print(json_output)
    sys.exit(0)

# ====================================================================
# Script entry point
# ====================================================================
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Catch any unexpected errors
        print(json.dumps({"error": f"Unexpected error: {e}"}))
        sys.exit(3)
