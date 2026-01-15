# Azure VPN Connection Monitoring Setup Guide

This guide explains how to set up monitoring for Azure VPN Connections using Zabbix with Python External Script.

## Overview

This setup allows a Zabbix proxy running on an Azure VM to monitor VPN Connections using Python External Script to retrieve metrics, and Azure's Managed Identity for secure authentication, eliminating the need for storing credentials.

## Prerequisites

- Azure VM with Managed Identity enabled
- Zabbix server installed on the VM
- Python 3.8+ with `requests` module
- Azure CLI installed and configured
- Appropriate Azure subscription access

## Step 1: Configure Managed Identity

### 1.1 Verify Managed Identity

First, retrieve your VM's Managed Identity Principal ID:

```bash
VM_IDENTITY=$(az vm show -g <RESOURCE_GROUP> -n <VM_NAME> --query identity.principalId -o tsv)
echo $VM_IDENTITY
```

Expected output format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

### 1.2 Test Managed Identity Token

Verify the VM can obtain authentication tokens:

```bash
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## Step 2: Assign Azure Roles

### 2.1 Get Subscription ID

```bash
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
```

### 2.2 Assign Reader Role

Grant the Managed Identity read access to the VPN Connection:

```bash
az role assignment create \
  --assignee-object-id $VM_IDENTITY \
  --assignee-principal-type ServicePrincipal \
  --role "Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.Network/connections/<CONNECTION_NAME>"
```

### 2.3 Assign Monitoring Reader Role

Grant access to metrics data:

```bash
az role assignment create \
  --assignee-object-id $VM_IDENTITY \
  --assignee-principal-type ServicePrincipal \
  --role "Monitoring Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.Network/connections/<CONNECTION_NAME>"
```

### 2.4 Verify Role Assignments

```bash
az role assignment list \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.Network/connections/<CONNECTION_NAME>" \
  --query "[].{Role:roleDefinitionName, PrincipalId:principalId, PrincipalType:principalType}" \
  -o table
```

Expected output:
```
Role               PrincipalId                           PrincipalType
-----------------  ------------------------------------  ----------------
Reader             xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  ServicePrincipal
Monitoring Reader  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  ServicePrincipal
```

## Step 3: Deploy Monitoring Script

### 3.1 Transfer Script to Zabbix Server

From your management workstation:

```bash
# Linux/Mac
scp vpn_connection_monitor.py <username>@<zabbix-server-ip>:/home/<username>/

# Windows (using PowerShell or Command Prompt with OpenSSH)
scp C:\path\to\vpn_connection_monitor.py <username>@<zabbix-server-ip>:/home/<username>/
```

### 3.2 Move Script to Zabbix Directory

On the Zabbix server:

```bash
sudo mv /home/<username>/vpn_connection_monitor.py /usr/lib/zabbix/externalscripts/
```

### 3.3 Set Permissions

```bash
sudo chmod +x /usr/lib/zabbix/externalscripts/vpn_connection_monitor.py
sudo chown zabbix:zabbix /usr/lib/zabbix/externalscripts/vpn_connection_monitor.py
```

### 3.4 Verify Permissions

```bash
ls -la /usr/lib/zabbix/externalscripts/vpn_connection_monitor.py
```

Expected output:
```
-rwxrwxr-x 1 zabbix zabbix 15420 Jan  13 10:30 /usr/lib/zabbix/externalscripts/vpn_connection_monitor.py
```

## Step 4: Verify Dependencies

### 4.1 Check Python Version

```bash
python3 --version
```

Required: Python 3.8 or higher

### 4.2 Verify Requests Module

```bash
python3 -c "import requests; print('requests OK')"
```

### 4.3 Install Requests (if needed)

**Debian/Ubuntu:**
```bash
sudo apt-get install python3-requests
```

**RHEL/CentOS:**
```bash
sudo yum install python3-requests
```

**Using pip:**
```bash
sudo pip3 install requests
```

## Step 5: Obtain Azure Resource Credentials

Before running the monitoring script, you need to gather three pieces of information from your Azure environment.

### 5.1 Subscription ID

Get your Azure subscription ID:

```bash
az account show --query id -o tsv
```

Example output:
```
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Alternatively, view all subscriptions:

```bash
az account list --query "[].{name:name, id:id, state:state}" -o table
```

### 5.2 Resource Group Name

Identify the resource group where your VPN Connection is located:

```bash
az group list --query "[].name" -o table
```

Example: `MyVPNResourceGroup`

### 5.3 VPN Connection Name

Get the name of your VPN Connection:

```bash
az network vpn-connection list --resource-group <YOUR_RESOURCE_GROUP> --query "[].name" -o table
```

Example: `MyVPNConnection`

### 5.4 Example Parameters

For this guide, the following example placeholders are used:

| Parameter | Placeholder |
|-----------|-------------|
| Subscription ID | `<SUBSCRIPTION_ID>` |
| Resource Group | `<RESOURCE_GROUP>` |
| Connection Name | `<CONNECTION_NAME>` |

## Step 6: Test the Monitoring Script

The script requires three command-line arguments in the following order:

1. Subscription ID
2. Resource Group name
3. VPN Connection name

### 6.1 Script Syntax

```bash
sudo -u zabbix python3 /usr/lib/zabbix/externalscripts/vpn_connection_monitor.py <SUBSCRIPTION_ID> <RESOURCE_GROUP> <CONNECTION_NAME>
```

### 6.2 Run the Script

Using your actual Azure credentials:

```bash
sudo -u zabbix python3 /usr/lib/zabbix/externalscripts/vpn_connection_monitor.py <SUBSCRIPTION_ID> <RESOURCE_GROUP> <CONNECTION_NAME>
```

### Expected Output

```json
{
    "data": {
        "name": "MyVPNConnection",
        "location": "eastus",
        "type": "Microsoft.Network/connections",
        "connectionType": "IPsec",
        "connectionStatus": "Connected",
        "provisioningState": "Succeeded",
        "connectionProtocol": "IKEv2",
        "routingWeight": 0,
        "dpdTimeoutSeconds": 45,
        "connectionMode": "Default",
        "sharedKey": "***",
        "enableBgp": false,
        "usePolicyBasedTrafficSelectors": false,
        "useLocalAzureIpAddress": false,
        "enablePrivateLinkFastPath": false,
        "expressRouteGatewayBypass": false,
        "virtualNetworkGateway1": {
            "id": "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Network/virtualNetworkGateways/vng-vpn-hub-01"
        },
        "virtualNetworkGateway2": null,
        "localNetworkGateway2": {
            "id": "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Network/localNetworkGateways/lng-vpn-gateway"
        },
        "peer": null,
        "ingressBytesTransferred": 1250000000,
        "egressBytesTransferred": 2500000000,
        "ipsecPolicies": [
            {
                "saLifeTimeSeconds": 27000,
                "saDataSizeKilobytes": 102400000,
                "ipsecEncryption": "AES256",
                "ipsecIntegrity": "SHA256",
                "ikeEncryption": "AES256",
                "ikeIntegrity": "SHA256",
                "dhGroup": "DHGroup14",
                "pfsGroup": "PFS2048"
            }
        ],
        "trafficSelectorPolicies": [],
        "connectionStatusDetails": null,
        "metrics": {
            "BitsInPerSecond": 50000000,
            "BitsOutPerSecond": 75000000
        },
        "healthStatus": "Connected"
    }
}
```

**Note**: The output includes comprehensive connection configuration, IPsec policies, real-time metrics, and connection status.

## Monitored Metrics

The script collects the following metrics:

| Metric | Description | Unit |
|--------|-------------|------|
| BitsInPerSecond | Ingress throughput | bits/s |
| BitsOutPerSecond | Egress throughput | bits/s |

**Note**: Additional metrics like `TunnelAverageBandwidth`, `TunnelEgressBytes`, `TunnelIngressBytes`, `TunnelEgressPackets`, `TunnelIngressPackets`, and packet drop counters may be available depending on your VPN gateway configuration.

## Script Features

The `vpn_connection_monitor.py` script provides:

- **Managed Identity Authentication**: Securely authenticates using Azure VM's managed identity (no credentials in code)
- **Comprehensive Connection Data**: Retrieves complete VPN connection properties including type, protocol, and gateway information
- **Real-time Metrics**: Collects performance metrics over a 5-minute window from Azure Monitor
- **Connection Status**: Determines connection health using Azure Resource Health API with fallback to connection state
- **IPsec Policy Information**: Extracts detailed IPsec/IKE configuration
- **JSON Output**: Returns structured JSON output optimized for Zabbix parsing
- **Error Handling**: Provides clear error messages and appropriate exit codes

### Health Status Logic

The script determines health status using the following priority:

1. **Azure Resource Health API** (primary): Maps availability states to connection status
   - `Available` → `Connected`
   - `Degraded` → `Degraded`
   - `Unavailable` → `NotConnected`
   - `Unknown` → `Unknown`

2. **Connection State** (fallback): Uses the connection status from Azure
   - `Connected` → `Connected`
   - `NotConnected` → `NotConnected`
   - `Connecting` → `Connecting`
   - Provisioning state not "Succeeded" → `Provisioning`

3. **Metrics-based Degradation Detection**: If connected, checks for low bandwidth
   - Very low bandwidth (<100 Kbps) while connected → `Degraded`

## Connection Types Supported

The script supports monitoring all Azure VPN connection types:

| Connection Type | Description |
|----------------|-------------|
| **IPsec** | Site-to-Site VPN connection using IPsec/IKE |
| **Vnet2Vnet** | VNet-to-VNet connection between Azure virtual networks |
| **ExpressRoute** | Connection to an ExpressRoute circuit |
| **VPNClient** | Point-to-Site VPN connection |

## Step 7: Configure Zabbix Template

### 7.1 Import the Zabbix Template

The Zabbix template is provided in three formats: XML, JSON, and YAML. Choose the format compatible with your Zabbix version.

#### Import via Web Interface

1. Log in to your Zabbix web interface
2. Navigate to **Configuration** → **Templates**
3. Click **Import** in the top-right corner
4. Click **Choose File** and select one of the template files:
   - `zbx_vpn_template.xml` (recommended for most versions)
   - `zbx_vpn_template.json`
   - `zbx_vpn_template.yaml`
5. Review the import options:
   - Check **Create new** for templates, groups, and items
   - Check **Update existing** if reimporting
6. Click **Import**

#### Verify Import

After import, you should see:
- Template name: **Template Azure VPN**
- Group: **Virtual machines**
- Items: 2 total (1 master item + 1 dependent item)
- Triggers: 2 configured triggers
- Macros: 3 user macros

### 7.2 Template Components

#### Master Item (External Check)

| Property | Value |
|----------|-------|
| **Name** | VPN Connection - Raw Data |
| **Type** | External check |
| **Key** | `vpn_connection_monitor.py["{$AZ_SUBSCRIPTION}","{$AZ_RG}","{$AZ_VPN_CONNECTION}"]` |
| **Update interval** | 1m (default, configurable) |
| **Value type** | Text |
| **Description** | Executes the Python script and retrieves complete VPN connection data in JSON format |

This master item calls the monitoring script with three parameters (subscription ID, resource group, connection name) and stores the raw JSON response.

#### Dependent Items

The dependent item uses JSON path preprocessing to extract specific values from the master item's output:

##### Health Status Item

| Item Name | Key | Type | JSON Path | Description |
|-----------|-----|------|-----------|-------------|
| **VPN Connection - Health Status** | `vpn.healthstatus` | Character | `$.data.healthStatus` | Overall health status: Connected, NotConnected, Degraded, Connecting, or Unknown |

### 7.3 Configured Triggers

The template includes 2 triggers for automated alerting:

#### Warning Priority

| Trigger Name | Expression | Description |
|--------------|------------|-------------|
| **VPN Connection is Degraded** | `{last()}="Degraded"` | Fires when the connection is degraded (connected but with issues) |
| **VPN Connection is Not Connected** | `{last()}="NotConnected"` | Fires when the VPN connection status is NotConnected |

### 7.4 Template Macros

The template uses three user macros that must be configured for each host:

| Macro | Description | Example Value |
|-------|-------------|---------------|
| **{$AZ_SUBSCRIPTION}** | Azure Subscription ID where the VPN connection is located | `12345678-1234-1234-1234-123456789abc` |
| **{$AZ_RG}** | Azure Resource Group name containing the VPN connection | `MyVPNResourceGroup` |
| **{$AZ_VPN_CONNECTION}** | VPN Connection name to monitor | `MyVPNConnection` |

These macros are referenced in the master item's key parameter and are passed as arguments to the monitoring script.

### 7.5 Create a Host for VPN Connection Monitoring

#### 7.5.1 Create New Host

1. Navigate to **Configuration** → **Hosts**
2. Click **Create host** in the top-right corner
3. Configure the host:
   - **Host name**: `Azure VPN - <Connection Name>` (e.g., `Azure VPN - Site to DC`)
   - **Visible name**: Same as host name or a friendly name
   - **Groups**: Select **Virtual machines** (or create a new group like "Azure VPN Connections")
   - **Interfaces**: 
     - Since this uses external scripts, the agent interface is optional
     - You can add a dummy IP (e.g., `127.0.0.1`) or leave it empty
4. Click **Add**

#### 7.5.2 Link Template to Host

1. Go to the newly created host
2. Click the **Templates** tab
3. In the **Link new templates** field, start typing "Azure VPN"
4. Select **Template Azure VPN**
5. Click **Add** (under the template selection)
6. Click **Update** to save

#### 7.5.3 Configure Host Macros

1. On the host configuration page, go to the **Macros** tab
2. You'll see three inherited macros from the template (they appear with `{$...}` notation)
3. Click **Inherited and host macros** to expand the view
4. Configure each macro with your Azure values:

   | Macro | Value |
   |-------|-------|
   | `{$AZ_SUBSCRIPTION}` | Your Azure subscription ID |
   | `{$AZ_RG}` | Your resource group name |
   | `{$AZ_VPN_CONNECTION}` | Your VPN connection name |

   Example:
   ```
   {$AZ_SUBSCRIPTION} = 12345678-abcd-efgh-ijkl-123456789012
   {$AZ_RG} = Production-Network-RG
   {$AZ_VPN_CONNECTION} = VPN-Site-to-DC
   ```

5. Click **Update** to save

### 7.6 Verify Monitoring

#### 7.6.1 Check Latest Data

1. Navigate to **Monitoring** → **Latest data**
2. Filter by your host name
3. You should see both items collecting data
4. The **VPN Connection - Raw Data** item should show the full JSON output
5. The dependent item should show the extracted health status value

#### 7.6.2 Verify Items Are Working

After a few minutes, check that:
- Both items show recent timestamps
- Health status shows expected value ("Connected", "Degraded", etc.)
- Raw data contains complete JSON with connection configuration
- No "Not supported" or error messages

#### 7.6.3 Test Triggers

You can verify triggers are working:
1. Navigate to **Monitoring** → **Problems**
2. Any active issues with the VPN connection will appear here
3. Check trigger expressions in **Configuration** → **Hosts** → [Your Host] → **Triggers**

### 7.7 Monitoring Multiple VPN Connections

To monitor multiple VPN connections:

#### Option 1: Multiple Hosts (Recommended)

Create a separate host for each VPN connection:
1. Follow steps 7.5.1 through 7.5.3 for each connection
2. Use descriptive host names (e.g., `Azure VPN - HQ to Branch1`, `Azure VPN - DR Site`)
3. Configure different macro values for each host

**Benefits:**
- Clear separation of monitoring data
- Individual trigger states per connection
- Easy to disable monitoring for specific connections
- Better for reporting and dashboards
- Maps to Azure Portal view where each connection is a separate resource

#### Option 2: Multiple Items on Single Host

Create multiple instances of items on a single host:
1. Clone the template items manually
2. Modify the keys and master item parameters
3. Create separate macros for each connection (e.g., `{$AZ_VPN_CONNECTION_1}`, `{$AZ_VPN_CONNECTION_2}`)

**Note:** This approach is more complex and not recommended unless you have specific requirements.

### 7.8 Customization Options

#### 7.8.1 Adjust Update Interval

To change how frequently the script runs:
1. Go to **Configuration** → **Hosts** → [Your Host] → **Items**
2. Click on **VPN Connection - Raw Data** (the master item)
3. Modify the **Update interval** field (default: 1m)
4. Recommended intervals:
   - Production VPN: 1 minute
   - Development/testing: 5 minutes
   - Backup connections: 2-3 minutes
5. Click **Update**

**Note:** All dependent items will automatically update when the master item updates.

#### 7.8.2 Add Custom Items

To monitor additional data from the JSON output:
1. Create a new item
2. Set **Type** to **Dependent item**
3. Set **Master item** to `vpn_connection_monitor.py["{$AZ_SUBSCRIPTION}","{$AZ_RG}","{$AZ_VPN_CONNECTION}"]`
4. Add preprocessing step:
   - **Type**: JSONPath
   - **Parameters**: Your desired JSON path
5. Configure remaining item properties (type, units, etc.)

Useful additional items:
- Connection status: `$.data.connectionStatus`
- Connection type: `$.data.connectionType`
- Provisioning state: `$.data.provisioningState`
- Connection protocol: `$.data.connectionProtocol`
- Ingress throughput: `$.data.metrics.BitsInPerSecond`
- Egress throughput: `$.data.metrics.BitsOutPerSecond`
- IPsec encryption: `$.data.ipsecPolicies[0].ipsecEncryption`
- IKE encryption: `$.data.ipsecPolicies[0].ikeEncryption`
- DPD timeout: `$.data.dpdTimeoutSeconds`
- Total ingress bytes: `$.data.ingressBytesTransferred`
- Total egress bytes: `$.data.egressBytesTransferred`

#### 7.8.3 Add Additional Triggers

Create custom triggers for specific monitoring needs:

**Example 1: Provisioning State Alert**
- Create dependent item for provisioning state (JSONPath: `$.data.provisioningState`)
- Expression: `{Template Azure VPN:vpn.provisioningstate.last()}<>"Succeeded"`
- Severity: High
- Description: Alert when provisioning state is not "Succeeded"

**Example 2: Connection Protocol Alert**
- Create dependent item for connection protocol (JSONPath: `$.data.connectionProtocol`)
- Expression: `{Template Azure VPN:vpn.connectionprotocol.last()}<>"IKEv2"`
- Severity: Warning
- Description: Alert when connection is not using IKEv2

**Example 3: Bandwidth Threshold Alert**
- Create dependent item for ingress bits (JSONPath: `$.data.metrics.BitsInPerSecond`)
- Expression: `{Template Azure VPN:vpn.bitsin.last()}>100000000`
- Severity: Warning
- Description: Alert when ingress bandwidth exceeds 100 Mbps

## Troubleshooting

### Script Returns No Data or Errors

If you encounter issues with the script not returning data:

#### 1. Install dos2unix (if transferring from Windows)

Line ending issues from Windows can cause problems:

```bash
sudo apt-get update
sudo apt-get install dos2unix -y
```

#### 2. Convert Line Endings

```bash
sudo dos2unix /usr/lib/zabbix/externalscripts/vpn_connection_monitor.py
```

#### 3. Reset Permissions

```bash
sudo chmod +x /usr/lib/zabbix/externalscripts/vpn_connection_monitor.py
sudo chown zabbix:zabbix /usr/lib/zabbix/externalscripts/vpn_connection_monitor.py
```

#### 4. Test Again

```bash
sudo -u zabbix python3 /usr/lib/zabbix/externalscripts/vpn_connection_monitor.py <SUBSCRIPTION_ID> <RESOURCE_GROUP> <CONNECTION_NAME>
```

### Common Issues

**Issue: "No module named 'requests'"**
- Solution: Install python3-requests package
```bash
sudo apt-get install python3-requests
```

**Issue: "Permission denied"**
- Solution: Verify script has execute permissions and is owned by zabbix user
```bash
ls -la /usr/lib/zabbix/externalscripts/vpn_connection_monitor.py
```

**Issue: "Authentication failed"**
- Solution: Verify Managed Identity is properly configured and has required role assignments
```bash
# Verify Managed Identity
az vm identity show -g <RESOURCE_GROUP> -n <VM_NAME>

# Verify role assignments
az role assignment list --assignee $VM_IDENTITY --all
```

**Issue: "Resource not found"**
- Solution: Verify the VPN connection resource path and parameters
```bash
# List all VPN connections in resource group
az network vpn-connection list -g <RESOURCE_GROUP> --query "[].{name:name, status:connectionStatus}" -o table
```

**Issue: "Connection shows 'NotConnected' but portal shows 'Connected'"**
- Solution: This may be a transient state. Wait 1-2 minutes and check again. The script polls current state which may lag slightly.

**Issue: "Metrics are null or missing"**
- Solution: Some metrics may not be available for all connection types or may require time to populate. This is normal for newly created connections.

**Issue: "Zabbix shows 'Not supported' for items"**
- Solution: Check Zabbix server logs
```bash
sudo tail -f /var/log/zabbix/zabbix_server.log
```
Common causes:
- Script path incorrect in Zabbix item configuration
- Macro values not properly configured
- Script execution timeout (increase timeout in Zabbix configuration)

### VPN-Specific Troubleshooting

**Issue: IPsec tunnel established but no traffic**
- Check: `BitsInPerSecond` and `BitsOutPerSecond` metrics
- Verify: Route tables and network security groups
- Review: `trafficSelectorPolicies` in the JSON output

**Issue: Connection flapping**
- Monitor: `connectionStatus` over time
- Check: DPD timeout settings (`dpdTimeoutSeconds`)
- Review: IPsec/IKE policy mismatches

**Issue: Shared key showing as null**
- Note: This is expected behavior. The script masks the shared key for security (`***`)
- The actual shared key is never exposed in monitoring output

### Debug Mode

To see detailed error messages, run the script with Python's verbose mode:

```bash
sudo -u zabbix python3 -v /usr/lib/zabbix/externalscripts/vpn_connection_monitor.py <SUBSCRIPTION_ID> <RESOURCE_GROUP> <CONNECTION_NAME>
```

### Check Zabbix Logs

View Zabbix server logs for external script errors:

```bash
sudo tail -f /var/log/zabbix/zabbix_server.log | grep vpn_connection
```

## Security Considerations

- **No Credentials Required**: Uses Azure Managed Identity for authentication
- **Least Privilege**: Only Reader and Monitoring Reader roles are assigned
- **Scope Limited**: Permissions are scoped to specific VPN connection resources
- **Secure by Default**: No secrets or keys stored in configuration files
- **Shared Key Protection**: The script masks the VPN shared key in output (shows `***`)

## Integration with Zabbix

The complete integration workflow:

1. **Script Deployment**: Monitor script placed in Zabbix external scripts directory
2. **Template Import**: Zabbix template defining items, triggers, and macros
3. **Host Creation**: Individual hosts created for each VPN connection
4. **Macro Configuration**: Azure credentials configured per host
5. **Data Collection**: Zabbix executes script at defined intervals
6. **Metric Extraction**: Dependent items parse JSON output
7. **Alerting**: Triggers fire based on configured thresholds
8. **Visualization**: Graphs and dashboards display metrics

## Advanced Configuration

### Creating a Comprehensive Dashboard

Build a VPN connection dashboard:

1. Navigate to **Monitoring** → **Dashboards**
2. Create a new dashboard
3. Add widgets for:
   - **Health Status**: Shows current connection health
   - **Connection Details**: Data widget showing key configuration values
   - **Throughput Graph**: Graph showing ingress/egress bandwidth
   - **Problems**: Shows active triggers
   - **Connection History**: Graph showing status changes over time

### Monitoring IPsec Policies

The script returns detailed IPsec/IKE configuration. To create policy-specific monitoring:

1. **Identify policies** in the JSON output under `$.data.ipsecPolicies[]`
2. **Create dependent items** for policy parameters:
   - `$.data.ipsecPolicies[0].ipsecEncryption`
   - `$.data.ipsecPolicies[0].ipsecIntegrity`
   - `$.data.ipsecPolicies[0].ikeEncryption`
   - `$.data.ipsecPolicies[0].ikeIntegrity`
   - `$.data.ipsecPolicies[0].dhGroup`
   - `$.data.ipsecPolicies[0].pfsGroup`
3. **Create triggers** to alert on weak encryption settings

### Integration with Other Monitoring Systems

The script's JSON output can be consumed by other monitoring systems:

- **Prometheus**: Create a Prometheus exporter that calls the script and parses JSON
- **Grafana**: Import data from Zabbix or create direct queries
- **Azure Monitor**: Complement built-in Azure monitoring with custom metrics
- **PagerDuty/Opsgenie**: Configure Zabbix to send alerts to incident management platforms

## Comparison: VPN vs ExpressRoute vs Traffic Manager Monitoring

| Feature | VPN Connection | ExpressRoute | Traffic Manager |
|---------|----------------|--------------|-----------------|
| **Resource Type** | Virtual network gateway connection | Dedicated network circuit | DNS-based load balancer |
| **Connection Type** | IPsec, VNet2VNet, VPNClient | Private/Microsoft/Public peering | Endpoints (Azure/External) |
| **Metrics** | Throughput (bits/s) | Throughput, ARP/BGP availability | QPS, endpoint states |
| **Health Model** | Connection + metrics | Circuit + peering status | Profile + endpoint status |
| **Encryption** | IPsec/IKE policies | No (dedicated line) | N/A (DNS routing) |
| **Routing** | Static or BGP | BGP routing | Traffic routing methods |
| **Scope** | Site-to-site, point-to-site | Regional (dedicated) | Global (multi-region) |
| **Use Case** | Secure internet-based connectivity | High-bandwidth private connectivity | Global load balancing |

## Additional Resources

- [Azure Managed Identity Documentation](https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/)
- [Azure VPN Gateway Monitoring](https://docs.microsoft.com/azure/vpn-gateway/vpn-gateway-howto-setup-alerts-virtual-network-gateway-metric)
- [Azure VPN Gateway Metrics](https://docs.microsoft.com/azure/vpn-gateway/monitor-vpn-gateway)
- [Zabbix External Checks](https://www.zabbix.com/documentation/current/manual/config/items/itemtypes/external)
- [Zabbix Template Documentation](https://www.zabbix.com/documentation/current/manual/config/templates)
- [Zabbix JSON Preprocessing](https://www.zabbix.com/documentation/current/manual/config/items/preprocessing/jsonpath_functionality)

## Best Practices

### Monitoring Strategy

1. **Connection-Level Monitoring**: Start with connection health status
2. **Throughput Monitoring**: Track bandwidth utilization for capacity planning
3. **Policy Monitoring**: Verify IPsec/IKE configuration compliance
4. **Alert Tuning**: Adjust trigger thresholds based on your traffic patterns

### Performance Optimization

1. **Update Interval**: Use 1-2 minute intervals for production, longer for dev/test
2. **History Retention**: Configure appropriate history and trend retention periods
3. **Dependent Items**: Use dependent items to minimize API calls
4. **Batch Monitoring**: Monitor multiple connections with separate hosts

### Maintenance

1. **Regular Testing**: Periodically test the monitoring script manually
2. **Role Verification**: Verify role assignments haven't been removed
3. **Script Updates**: Keep the monitoring script updated
4. **Template Review**: Review and update templates as Azure APIs
