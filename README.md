[comment]: # "Auto-generated SOAR connector documentation"
# Tenable\.sc

Publisher: Splunk  
Connector Version: 2\.3\.0  
Product Vendor: Tenable  
Product Name: Tenable\.sc  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.3  

This app integrates with Tenable's SecurityCenter to provide endpoint\-based investigative actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2017-2022 Splunk Inc."
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Cisco ISE server. Below are the default
ports used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Tenable\.sc asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Tenable\.sc instance URL \(https\://sc\_instance\.company\.com\)
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**retry\_count** |  optional  | numeric | Maximum attempts to retry api call if database locked errors \(Default\: 5\)
**retry\_wait** |  optional  | numeric | Delay in seconds between retries \(Default\: 30\)
**username** |  required  | string | Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[scan endpoint](#action-scan-endpoint) - Runs a scan against a specified IP or host  
[list vulnerabilities](#action-list-vulnerabilities) - Query Tenable\.sc for a list of vulnerabilities associated with an IP or host name or CVEID  
[list policies](#action-list-policies) - Lists the scan policies available in Tenable\.sc  
[list repositories](#action-list-repositories) - Lists the repositories available in Tenable\.sc  
[update asset](#action-update-asset) - Update existing asset with provided fields or create a new one as a 'static' type  
[update group](#action-update-group) - Update existing group with provided fields  
[list credentials](#action-list-credentials) - Lists the credentials available in Tenable\.sc  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'scan endpoint'
Runs a scan against a specified IP or host

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | IP/Hostname to scan \(comma\-separated\) | string |  `ip`  `host name` 
**scan\_policy\_id** |  required  | Tenable\.sc Scan Policy ID to use | numeric |  `tenablesc scan policy id` 
**repository\_id** |  optional  | Tenable\.sc repository ID to use \(Default\: 1\) | numeric |  `tenablesc repository id` 
**credential\_id** |  optional  | Tenable\.sc credential ID to use | numeric |  `tenablesc credential id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.credential\_id | numeric |  `tenablesc credential id` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.repository\_id | numeric |  `tenablesc repository id` 
action\_result\.parameter\.scan\_policy\_id | numeric |  `tenablesc scan policy id` 
action\_result\.data\.\*\.assets | string | 
action\_result\.data\.\*\.canManage | string | 
action\_result\.data\.\*\.canUse | string | 
action\_result\.data\.\*\.classifyMitigatedAge | string | 
action\_result\.data\.\*\.createdTime | string | 
action\_result\.data\.\*\.creator | string | 
action\_result\.data\.\*\.creator\.firstname | string | 
action\_result\.data\.\*\.creator\.id | string | 
action\_result\.data\.\*\.creator\.lastname | string | 
action\_result\.data\.\*\.creator\.username | string |  `user name` 
action\_result\.data\.\*\.credentials | string | 
action\_result\.data\.\*\.credentials\.\*\.id | string |  `tenablesc credential id` 
action\_result\.data\.\*\.credentials\.\*\.name | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.dhcpTracking | string | 
action\_result\.data\.\*\.emailOnFinish | string | 
action\_result\.data\.\*\.emailOnLaunch | string | 
action\_result\.data\.\*\.error\_code | string | 
action\_result\.data\.\*\.error\_msgaction\_result\.data\.\*\.warnings | string | 
action\_result\.data\.\*\.id | string |  `tenablesc scan id` 
action\_result\.data\.\*\.ipList | string |  `ip`  `host name` 
action\_result\.data\.\*\.maxScanTime | string | 
action\_result\.data\.\*\.modifiedTime | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.numDependents | string | 
action\_result\.data\.\*\.owner | string | 
action\_result\.data\.\*\.owner\.firstname | string | 
action\_result\.data\.\*\.owner\.id | string | 
action\_result\.data\.\*\.owner\.lastname | string | 
action\_result\.data\.\*\.owner\.username | string |  `user name` 
action\_result\.data\.\*\.ownerGroup | string | 
action\_result\.data\.\*\.ownerGroup\.description | string | 
action\_result\.data\.\*\.ownerGroup\.id | string | 
action\_result\.data\.\*\.ownerGroup\.name | string | 
action\_result\.data\.\*\.plugin | string | 
action\_result\.data\.\*\.plugin\.description | string | 
action\_result\.data\.\*\.plugin\.id | numeric | 
action\_result\.data\.\*\.plugin\.name | string | 
action\_result\.data\.\*\.policy | string | 
action\_result\.data\.\*\.policy\.context | string | 
action\_result\.data\.\*\.policy\.creator\.firstname | string | 
action\_result\.data\.\*\.policy\.creator\.id | string | 
action\_result\.data\.\*\.policy\.creator\.lastname | string | 
action\_result\.data\.\*\.policy\.creator\.username | string |  `user name` 
action\_result\.data\.\*\.policy\.description | string | 
action\_result\.data\.\*\.policy\.id | string |  `tenablesc scan policy id` 
action\_result\.data\.\*\.policy\.name | string | 
action\_result\.data\.\*\.policy\.owner\.firstname | string | 
action\_result\.data\.\*\.policy\.owner\.id | string | 
action\_result\.data\.\*\.policy\.owner\.lastname | string | 
action\_result\.data\.\*\.policy\.owner\.username | string |  `user name` 
action\_result\.data\.\*\.policy\.ownerGroup\.description | string | 
action\_result\.data\.\*\.policy\.ownerGroup\.id | string | 
action\_result\.data\.\*\.policy\.ownerGroup\.name | string | 
action\_result\.data\.\*\.policy\.tags | string | 
action\_result\.data\.\*\.policyPrefs | string | 
action\_result\.data\.\*\.policyPrefs\.\*\.name | string | 
action\_result\.data\.\*\.policyPrefs\.\*\.value | string | 
action\_result\.data\.\*\.reports | string | 
action\_result\.data\.\*\.repository | string | 
action\_result\.data\.\*\.repository\.description | string | 
action\_result\.data\.\*\.repository\.id | string | 
action\_result\.data\.\*\.repository\.name | string | 
action\_result\.data\.\*\.response | string | 
action\_result\.data\.\*\.rolloverType | string | 
action\_result\.data\.\*\.scanResultID | string |  `tenablesc scan result id` 
action\_result\.data\.\*\.scanningVirtualHosts | string | 
action\_result\.data\.\*\.schedule | string | 
action\_result\.data\.\*\.schedule\.dependent | string | 
action\_result\.data\.\*\.schedule\.dependent\.description | string | 
action\_result\.data\.\*\.schedule\.dependent\.id | numeric | 
action\_result\.data\.\*\.schedule\.dependent\.name | string | 
action\_result\.data\.\*\.schedule\.enabled | string | 
action\_result\.data\.\*\.schedule\.id | numeric | 
action\_result\.data\.\*\.schedule\.nextRun | numeric | 
action\_result\.data\.\*\.schedule\.objectType | numeric | 
action\_result\.data\.\*\.schedule\.repeatRule | string | 
action\_result\.data\.\*\.schedule\.start | string | 
action\_result\.data\.\*\.schedule\.type | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.timeoutAction | string | 
action\_result\.data\.\*\.timestamp | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.zone | string | 
action\_result\.data\.\*\.zone\.description | string | 
action\_result\.data\.\*\.zone\.id | numeric | 
action\_result\.data\.\*\.zone\.name | string | 
action\_result\.summary\.name | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list vulnerabilities'
Query Tenable\.sc for a list of vulnerabilities associated with an IP or host name or CVEID

Type: **investigate**  
Read only: **True**

If the input IP / host name / CVEID is not available in the server, Action will pass with 0 vulnerability\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP / host name of host to query | string |  `ip`  `host name` 
**cve\_id** |  optional  | CVEID to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.cve\_id | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data\.\*\.endOffset | string | 
action\_result\.data\.\*\.matchingDataElementCount | string | 
action\_result\.data\.\*\.results\.\*\.family\.id | string | 
action\_result\.data\.\*\.results\.\*\.family\.name | string | 
action\_result\.data\.\*\.results\.\*\.family\.type | string | 
action\_result\.data\.\*\.results\.\*\.hostTotal | string | 
action\_result\.data\.\*\.results\.\*\.name | string | 
action\_result\.data\.\*\.results\.\*\.pluginID | string | 
action\_result\.data\.\*\.results\.\*\.severity\.description | string | 
action\_result\.data\.\*\.results\.\*\.severity\.id | string | 
action\_result\.data\.\*\.results\.\*\.severity\.name | string | 
action\_result\.data\.\*\.results\.\*\.total | string | 
action\_result\.data\.\*\.results\.\*\.vprContext | string | 
action\_result\.data\.\*\.results\.\*\.vprScore | string | 
action\_result\.data\.\*\.returnedRecords | numeric | 
action\_result\.data\.\*\.startOffset | string | 
action\_result\.data\.\*\.totalRecords | string | 
action\_result\.summary\.critical\_vulns | numeric | 
action\_result\.summary\.high\_vulns | numeric | 
action\_result\.summary\.info\_vulns | numeric | 
action\_result\.summary\.low\_vulns | numeric | 
action\_result\.summary\.medium\_vulns | numeric | 
action\_result\.summary\.total\_vulnerabilities | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list policies'
Lists the scan policies available in Tenable\.sc

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.manageable\.\*\.description | string | 
action\_result\.data\.\*\.manageable\.\*\.id | string |  `tenablesc scan policy id` 
action\_result\.data\.\*\.manageable\.\*\.name | string | 
action\_result\.data\.\*\.manageable\.\*\.status | string | 
action\_result\.data\.\*\.usable\.\*\.description | string | 
action\_result\.data\.\*\.usable\.\*\.id | string |  `tenablesc scan policy id` 
action\_result\.data\.\*\.usable\.\*\.name | string | 
action\_result\.data\.\*\.usable\.\*\.status | string | 
action\_result\.summary | string | 
action\_result\.summary\.policy\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list repositories'
Lists the repositories available in Tenable\.sc

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.SCI\.description | string | 
action\_result\.data\.\*\.SCI\.id | numeric | 
action\_result\.data\.\*\.SCI\.name | string | 
action\_result\.data\.\*\.dataFormat | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | numeric |  `tenablesc repository id` 
action\_result\.data\.\*\.name | string | 
action\_result\.summary | string | 
action\_result\.summary\.total\_repositories | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update asset'
Update existing asset with provided fields or create a new one as a 'static' type

Type: **generic**  
Read only: **False**

View Tenable\.sc API docs for available fields to update\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**asset\_name** |  required  | Name of asset to update | string | 
**update\_fields** |  required  | Fields to use for updating the asset \(JSON String\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.asset\_name | string | 
action\_result\.parameter\.update\_fields | string | 
action\_result\.data\.\*\.error\_code | numeric | 
action\_result\.data\.\*\.error\_msg | string | 
action\_result\.data\.\*\.response\.canManage | string | 
action\_result\.data\.\*\.response\.canUse | string | 
action\_result\.data\.\*\.response\.context | string | 
action\_result\.data\.\*\.response\.createdTime | string | 
action\_result\.data\.\*\.response\.creator\.firstname | string | 
action\_result\.data\.\*\.response\.creator\.id | string | 
action\_result\.data\.\*\.response\.creator\.lastname | string | 
action\_result\.data\.\*\.response\.creator\.username | string |  `user name` 
action\_result\.data\.\*\.response\.description | string | 
action\_result\.data\.\*\.response\.id | string | 
action\_result\.data\.\*\.response\.ioFirstSyncTime | string | 
action\_result\.data\.\*\.response\.ioLastSyncFailure | string | 
action\_result\.data\.\*\.response\.ioLastSyncSuccess | string | 
action\_result\.data\.\*\.response\.ioSyncErrorDetails | string | 
action\_result\.data\.\*\.response\.ioSyncStatus | string | 
action\_result\.data\.\*\.response\.ipCount | numeric | 
action\_result\.data\.\*\.response\.modifiedTime | string | 
action\_result\.data\.\*\.response\.name | string | 
action\_result\.data\.\*\.response\.owner\.firstname | string | 
action\_result\.data\.\*\.response\.owner\.id | string | 
action\_result\.data\.\*\.response\.owner\.lastname | string | 
action\_result\.data\.\*\.response\.owner\.username | string |  `user name` 
action\_result\.data\.\*\.response\.ownerGroup\.description | string | 
action\_result\.data\.\*\.response\.ownerGroup\.id | string | 
action\_result\.data\.\*\.response\.ownerGroup\.name | string | 
action\_result\.data\.\*\.response\.repositories\.\*\.ipCount | string | 
action\_result\.data\.\*\.response\.repositories\.\*\.repository\.description | string | 
action\_result\.data\.\*\.response\.repositories\.\*\.repository\.id | string | 
action\_result\.data\.\*\.response\.repositories\.\*\.repository\.name | string | 
action\_result\.data\.\*\.response\.status | string | 
action\_result\.data\.\*\.response\.tags | string | 
action\_result\.data\.\*\.response\.targetGroup\.description | string | 
action\_result\.data\.\*\.response\.targetGroup\.id | numeric | 
action\_result\.data\.\*\.response\.targetGroup\.name | string | 
action\_result\.data\.\*\.response\.template\.description | string | 
action\_result\.data\.\*\.response\.template\.id | numeric | 
action\_result\.data\.\*\.response\.template\.name | string | 
action\_result\.data\.\*\.response\.type | string | 
action\_result\.data\.\*\.response\.typeFields\.definedDNSNames | string | 
action\_result\.data\.\*\.response\.typeFields\.definedIPs | string |  `ip` 
action\_result\.data\.\*\.response\.typeFields\.rules\.children\.\*\.children\.\*\.filterName | string | 
action\_result\.data\.\*\.response\.typeFields\.rules\.children\.\*\.children\.\*\.operator | string | 
action\_result\.data\.\*\.response\.typeFields\.rules\.children\.\*\.children\.\*\.pluginIDConstraint | string | 
action\_result\.data\.\*\.response\.typeFields\.rules\.children\.\*\.children\.\*\.type | string | 
action\_result\.data\.\*\.response\.typeFields\.rules\.children\.\*\.children\.\*\.value | string | 
action\_result\.data\.\*\.response\.typeFields\.rules\.children\.\*\.filterName | string | 
action\_result\.data\.\*\.response\.typeFields\.rules\.children\.\*\.operator | string | 
action\_result\.data\.\*\.response\.typeFields\.rules\.children\.\*\.pluginIDConstraint | string | 
action\_result\.data\.\*\.response\.typeFields\.rules\.children\.\*\.type | string | 
action\_result\.data\.\*\.response\.typeFields\.rules\.children\.\*\.value | string | 
action\_result\.data\.\*\.response\.typeFields\.rules\.operator | string | 
action\_result\.data\.\*\.response\.typeFields\.rules\.type | string | 
action\_result\.data\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update group'
Update existing group with provided fields

Type: **generic**  
Read only: **False**

View Tenable\.sc API docs for available fields to update\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_name** |  required  | Name of group to update | string | 
**update\_fields** |  required  | Fields to use for updating the group \(JSON String\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.group\_name | string | 
action\_result\.parameter\.update\_fields | string | 
action\_result\.data\.\*\.error\_code | numeric | 
action\_result\.data\.\*\.error\_msg | string | 
action\_result\.data\.\*\.response\.assets\.\*\.description | string | 
action\_result\.data\.\*\.response\.assets\.\*\.id | string | 
action\_result\.data\.\*\.response\.assets\.\*\.name | string | 
action\_result\.data\.\*\.response\.createDefaultObjects | string | 
action\_result\.data\.\*\.response\.createdTime | string | 
action\_result\.data\.\*\.response\.definingAssets\.\*\.description | string | 
action\_result\.data\.\*\.response\.definingAssets\.\*\.id | string | 
action\_result\.data\.\*\.response\.definingAssets\.\*\.name | string | 
action\_result\.data\.\*\.response\.description | string | 
action\_result\.data\.\*\.response\.id | string | 
action\_result\.data\.\*\.response\.modifiedTime | string | 
action\_result\.data\.\*\.response\.name | string | 
action\_result\.data\.\*\.response\.userCount | numeric | 
action\_result\.data\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list credentials'
Lists the credentials available in Tenable\.sc

Type: **investigate**  
Read only: **True**

This action result does not contain any sensitive information like password\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | numeric |  `tenablesc credential id` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary | string | 
action\_result\.summary\.total\_credentials | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 