# Tenable.sc

Publisher: Splunk <br>
Connector Version: 2.4.1 <br>
Product Vendor: Tenable <br>
Product Name: Tenable.sc <br>
Minimum Product Version: 6.3.0

This app integrates with Tenable's SecurityCenter to provide endpoint-based investigative actions

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Cisco ISE server. Below are the default
ports used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |

### Configuration variables

This table lists the configuration variables required to operate Tenable.sc. These variables are specified when configuring a Tenable.sc asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | required | string | Tenable.sc instance URL (https://sc_instance.company.com) |
**verify_server_cert** | optional | boolean | Verify server certificate |
**retry_count** | optional | numeric | Maximum attempts to retry api call if database locked errors (Default: 5) |
**retry_wait** | optional | numeric | Delay in seconds between retries (Default: 30) |
**username** | required | string | Username |
**password** | required | password | Password |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity <br>
[scan endpoint](#action-scan-endpoint) - Runs a scan against a specified IP or host <br>
[list vulnerabilities](#action-list-vulnerabilities) - Query Tenable.sc for a list of vulnerabilities associated with an IP or host name or CVEID <br>
[list policies](#action-list-policies) - Lists the scan policies available in Tenable.sc <br>
[list repositories](#action-list-repositories) - Lists the repositories available in Tenable.sc <br>
[update asset](#action-update-asset) - Update existing asset with provided fields or create a new one as a 'static' type <br>
[update group](#action-update-group) - Update existing group with provided fields <br>
[list credentials](#action-list-credentials) - Lists the credentials available in Tenable.sc <br>
[list scans](#action-list-scans) - Lists the scan results in Tenable.sc <br>
[scan information](#action-scan-information) - Gets the information of a scan in Tenable.sc

## action: 'test connectivity'

Validate the asset configuration for connectivity

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'scan endpoint'

Runs a scan against a specified IP or host

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**scan_name** | optional | Title of the Tenable scan | string | |
**ip_hostname** | required | IP/Hostname to scan (comma-separated) | string | `ip` `host name` |
**scan_policy_id** | required | Scan Policy ID of the Tenable scan | numeric | `tenablesc scan policy id` |
**repository_id** | optional | Repository ID of the Tenable scan | numeric | `tenablesc repository id` |
**credential_id** | optional | Credential ID of the Tenable scan | numeric | `tenablesc credential id` |
**report_id** | optional | Report ID of the Tenable scan | numeric | |
**report_source** | optional | Resource from which to fetch report | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.credential_id | numeric | `tenablesc credential id` | |
action_result.parameter.ip_hostname | string | `ip` `host name` | 1.1.1.1 |
action_result.parameter.repository_id | numeric | `tenablesc repository id` | 1 |
action_result.parameter.scan_policy_id | numeric | `tenablesc scan policy id` | 2 |
action_result.data.\*.assets | string | | |
action_result.data.\*.canManage | string | | true |
action_result.data.\*.canUse | string | | true |
action_result.data.\*.classifyMitigatedAge | string | | |
action_result.data.\*.createdTime | string | | 1605111111 |
action_result.data.\*.creator | string | | |
action_result.data.\*.creator.firstname | string | | |
action_result.data.\*.creator.id | string | | 1 |
action_result.data.\*.creator.lastname | string | | |
action_result.data.\*.creator.username | string | `user name` | username |
action_result.data.\*.credentials | string | | |
action_result.data.\*.credentials.\*.id | string | `tenablesc credential id` | 1 |
action_result.data.\*.credentials.\*.name | string | | SSH1 |
action_result.data.\*.description | string | | |
action_result.data.\*.dhcpTracking | string | | |
action_result.data.\*.emailOnFinish | string | | |
action_result.data.\*.emailOnLaunch | string | | |
action_result.data.\*.error_code | string | | |
action_result.data.\*.error_msgaction_result.data.\*.warnings | string | | |
action_result.data.\*.id | string | `tenablesc scan id` | 1 |
action_result.data.\*.ipList | string | `ip` `host name` | 1.1.1.1 |
action_result.data.\*.maxScanTime | string | | unlimited |
action_result.data.\*.modifiedTime | string | | 1605111111 |
action_result.data.\*.name | string | | Scan Launched |
action_result.data.\*.numDependents | string | | |
action_result.data.\*.owner | string | | |
action_result.data.\*.owner.firstname | string | | |
action_result.data.\*.owner.id | string | | 1 |
action_result.data.\*.owner.lastname | string | | |
action_result.data.\*.owner.username | string | `user name` | username |
action_result.data.\*.ownerGroup | string | | |
action_result.data.\*.ownerGroup.description | string | | Test description |
action_result.data.\*.ownerGroup.id | string | | 0 |
action_result.data.\*.ownerGroup.name | string | | Full Access |
action_result.data.\*.plugin | string | | |
action_result.data.\*.plugin.description | string | | |
action_result.data.\*.plugin.id | numeric | | |
action_result.data.\*.plugin.name | string | | |
action_result.data.\*.policy | string | | |
action_result.data.\*.policy.context | string | | |
action_result.data.\*.policy.creator.firstname | string | | |
action_result.data.\*.policy.creator.id | string | | 1 |
action_result.data.\*.policy.creator.lastname | string | | |
action_result.data.\*.policy.creator.username | string | `user name` | username |
action_result.data.\*.policy.description | string | | Test description |
action_result.data.\*.policy.id | string | `tenablesc scan policy id` | 1 |
action_result.data.\*.policy.name | string | | Policy1 |
action_result.data.\*.policy.owner.firstname | string | | |
action_result.data.\*.policy.owner.id | string | | |
action_result.data.\*.policy.owner.lastname | string | | |
action_result.data.\*.policy.owner.username | string | `user name` | username |
action_result.data.\*.policy.ownerGroup.description | string | | Test description |
action_result.data.\*.policy.ownerGroup.id | string | | 0 |
action_result.data.\*.policy.ownerGroup.name | string | | Full Access |
action_result.data.\*.policy.tags | string | | Test tag |
action_result.data.\*.policyPrefs | string | | |
action_result.data.\*.policyPrefs.\*.name | string | | MODE|advanced |
action_result.data.\*.policyPrefs.\*.value | string | | default |
action_result.data.\*.reports | string | | |
action_result.data.\*.repository | string | | |
action_result.data.\*.repository.description | string | | |
action_result.data.\*.repository.id | string | | 1 |
action_result.data.\*.repository.name | string | | TEST REPO |
action_result.data.\*.response | string | | |
action_result.data.\*.rolloverType | string | | template |
action_result.data.\*.scanResultID | string | `tenablesc scan result id` | 1 |
action_result.data.\*.scanningVirtualHosts | string | | false |
action_result.data.\*.schedule | string | | |
action_result.data.\*.schedule.dependent | string | | |
action_result.data.\*.schedule.dependent.description | string | | |
action_result.data.\*.schedule.dependent.id | numeric | | |
action_result.data.\*.schedule.dependent.name | string | | |
action_result.data.\*.schedule.enabled | string | | true |
action_result.data.\*.schedule.id | numeric | | |
action_result.data.\*.schedule.nextRun | numeric | | |
action_result.data.\*.schedule.objectType | numeric | | |
action_result.data.\*.schedule.repeatRule | string | | |
action_result.data.\*.schedule.start | string | | |
action_result.data.\*.schedule.type | string | | now |
action_result.data.\*.status | string | | 0 |
action_result.data.\*.timeoutAction | string | | import |
action_result.data.\*.timestamp | string | | |
action_result.data.\*.type | string | | policy |
action_result.data.\*.zone | string | | |
action_result.data.\*.zone.description | string | | |
action_result.data.\*.zone.id | numeric | | 1 |
action_result.data.\*.zone.name | string | | |
action_result.summary.name | string | | Scan Launched |
action_result.message | string | | Name: Scan Launched |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.parameter.scan_name | string | | |
action_result.parameter.report_id | numeric | | |
action_result.parameter.report_source | string | | |

## action: 'list vulnerabilities'

Query Tenable.sc for a list of vulnerabilities associated with an IP or host name or CVEID

Type: **investigate** <br>
Read only: **True**

If the input IP / host name / CVEID is not available in the server, Action will pass with 0 vulnerability.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** | optional | IP / host name of host to query | string | `ip` `host name` |
**cve_id** | optional | CVEID to query | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.cve_id | string | | |
action_result.parameter.ip_hostname | string | `ip` `host name` | 1.1.1.1 |
action_result.data.\*.endOffset | string | | 100 |
action_result.data.\*.matchingDataElementCount | string | | 1:1:1:1:1:1:1:1 |
action_result.data.\*.results.\*.family.id | string | | 1 |
action_result.data.\*.results.\*.family.name | string | | Family name |
action_result.data.\*.results.\*.family.type | string | | active |
action_result.data.\*.results.\*.hostTotal | string | | 1 |
action_result.data.\*.results.\*.name | string | | Plugin name |
action_result.data.\*.results.\*.pluginID | string | | 1 |
action_result.data.\*.results.\*.severity.description | string | | Test description |
action_result.data.\*.results.\*.severity.id | string | | 3 |
action_result.data.\*.results.\*.severity.name | string | | High |
action_result.data.\*.results.\*.total | string | | 1 |
action_result.data.\*.results.\*.vprContext | string | | |
action_result.data.\*.results.\*.vprScore | string | | |
action_result.data.\*.returnedRecords | numeric | | 60 |
action_result.data.\*.startOffset | string | | 0 |
action_result.data.\*.totalRecords | string | | 60 |
action_result.summary.critical_vulns | numeric | | 10 |
action_result.summary.high_vulns | numeric | | 10 |
action_result.summary.info_vulns | numeric | | 10 |
action_result.summary.low_vulns | numeric | | 10 |
action_result.summary.medium_vulns | numeric | | 10 |
action_result.summary.total_vulnerabilities | numeric | | 60 |
action_result.message | string | | Total vulnerabilities: 11 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list policies'

Lists the scan policies available in Tenable.sc

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.manageable.\*.description | string | | |
action_result.data.\*.manageable.\*.id | string | `tenablesc scan policy id` | 1000001 |
action_result.data.\*.manageable.\*.name | string | | Policy1 |
action_result.data.\*.manageable.\*.status | string | | 0 |
action_result.data.\*.usable.\*.description | string | | |
action_result.data.\*.usable.\*.id | string | `tenablesc scan policy id` | 1000001 |
action_result.data.\*.usable.\*.name | string | | Policy1 |
action_result.data.\*.usable.\*.status | string | | 0 |
action_result.summary | string | | |
action_result.summary.policy_count | numeric | | 25 |
action_result.message | string | | Total policies: 56 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list repositories'

Lists the repositories available in Tenable.sc

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.SCI.description | string | | This Tenable.sc system |
action_result.data.\*.SCI.id | numeric | | 1 |
action_result.data.\*.SCI.name | string | | Local |
action_result.data.\*.dataFormat | string | | IPv4 |
action_result.data.\*.description | string | | Description |
action_result.data.\*.id | numeric | `tenablesc repository id` | 1 |
action_result.data.\*.name | string | | Repository |
action_result.summary | string | | |
action_result.summary.total_repositories | numeric | | 2 |
action_result.message | string | | Total Repositories: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update asset'

Update existing asset with provided fields or create a new one as a 'static' type

Type: **generic** <br>
Read only: **False**

View Tenable.sc API docs for available fields to update.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**asset_name** | required | Name of asset to update | string | |
**update_fields** | required | Fields to use for updating the asset (JSON String) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.asset_name | string | | XX_REPO |
action_result.parameter.update_fields | string | | {"definedIPs": "1.1.1.1"} |
action_result.data.\*.error_code | numeric | | 0 |
action_result.data.\*.error_msg | string | | |
action_result.data.\*.response.canManage | string | | true |
action_result.data.\*.response.canUse | string | | true |
action_result.data.\*.response.context | string | | |
action_result.data.\*.response.createdTime | string | | 1559156157 |
action_result.data.\*.response.creator.firstname | string | | FirstName |
action_result.data.\*.response.creator.id | string | | 148 |
action_result.data.\*.response.creator.lastname | string | | LastName |
action_result.data.\*.response.creator.username | string | `user name` | username |
action_result.data.\*.response.description | string | | Test description |
action_result.data.\*.response.id | string | | 893 |
action_result.data.\*.response.ioFirstSyncTime | string | | |
action_result.data.\*.response.ioLastSyncFailure | string | | |
action_result.data.\*.response.ioLastSyncSuccess | string | | |
action_result.data.\*.response.ioSyncErrorDetails | string | | |
action_result.data.\*.response.ioSyncStatus | string | | Not Synced |
action_result.data.\*.response.ipCount | numeric | | -1 |
action_result.data.\*.response.modifiedTime | string | | 1559157366 |
action_result.data.\*.response.name | string | | XX_REPO |
action_result.data.\*.response.owner.firstname | string | | FirstName |
action_result.data.\*.response.owner.id | string | | 148 |
action_result.data.\*.response.owner.lastname | string | | LastName |
action_result.data.\*.response.owner.username | string | `user name` | username |
action_result.data.\*.response.ownerGroup.description | string | | Test description |
action_result.data.\*.response.ownerGroup.id | string | | 0 |
action_result.data.\*.response.ownerGroup.name | string | | Full Access |
action_result.data.\*.response.repositories.\*.ipCount | string | | -1 |
action_result.data.\*.response.repositories.\*.repository.description | string | | |
action_result.data.\*.response.repositories.\*.repository.id | string | | 1 |
action_result.data.\*.response.repositories.\*.repository.name | string | | TEST_REPO |
action_result.data.\*.response.status | string | | 0 |
action_result.data.\*.response.tags | string | | |
action_result.data.\*.response.targetGroup.description | string | | |
action_result.data.\*.response.targetGroup.id | numeric | | -1 |
action_result.data.\*.response.targetGroup.name | string | | |
action_result.data.\*.response.template.description | string | | |
action_result.data.\*.response.template.id | numeric | | -1 |
action_result.data.\*.response.template.name | string | | |
action_result.data.\*.response.type | string | | static |
action_result.data.\*.response.typeFields.definedDNSNames | string | | abc.com |
action_result.data.\*.response.typeFields.definedIPs | string | `ip` | 1.1.1.1 |
action_result.data.\*.response.typeFields.rules.children.\*.children.\*.filterName | string | | |
action_result.data.\*.response.typeFields.rules.children.\*.children.\*.operator | string | | |
action_result.data.\*.response.typeFields.rules.children.\*.children.\*.pluginIDConstraint | string | | |
action_result.data.\*.response.typeFields.rules.children.\*.children.\*.type | string | | |
action_result.data.\*.response.typeFields.rules.children.\*.children.\*.value | string | | |
action_result.data.\*.response.typeFields.rules.children.\*.filterName | string | | |
action_result.data.\*.response.typeFields.rules.children.\*.operator | string | | |
action_result.data.\*.response.typeFields.rules.children.\*.pluginIDConstraint | string | | |
action_result.data.\*.response.typeFields.rules.children.\*.type | string | | |
action_result.data.\*.response.typeFields.rules.children.\*.value | string | | |
action_result.data.\*.response.typeFields.rules.operator | string | | |
action_result.data.\*.response.typeFields.rules.type | string | | |
action_result.data.\*.timestamp | numeric | | 1559157366 |
action_result.data.\*.type | string | | regular |
action_result.summary | string | | |
action_result.message | string | | Successfully updated asset. |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update group'

Update existing group with provided fields

Type: **generic** <br>
Read only: **False**

View Tenable.sc API docs for available fields to update.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group_name** | required | Name of group to update | string | |
**update_fields** | required | Fields to use for updating the group (JSON String) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.group_name | string | | XX |
action_result.parameter.update_fields | string | | {"assets": [{"id": "893"}]} |
action_result.data.\*.error_code | numeric | | 0 |
action_result.data.\*.error_msg | string | | |
action_result.data.\*.response.assets.\*.description | string | | |
action_result.data.\*.response.assets.\*.id | string | | 893 |
action_result.data.\*.response.assets.\*.name | string | | XX_REPO |
action_result.data.\*.response.createDefaultObjects | string | | |
action_result.data.\*.response.createdTime | string | | 1559161314 |
action_result.data.\*.response.definingAssets.\*.description | string | | All defining ranges of the Group in whose context this Asset is being evaluated. |
action_result.data.\*.response.definingAssets.\*.id | string | | 0 |
action_result.data.\*.response.definingAssets.\*.name | string | | All Defined Assets |
action_result.data.\*.response.description | string | | |
action_result.data.\*.response.id | string | | 64 |
action_result.data.\*.response.modifiedTime | string | | 1559161525 |
action_result.data.\*.response.name | string | | XX |
action_result.data.\*.response.userCount | numeric | | 0 |
action_result.data.\*.timestamp | numeric | | 1559161525 |
action_result.data.\*.type | string | | regular |
action_result.summary | string | | |
action_result.message | string | | Successfully updated group. |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list credentials'

Lists the credentials available in Tenable.sc

Type: **investigate** <br>
Read only: **True**

This action result does not contain any sensitive information like password.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.description | string | | Description |
action_result.data.\*.id | numeric | `tenablesc credential id` | 1 |
action_result.data.\*.name | string | | SSH1 |
action_result.data.\*.type | string | | ssh |
action_result.summary | string | | |
action_result.summary.total_credentials | numeric | | 3 |
action_result.message | string | | Total Credentials: 3 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list scans'

Lists the scan results in Tenable.sc

Type: **investigate** <br>
Read only: **True**

This action result does not contain any sensitive information like password.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**earliest_time** | optional | Number of minutes from now | numeric | |
**latest_time** | optional | Number of minutes from now. Leave blank for current time | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.earliest_time | numeric | | |
action_result.parameter.latest_time | numeric | | |
action_result.data.\*.description | string | | Description |
action_result.data.\*.id | numeric | `tenablesc scan id` | 1 |
action_result.data.\*.name | string | | Server Scan |
action_result.data.\*.status | string | | Completed |
action_result.data.\*.startTime | numeric | | 1746535301 |
action_result.data.\*.finishTime | numeric | | 1746535301 |
action_result.summary | string | | |
action_result.summary.total_scans | numeric | | 3 |
action_result.message | string | | Total Scans: 3 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'scan information'

Gets the information of a scan in Tenable.sc

Type: **investigate** <br>
Read only: **True**

This action result does not contain any sensitive information like password.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**scan_id** | required | ID of the Tenable scan | numeric | `tenablesc scan id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.scan_id | numeric | `tenablesc scan id` | |
action_result.data.\*.description | string | | Description |
action_result.data.\*.id | numeric | `tenablesc scan id` | 1 |
action_result.data.\*.name | string | | Server Scan |
action_result.data.\*.status | string | | Completed |
action_result.data.\*.details | string | | Scan Policy |
action_result.data.\*.importStatus | string | | Finished |
action_result.data.\*.dataFormat | string | | universal |
action_result.data.\*.resultType | string | | active |
action_result.data.\*.running | string | | false |
action_result.data.\*.errorDetails | string | | |
action_result.data.\*.totalIPs | numeric | | 1 |
action_result.data.\*.completedIPs | numeric | | 1 |
action_result.data.\*.scannedIPs | numeric | | 1 |
action_result.data.\*.agentScanUUID | string | | 12345678-9abc-4ef0-9234-56789abcdef0 |
action_result.data.\*.startTime | numeric | | 1746530578 |
action_result.data.\*.finishTime | numeric | | 1746531065 |
action_result.data.\*.scanDuration | numeric | | 487 |
action_result.data.\*.completedChecks | numeric | | 198995 |
action_result.data.\*.totalChecks | numeric | | 198995 |
action_result.data.\*.progress.scanningIPs | string | | 10.0.0.1 |
action_result.data.\*.progress.scannedIPs | string | | 10.0.0.1 |
action_result.data.\*.progress.deadHostIPs | string | | 10.0.0.1 |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
