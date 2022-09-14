# File: tenablesc_consts.py
#
# Copyright (c) 2017-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
IP_HOSTNAME = "ip_hostname"
SCAN_POLICY = "scan_policy_id"
DATETIME_FORMAT = "TZID=UTC:%Y%m%dT%H%M%S"
REPOSITORY_ID = "repository_id"
CREDENTIAL_ID = "credential_id"
SCAN_DELAY = 3
PAGE_SIZE = 100
INVALID_HOST_CHARS = " !\"'@#$%^&*(){};[]|"

TENABLE_ERR_CODE_UNAVAILABLE = "Error code unavailable"
TENABLE_ERR_MSG_UNAVAILABLE = (
    "Error message unavailable. Please check the asset configuration and|or action parameters."
)
TENABLE_ERR_INVALID_JSON = 'Error: Invalid JSON format in the "{param}".'
TENABLE_ERR_INVALID_INT = 'Please provide a valid {msg} integer value in the "{param}"'
