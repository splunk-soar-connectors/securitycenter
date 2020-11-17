# File: tenablesc_consts.py
# Copyright (c) 2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

IP_HOSTNAME = "ip_hostname"
SCAN_POLICY = "scan_policy_id"
DATETIME_FORMAT = "TZID=UTC:%Y%m%dT%H%M%S"
SCAN_DELAY = 3
PAGE_SIZE = 100

TENABLE_ERR_CODE_UNAVAILABLE = "Error code unavailable"
TENABLE_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
TENABLE_UNICODE_DAMMIT_TYPE_ERROR_MESSAGE = "Error occurred while connecting to the Tenable.sc server. Please check the asset configuration and|or the action parameters."
TENABLE_ERR_INVALID_JSON = 'Error: Invalid JSON format in the "{param}".'
TENABLE_ERR_INVALID_INT = 'Please provide a valid {msg} integer value in the "{param}"'
