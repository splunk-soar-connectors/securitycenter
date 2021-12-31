# File: tenablesc_connector.py
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
#
#
# Phantom App imports
import datetime
import json
import sys
import time

import phantom.app as phantom
import phantom.utils as ph_utils
# Imports local to this App
import requests
from bs4 import BeautifulSoup, UnicodeDammit
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from tenablesc_consts import *


class SecurityCenterConnector(BaseConnector):
    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"
    ACTION_ID_SCAN_ENDPOINT = "scan_endpoint"
    ACTION_ID_LIST_SCAN_POLICIES = "list_policies"
    ACTION_ID_GET_IP_VULNERABILITIES = "list_vulnerabilities"
    ACTION_ID_UPDATE_ASSET = "update_asset"
    ACTION_ID_UPDATE_GROUP = "update_group"
    ACTION_ID_LIST_REPOSITORY = "list_repositories"

    def __init__(self):

        # Call the BaseConnectors init first
        super(SecurityCenterConnector, self).__init__()
        self._verify = None
        self._good_token = None
        self._rest_url = None
        self._retry_count = None
        self._retry_wait = None

    def _handle_py_ver_compat_for_input_str(self, input_str, always_encode=False):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :param always_encode: Used if the string needs to be encoded for python 3
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and (self._python_version == 2 or always_encode):
                input_str = UnicodeDammit(input_str).unicode_markup.encode("utf-8")
        except Exception as ex:
            self.debug_print(ex)
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = TENABLE_ERR_CODE_UNAVAILABLE
        error_msg = TENABLE_ERR_MSG_UNAVAILABLE

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = TENABLE_ERR_CODE_UNAVAILABLE
                    error_msg = e.args[0]
            else:
                error_code = TENABLE_ERR_CODE_UNAVAILABLE
                error_msg = TENABLE_ERR_MSG_UNAVAILABLE
        except Exception as ex:
            self.debug_print(ex)
            error_code = TENABLE_ERR_CODE_UNAVAILABLE
            error_msg = TENABLE_ERR_MSG_UNAVAILABLE

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TENABLE_UNICODE_DAMMIT_TYPE_ERR_MESSAGE
        except Exception as ex:
            self.debug_print(ex)
            error_msg = TENABLE_ERR_MSG_UNAVAILABLE

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return (
                        action_result.set_status(phantom.APP_ERROR, TENABLE_ERR_INVALID_INT.format(msg="", param=key)),
                        None,
                    )

                parameter = int(parameter)
            except Exception as ex:
                self.debug_print(ex)
                return (
                    action_result.set_status(phantom.APP_ERROR, TENABLE_ERR_INVALID_INT.format(msg="", param=key)),
                    None,
                )

            if parameter < 0:
                return (
                    action_result.set_status(
                        phantom.APP_ERROR, TENABLE_ERR_INVALID_INT.format(msg="non-negative", param=key)
                    ),
                    None,
                )
            if not allow_zero and parameter == 0:
                return (
                    action_result.set_status(
                        phantom.APP_ERROR, TENABLE_ERR_INVALID_INT.format(msg="non-zero positive", param=key)
                    ),
                    None,
                )

        return phantom.APP_SUCCESS, parameter

    def _get_token(self):

        config = self.get_config()

        rjson = {}
        error_msg = None
        for retry in range(1, self._retry_count + 1):

            self._session = requests.Session()  # nosemgrep
            self._session.headers = {"Content-type": "application/json", "accept": "application/json"}
            auth_data = {"username": config["username"], "password": config["password"]}

            if retry > 1:
                self.save_progress("Failed.")
                self.save_progress("Waiting for {} seconds until retry".format(self._retry_wait))
                time.sleep(self._retry_wait)

            self.save_progress("Getting token for session...; try #{}".format(retry))
            try:
                r = self._session.post(
                    "{}{}".format(self._rest_url, "/rest/token"), json=auth_data, verify=self._verify
                )  # nosemgrep
                self.save_progress("Request Completed")

            except requests.exceptions.InvalidSchema:
                error_msg = "Error Connecting to server. No Connection adapter were found for %s" % (self._rest_url)
                return self.set_status(phantom.APP_ERROR, error_msg)
            except requests.exceptions.InvalidURL:
                error_msg = "Error connecting to server. Invalid url %s" % (self._rest_url)
                return self.set_status(phantom.APP_ERROR, error_msg)
            except Exception as e:
                self.save_progress("Request Exception")
                error_msg = "Error: connection error with server; {}".format(self._get_error_message_from_exception(e))
                self.save_progress(error_msg)
                continue

            if not r:
                error_msg = "Error: no response from server"
                self.save_progress(error_msg)
                continue

            rjson = {}
            try:
                rjson = r.json()
                # print(json.dumps(rjson, indent=4))

            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                self.debug_print("Exception: {}".format(error_msg))

            if len(rjson) == 0:
                error_msg = "Error: response not json compliant"
                self.save_progress(error_msg)
                continue

            if rjson.get("error_code"):
                error_msg = "Error: error code {}: {}".format(
                    rjson.get("error_code"),
                    self._handle_py_ver_compat_for_input_str(rjson.get("error_msg").replace("\n", " ").strip()),
                )
                self.save_progress(error_msg)
                continue

            token = rjson.get("response", {})
            token = token.get("token", None)
            if not isinstance(token, int):
                error_msg = "Error: token is not numeric"
                self.save_progress(error_msg)
                continue

            self._session.headers.update({"X-SecurityCenter": str(token)})
            self._good_token = True
            return phantom.APP_SUCCESS

        if rjson.get("error_code"):
            error_msg = "Error: error code {}: {}".format(
                rjson.get("error_code"),
                self._handle_py_ver_compat_for_input_str(rjson.get("error_msg").replace("\n", " ").strip()),
            )
            self.save_progress(error_msg)

        return self.set_status(
            phantom.APP_ERROR, "Error: Exceeded number of retries to get token; {}".format(error_msg)
        )

    def initialize(self):

        self._good_token = False

        config = self.get_config()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(
                phantom.APP_ERROR, "Error occurred while fetching the Phantom server's Python major version"
            )

        self._verify = config["verify_server_cert"]
        self._rest_url = self._handle_py_ver_compat_for_input_str(config["base_url"].rstrip("/"))

        ret_val, self._retry_count = self._validate_integer(self, config.get("retry_count", 5), "Maximum attempts")
        if phantom.is_fail(ret_val):
            return self.get_status()

        ret_val, self._retry_wait = self._validate_integer(self, config.get("retry_wait", 30), "Delay")
        if phantom.is_fail(ret_val):
            return self.get_status()

        status = self._get_token()
        if phantom.is_fail(status):
            self.save_progress(self.get_status_message())
            return self.set_status(phantom.APP_ERROR, "Returning error in initialize")

        return phantom.APP_SUCCESS

    def finalize(self):

        # Logout
        ret_val = phantom.APP_SUCCESS
        if self._good_token:
            ret_val, resp = self._make_rest_call("/token", self, method="delete")
        return ret_val

    def _process_html_response(self, response, action_result):

        # An html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception as ex:
            self.debug_print(ex)
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, self._handle_py_ver_compat_for_input_str(error_text)
        )

        message = message.replace("{", "{{").replace("}", "}}")

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON", error_msg), None

        if 200 <= r.status_code < 205:
            return phantom.APP_SUCCESS, resp_json

        action_result.add_data(resp_json)
        message = self._handle_py_ver_compat_for_input_str(r.text.replace("{", "{{").replace("}", "}}"))
        return (
            action_result.set_status(
                phantom.APP_ERROR,
                "Error from server, Status Code: {0} data returned: {1}".format(r.status_code, message),
            ),
            resp_json,
        )

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, "add_debug_data"):
            if r is not None:
                action_result.add_debug_data({"r_text": r.text})
                action_result.add_debug_data({"r_headers": r.headers})
                action_result.add_debug_data({"r_status_code": r.status_code})
            else:
                action_result.add_debug_data({"r_text": "r is None"})

        # There are just too many differences in the response to handle all of them in the same function
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not an html or json, handle if it is a successful empty response
        # if (200 <= r.status_code < 205) and (not r.text):
        #   return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, self._handle_py_ver_compat_for_input_str(r.text.replace("{", "{{").replace("}", "}}"))
        )

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _make_rest_call(self, endpoint, action_result, params={}, json={}, method="get"):

        url = "{0}/rest{1}".format(self._rest_url, endpoint)

        try:
            request_func = getattr(self._session, method)
        except AttributeError:
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, "Unsupported method: {0}".format(method)), None
        except Exception as e:
            # Set the action_result status to error, the handler function will most probably return as is
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Handled exception: {0}".format(error_msg)), None

        error_msg = None
        for retry in range(1, self._retry_count + 1):

            if retry > 1:
                self.save_progress("Failed.")
                self.save_progress("Waiting for {} seconds until retry".format(self._retry_wait))
                time.sleep(self._retry_wait)

            self.save_progress("Making REST call...; try #{}".format(retry))
            r = None
            try:
                r = request_func(url, params=params, json=json, verify=self._verify)  # nosemgrep
                self.save_progress("Request Completed")

            except requests.exceptions.InvalidSchema:
                error_msg = "Error Connecting to server. No Connection adapter were found for %s" % (url)
                return action_result.set_status(phantom.APP_ERROR, error_msg)
            except requests.exceptions.InvalidURL:
                error_msg = "Error connecting to server. Invalid url %s" % (url)
                return action_result.set_status(phantom.APP_ERROR, error_msg)
            except Exception as e:
                self.save_progress("Request Exception")
                error_msg = "Error: connection error with server; {}".format(self._get_error_message_from_exception(e))
                self.save_progress(error_msg)
                continue

            if r is None:
                error_msg = "Error: no response from server"
                self.save_progress(error_msg)
                continue

            rjson = {}
            try:
                rjson = r.json()

            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                self.debug_print("Exception: {}".format(error_msg))

            if len(rjson) == 0:
                error_msg = "Error: response not json compliant"
                self.save_progress(error_msg)
                continue

            if rjson.get("error_code"):
                error_msg = "Error: error code {}: {}".format(
                    rjson.get("error_code"),
                    self._handle_py_ver_compat_for_input_str(rjson.get("error_msg").replace("\n", " ").strip()),
                )
                self.send_progress(error_msg)
                continue

            return self._process_response(r, action_result)

        self.save_progress("Error: Failed to make REST call; {}".format(error_msg))
        return action_result.set_status(phantom.APP_ERROR, "REST API to server failed: {}".format(error_msg)), None

    def load_dirty_json(self, dirty_json):
        import re

        regex_replace = [
            (r"([ \{,:\[])(u)?'([^']+)'", r'\1"\3"'),
            (r" False([, \}\]])", r" false\1"),
            (r" True([, \}\]])", r" true\1"),
        ]
        for r, s in regex_replace:
            dirty_json = re.sub(r, s, dirty_json)
        clean_json = json.loads(dirty_json, strict=False)

        return clean_json

    def _test_connectivity(self):

        self.save_progress("Checking connectivity to your Tenable.sc instance...")
        ret_val, resp_json = self._make_rest_call("/user", self)
        if phantom.is_fail(ret_val):
            self.append_to_message("Test connectivity failed")
            return self.get_status()
        else:
            return self.set_status_save_progress(phantom.APP_SUCCESS, "Connectivity to Tenable.sc was successful.")

    def _scan_endpoint(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # target to scan
        ip_hostname = self._handle_py_ver_compat_for_input_str(param[IP_HOSTNAME])

        # Clean up ip hostname
        ip_hostname = [x.strip() for x in ip_hostname.split(",")]
        ip_hostname = list(filter(None, ip_hostname))
        ip_hostname = ",".join(ip_hostname)
        ip_hostname = ip_hostname.replace("https://", "")
        ip_hostname = ip_hostname.replace("http://", "")

        try:
            if not phantom.is_hostname(ip_hostname) and not phantom.is_ip(ip_hostname):
                return action_result.set_status(phantom.APP_ERROR, "Invalid IP or Hostname supplied to scan endpoint.")
        except Exception as ex:
            self.debug_print(ex)
            return action_result.set_status(phantom.APP_ERROR, "Invalid IP or Hostname supplied to scan endpoint.")

        ret_val, scan_policy_id = self._validate_integer(action_result, param[SCAN_POLICY], "Scan policy ID")
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        ret_val, scan_repository_id = self._validate_integer(
            action_result, param.get(REPOSITORY_ID, 1), "respository_id"
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if len(str(scan_policy_id)) > 10:
            return action_result.set_status(phantom.APP_ERROR, "Invalid Scan policy ID. Please run 'list policies' to get policy IDs.")

        # Calculate scan start time with a defined delay
        scan_start = datetime.datetime.utcnow() + datetime.timedelta(minutes=SCAN_DELAY)
        scan_start = scan_start.strftime(DATETIME_FORMAT)
        # can probably remove some of these options
        scan_data = {
            "name": "Scan Launched from Phantom",
            "repository": {"id": scan_repository_id},
            "schedule": {"start": scan_start, "repeatRule": "FREQ=NOW;INTERVAL=1", "type": "now"},
            "reports": [],
            "type": "policy",
            "policy": {"id": scan_policy_id},
            "zone": {"id": -1},
            "ipList": str(ip_hostname),
            "credentials": [],
            "maxScanTime": "unlimited",
        }

        ret_val, resp_json = self._make_rest_call("/scan", action_result, json=scan_data, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json["response"])
        action_result.update_summary({"name": resp_json["response"]["name"]})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_vulnerabilities(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        list_vuln_host = self._handle_py_ver_compat_for_input_str(param.get(IP_HOSTNAME))
        if list_vuln_host and not ph_utils.is_ip(list_vuln_host):
            if len(list_vuln_host) > 255 or set(" !\"'@#$%^&*(){};[]|").intersection(list_vuln_host):
                return action_result.set_status(
                    phantom.APP_ERROR, "Invalid IP or Hostname supplied to list vulnerabilities"
                )

        cve_id = self._handle_py_ver_compat_for_input_str(param.get("cve_id"))

        if not cve_id and not list_vuln_host:
            return action_result.set_status(phantom.APP_ERROR, "Please provide either IP address/Hostname or CVE ID")

        filters = list()
        if list_vuln_host:
            if phantom.is_ip(list_vuln_host) is True:
                filters.append(
                    {
                        "id": "ip",
                        "filterName": "ip",
                        "operator": "=",
                        "type": "vuln",
                        "isPredefined": True,
                        "value": str(list_vuln_host).strip(),
                    }
                )
            else:
                filters.append(
                    {
                        "id": "dns",
                        "filterName": "dnsName",
                        "operator": "=",
                        "type": "vuln",
                        "isPredefined": True,
                        "value": str(list_vuln_host).strip(),
                    }
                )
        if cve_id:
            filters.append(
                {
                    "id": "cveID",
                    "filterName": "cveID",
                    "operator": "=",
                    "type": "vuln",
                    "isPredefined": True,
                    "value": str(cve_id).strip(),
                }
            )

        query_string = {
            "query": {
                "name": "",
                "description": "",
                "context": "",
                "status": -1,
                "createdTime": 0,
                "modifiedTime": 0,
                "groups": [],
                "type": "vuln",
                "tool": "sumid",
                "sourceType": "cumulative",
                "startOffset": 0,
                "endOffset": PAGE_SIZE,
                "filters": filters,
                "sortColumn": "severity",
                "sortDirection": "desc",
                "vulnTool": "sumid",
            },
            "sourceType": "cumulative",
            "sortField": "severity",
            "sortDir": "desc",
            "columns": [],
            "type": "vuln",
        }

        final_data = {}
        while True:
            ret_val, resp_json = self._make_rest_call("/analysis", action_result, json=query_string, method="post")

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if final_data:
                final_data["results"].extend(resp_json.get("response", {}).get("results", []))
            else:
                final_data = resp_json.get("response", {})

            if PAGE_SIZE > len(resp_json.get("response", {}).get("results", [])):
                break

            query_string["query"]["startOffset"] += PAGE_SIZE
            query_string["query"]["endOffset"] += PAGE_SIZE

        final_data["returnedRecords"] = len(final_data.get("results", []))
        final_data["endOffset"] = query_string["query"]["endOffset"]

        action_result.add_data(final_data)
        action_result.update_summary({"total_vulnerabilities": len(final_data.get("results", []))})

        crit_vulns = high_vulns = med_vulns = low_vulns = info_vulns = 0
        for vuln in final_data.get("results", []):
            if vuln["severity"]["id"] == "4":
                crit_vulns += 1
            elif vuln["severity"]["id"] == "3":
                high_vulns += 1
            elif vuln["severity"]["id"] == "2":
                med_vulns += 1
            elif vuln["severity"]["id"] == "1":
                low_vulns += 1
            elif vuln["severity"]["id"] == "0":
                info_vulns += 1
        action_result.update_summary(
            {
                "critical_vulns": crit_vulns,
                "high_vulns": high_vulns,
                "medium_vulns": med_vulns,
                "low_vulns": low_vulns,
                "info_vulns": info_vulns,
            }
        )

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_policies(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, resp_json = self._make_rest_call("/policy", action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json["response"])
        action_result.update_summary({"policy_count": len(resp_json["response"].get("usable", []))})
        message = "Total policies: {}".format(len(resp_json["response"].get("usable", [])))

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _list_repositories(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, resp_json = self._make_rest_call("/repository", action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for repository in resp_json["response"]:
            action_result.add_data(repository)

        action_result.update_summary({"repository_count": len(resp_json["response"])})
        message = "Total repositories: {}".format(len(resp_json["response"]))

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _update_asset(self, param):
        """
        Update asset with provided name and fields. Creates new asset if it doesn't exist.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        asset_name = self._handle_py_ver_compat_for_input_str(param["asset_name"])
        try:
            update_fields = self.load_dirty_json(self._handle_py_ver_compat_for_input_str(param["update_fields"]))
            if not isinstance(update_fields, dict):
                return action_result.set_status(
                    phantom.APP_ERROR, TENABLE_ERR_INVALID_JSON.format(param="update_fields")
                )
        except Exception as ex:
            self.debug_print(ex)
            return action_result.set_status(phantom.APP_ERROR, TENABLE_ERR_INVALID_JSON.format(param="update_fields"))

        endpoint = "/asset"

        ret_val, resp_json = self._make_rest_call(endpoint, action_result, params={"fields": "id,name"})
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for sc_asset in resp_json["response"]["manageable"] + resp_json["response"]["usable"]:
            if sc_asset["name"] == asset_name:
                self.save_progress("Asset found, attempting to update it.")
                endpoint = "{}/{}".format(endpoint, sc_asset["id"])

                ret_val, resp_json = self._make_rest_call(endpoint, action_result, json=update_fields, method="patch")
                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                action_result.add_data(resp_json)

                return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated asset.")

        self.save_progress("Asset does not exist, attempting to create it.")
        # Asset doesn't exist, creating new one with provided name.
        if "type" not in update_fields:
            update_fields["type"] = "static"
        if "name" not in update_fields:
            update_fields["name"] = asset_name

        ret_val, resp_json = self._make_rest_call(endpoint, action_result, json=update_fields, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created new asset.")

    def _update_group(self, param):
        """
        Update group with provided name and fields. Returns error if the group doesn't exist.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        group_name = self._handle_py_ver_compat_for_input_str(param["group_name"])
        try:
            update_fields = self.load_dirty_json(self._handle_py_ver_compat_for_input_str(param["update_fields"]))
            if not isinstance(update_fields, dict):
                return action_result.set_status(
                    phantom.APP_ERROR, TENABLE_ERR_INVALID_JSON.format(param="update_fields")
                )
        except Exception as ex:
            self.debug_print(ex)
            return action_result.set_status(phantom.APP_ERROR, TENABLE_ERR_INVALID_JSON.format(param="update_fields"))

        endpoint = "/group"

        ret_val, resp_json = self._make_rest_call(endpoint, action_result, params={"fields": "id,name"})
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for sc_group in resp_json["response"]:
            if sc_group["name"] == group_name:
                self.save_progress("Group found, attempting to update it.")
                endpoint = "{}/{}".format(endpoint, sc_group["id"])

                ret_val, resp_json = self._make_rest_call(endpoint, action_result, json=update_fields, method="patch")
                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                action_result.add_data(resp_json)

                return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated group.")

        # Group does not exist
        message = 'Group "{}" not found.'.format(group_name)
        return action_result.set_status(phantom.APP_ERROR, message)

    def handle_action(self, param):

        ret_val = None

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        if action_id == self.ACTION_ID_GET_IP_VULNERABILITIES:
            ret_val = self._list_vulnerabilities(param)
        elif action_id == self.ACTION_ID_SCAN_ENDPOINT:
            ret_val = self._scan_endpoint(param)
        elif action_id == self.ACTION_ID_LIST_SCAN_POLICIES:
            ret_val = self._list_policies(param)
        elif action_id == self.ACTION_ID_UPDATE_ASSET:
            ret_val = self._update_asset(param)
        elif action_id == self.ACTION_ID_LIST_REPOSITORY:
            ret_val = self._list_repositories(param)
        elif action_id == self.ACTION_ID_UPDATE_GROUP:
            ret_val = self._update_group(param)
        elif action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity()

        return ret_val


if __name__ == "__main__":

    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = SecurityCenterConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
