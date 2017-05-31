# --
# File: securitycenter_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
import requests
import datetime
import json
import BeautifulSoup
from securitycenter_consts import *


class SecurityCenterConnector(BaseConnector):

    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"
    ACTION_ID_SCAN_ENDPOINT = "scan_endpoint"
    ACTION_ID_LIST_SCAN_POLICIES = "list_policies"
    ACTION_ID_GET_IP_VULNERABILITIES = "list_vulnerabilities"

    def __init__(self):

        # Call the BaseConnectors init first
        super(SecurityCenterConnector, self).__init__()
        self._verify = None

    def initialize(self):

        config = self.get_config()
        self._verify = config["verify_server_cert"]
        self._rest_url = config["base_url"]

        self._session = requests.Session()
        auth_data = {"username": config["username"], "password": config["password"]}
        self._session.headers = {'Content-type': 'application/json', 'accept': 'application/json'}

        self.save_progress("Getting token for session...")
        try:
            auth_resp = self._session.post(self._rest_url + "/rest/token", json=auth_data, verify=self._verify)
            auth_resp_json = auth_resp.json()
            self._session.headers.update({'X-SecurityCenter': str(auth_resp_json['response']['token'])})
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, "Failed to get/set token", e)

        self.debug_print(self._session.headers)
        return phantom.APP_SUCCESS

    def finalize(self):

        # Logout
        ret_val, resp = self._make_rest_call('/token', self, method='delete')
        return ret_val

    def _process_html_response(self, response, action_result):

        # An html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON", e), None

        if (200 <= r.status_code < 205):
            return phantom.APP_SUCCESS, resp_json

        action_result.add_data(resp_json)
        message = r.text.replace('{', '{{').replace('}', '}}')
        return action_result.set_status(phantom.APP_ERROR,
                                               "Error from server, Status Code: {0} data returned: {1}".format(
                                                   r.status_code, message)), resp_json

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, 'add_debug_data'):
            if (r is not None):
                action_result.add_debug_data({'r_text': r.text})
                action_result.add_debug_data({'r_headers': r.headers})
                action_result.add_debug_data({'r_status_code': r.status_code})
            else:
                action_result.add_debug_data({'r_text': 'r is None'})

        # There are just too many differences in the response to handle all of them in the same function
        if ('json' in r.headers.get('Content-Type', '')):
            return self._process_json_response(r, action_result)

        if ('html' in r.headers.get('Content-Type', '')):
            return self._process_html_response(r, action_result)

        # it's not an html or json, handle if it is a successful empty response
        # if (200 <= r.status_code < 205) and (not r.text):
        #   return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _make_rest_call(self, endpoint, result, params={}, json={}, method="get"):

        url = "{0}/rest{1}".format(self._rest_url, endpoint)

        try:
            request_func = getattr(self._session, method)
        except AttributeError:
            # Set the action_result status to error, the handler function will most probably return as is
            return result.set_status(phantom.APP_ERROR, "Unsupported method: {0}".format(method)), None
        except Exception as e:
            # Set the action_result status to error, the handler function will most probably return as is
            return result.set_status(phantom.APP_ERROR, "Handled exception: {0}".format(str(e))), None

        try:
            r = request_func(url, params=params, json=json, verify=self._verify)
        except Exception as e:
            return result.set_status(phantom.APP_ERROR, "REST API to server failed: ", e), None

        return self._process_response(r, result)

    def _test_connectivity(self):

        self.save_progress("Checking connectivity to your SecurityCenter instance...")
        ret_val, resp_json = self._make_rest_call('/user', self)
        if phantom.is_fail(ret_val):
            self.append_to_message('Test connectivity failed')
            return self.get_status()
        else:
            self.debug_print(self._session.headers["X-SecurityCenter"])
            self.debug_print("In test connectivity, just before returning")
            return self.set_status_save_progress(phantom.APP_SUCCESS, "Connectivity to SecurityCenter was successful.")

    def _scan_endpoint(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)
        # target to scan
        ip_hostname = param[IP_HOSTNAME]
        scan_policy_id = param[SCAN_POLICY]

        # Calculate scan start time with a defined delay
        scan_start = datetime.datetime.utcnow() + datetime.timedelta(minutes=SCAN_DELAY)
        scan_start = scan_start.strftime(DATETIME_FORMAT)
        # can probably remove some of these options
        scan_data = {"name": "Scan Launched from Phantom", "repository": {"id": 1}, "schedule": {"start": scan_start,
                                                                      "repeatRule": "FREQ=NOW;INTERVAL=1",
                                                                      "type": "now"},
                    "reports": [], "type": "policy", "policy": {"id": scan_policy_id}, "zone": {"id": -1},
                    "ipList": str(ip_hostname), "credentials": [], "maxScanTime": "unlimited"}

        ret_val, resp_json = self._make_rest_call('/scan', self, json=scan_data, method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(resp_json["response"])
        action_result.set_summary({'name': resp_json["response"]["name"]})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_vulnerabilities(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        list_vuln_host = param[IP_HOSTNAME]
        if phantom.is_ip(list_vuln_host) is True:
            filters = [{
                            "id": "ip",
                            "filterName": "ip",
                            "operator": "=",
                            "type": "vuln",
                            "isPredefined": True,
                            "value": str(list_vuln_host)
                          }]
        else:
            filters = [{
                            "id": "dns",
                            "filterName": "dnsName",
                            "operator": "=",
                            "type": "vuln",
                            "isPredefined": True,
                            "value": str(list_vuln_host)
                          }]
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
                        "endOffset": 50,
                        "filters": filters,
                        "sortColumn": "severity",
                        "sortDirection": "desc",
                        "vulnTool": "sumid"
                      },
                      "sourceType": "cumulative",
                      "sortField": "severity",
                      "sortDir": "desc", "columns": [],
                      "type": "vuln"
                    }

        ret_val, resp_json = self._make_rest_call("/analysis", self, json=query_string, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(resp_json["response"])
        action_result.set_summary({'total_vulnerabilities': resp_json["response"]["totalRecords"]})

        crit_vulns = high_vulns = med_vulns = low_vulns = info_vulns = 0
        for vuln in resp_json["response"]["results"]:
            if vuln["severity"]["id"] == '4':
                crit_vulns += 1
            elif vuln["severity"]["id"] == '3':
                high_vulns += 1
            elif vuln["severity"]["id"] == '2':
                med_vulns += 1
            elif vuln["severity"]["id"] == '1':
                low_vulns += 1
            elif vuln["severity"]["id"] == '0':
                info_vulns += 1
        action_result.update_summary({'critical_vulns': crit_vulns, 'high_vulns': high_vulns, 'medium_vulns': med_vulns,
                                      'low_vulns': low_vulns, 'info_vulns': info_vulns})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_policies(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, resp_json = self._make_rest_call("/policy", self)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        action_result.add_data(resp_json["response"])

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_GET_IP_VULNERABILITIES):
            ret_val = self._list_vulnerabilities(param)
        if (action_id == self.ACTION_ID_SCAN_ENDPOINT):
            ret_val = self._scan_endpoint(param)
        if (action_id == self.ACTION_ID_LIST_SCAN_POLICIES):
            ret_val = self._list_policies(param)
        elif (action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity()

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = SecurityCenterConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
