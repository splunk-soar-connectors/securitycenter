# --
# File: securitycenter_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2017-2018
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
import phantom.utils as ph_utils

# Imports local to this App
import requests
import datetime
import json
import time
from bs4 import BeautifulSoup
from securitycenter_consts import *


class SecurityCenterConnector(BaseConnector):

    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"
    ACTION_ID_SCAN_ENDPOINT = "scan_endpoint"
    ACTION_ID_LIST_SCAN_POLICIES = "list_policies"
    ACTION_ID_GET_IP_VULNERABILITIES = "list_vulnerabilities"
    ACTION_ID_UPDATE_ASSET = "update_asset"
    ACTION_ID_UPDATE_GROUP = "update_group"

    def __init__(self):

        # Call the BaseConnectors init first
        super(SecurityCenterConnector, self).__init__()
        self._verify = None

    def _get_token(self):

        config = self.get_config()

        rjson = {}
        error_msg = None
        for retry in range(1, self._retry_count + 1):

            self._session = requests.Session()
            self._session.headers = {'Content-type': 'application/json', 'accept': 'application/json'}
            auth_data = {"username": config["username"], "password": config["password"]}

            if retry > 1:
                self.save_progress("Failed.")
                self.save_progress("Waiting for {} seconds until retry".format(self._retry_wait))
                time.sleep(self._retry_wait)

            self.save_progress("Getting token for session...; try #{}".format(retry))
            r = None
            error_msg = None
            try:
                r = self._session.post(self._rest_url + "/rest/token", json=auth_data, verify=self._verify)
                self.save_progress("Request Completed")

            except Exception as e:
                self.save_progress("Request Exception")
                error_msg = "Error: connection error with server; {}".format(e)
                self.save_progress(error_msg)

            if r == None:
                error_msg = "Error: no response from server"
                self.save_progress(error_msg)
                continue

            rjson = {}
            try:
                rjson = r.json()
                #print(json.dumps(rjson, indent=4))

            except Exception as e:
                #print("Exception: {}".format(e))
                #print("status_code: {}".format(r.status_code))
                #print("Text")
                #print(r.text)
                pass

            if len(rjson) == 0:
                error_msg = "Error: response not json compliant"
                self.save_progress(error_msg)
                continue

            if rjson.get('error_code'):
                error_msg = "Error: error code {}: {}".format(rjson.get('error_code'), rjson.get('error_msg').replace('\n',' ').strip())
                self.save_progress(error_msg)
                continue

            token = rjson.get("response") or {}
            token = token.get("token") or None
            if not isinstance(token, int):
                error_msg = "Error: token is not numeric"
                self.save_progress(error_msg)
                continue
                
            self._session.headers.update({'X-SecurityCenter': str(token)})
            self._good_token = True
            return self.set_status(phantom.APP_SUCCESS)

        if rjson.get('error_code'):
            error_msg = "Error: error code {}: {}".format(rjson.get('error_code'), rjson.get('error_msg').replace('\n',' ').strip())
            self.save_progress(error_msg)
            
        self.save_progress("Error: Exceeded number of retries to get token; {}".format(error_msg))
        return self.set_status(phantom.APP_ERROR, "Error: Exceeded number of retries to get token; {}".format(error_msg))

    def initialize(self):

        self._good_token = False

        config = self.get_config()
        self._verify = config["verify_server_cert"]
        self._rest_url = config["base_url"]
        self._retry_count = int(config['retry_count'])
        self._retry_wait = int(config['retry_wait'])

        status = self._get_token()
        if phantom.is_fail(status):
            print("Returning error in initialize")
            return self.get_status()

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

    def _make_rest_call(self, endpoint, action_result, params={}, json={}, method="get"):

        url = "{0}/rest{1}".format(self._rest_url, endpoint)

        try:
            request_func = getattr(self._session, method)
        except AttributeError:
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, "Unsupported method: {0}".format(method)), None
        except Exception as e:
            # Set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, "Handled exception: {0}".format(str(e))), None

        rjson = {}
        error_msg = None
        for retry in range(1, self._retry_count + 1):

            if retry > 1:
                self.save_progress("Failed.")
                self.save_progress("Waiting for {} seconds until retry".format(self._retry_wait))
                time.sleep(self._retry_wait)

            self.save_progress("Making REST call...; try #{}".format(retry))
            r = None
            error_msg = None
            try:
                r = request_func(url, params=params, json=json, verify=self._verify)
                self.save_progress("Request Completed")

            except Exception as e:
                self.save_progress("Request Exception")
                error_msg = "Error: connection error with server; {}".format(e)
                self.save_progress(error_msg)

            if r == None:
                error_msg = "Error: no response from server"
                self.save_progress(error_msg)
                continue

            rjson = {}
            try:
                # because json is a parameter
                import json as jjson
                rjson = r.json()
                #print(jjson.dumps(rjson, indent=4))

            except Exception as e:
                #print("Exception: {}".format(e))
                #print("status_code: {}".format(r.status_code))
                #print("Text")
                #print(r.text)
                pass

            if len(rjson) == 0:
                error_msg = "Error: response not json compliant"
                self.save_progress(error_msg)
                continue

            if rjson.get('error_code'):
                error_msg = "Error: error code {}: {}".format(rjson.get('error_code'), rjson.get('error_msg').replace('\n',' ').strip())
                self.send_progress(error_msg)
                continue

            return self._process_response(r, action_result)

        self.save_progress("Error: Failed to make REST call; {}".format(error_msg))
        return action_result.set_status(phantom.APP_ERROR, "REST API to server failed: ", error_msg), None

    def load_dirty_json(self, dirty_json):
        import re
        regex_replace = [(r"([ \{,:\[])(u)?'([^']+)'", r'\1"\3"'), (r" False([, \}\]])", r' false\1'),
                         (r" True([, \}\]])", r' true\1')]
        for r, s in regex_replace:
            dirty_json = re.sub(r, s, dirty_json)
        clean_json = json.loads(dirty_json)

        return clean_json

    def _test_connectivity(self):

        self.save_progress("Checking connectivity to your SecurityCenter instance...")
        ret_val, resp_json = self._make_rest_call('/user', self)
        if phantom.is_fail(ret_val):
            self.append_to_message('Test connectivity failed')
            return self.get_status()
        else:
            return self.set_status_save_progress(phantom.APP_SUCCESS, "Connectivity to SecurityCenter was successful.")

    def _scan_endpoint(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)
        # target to scan
        ip_hostname = param[IP_HOSTNAME]

        # Clean up ip hostname
        ip_hostname = [x.strip() for x in ip_hostname.split(',')]
        ip_hostname = ','.join(ip_hostname)
        ip_hostname = ip_hostname.replace("https://", "")
        ip_hostname = ip_hostname.replace("http://", "")
        if (not ph_utils.is_hostname(ip_hostname)):
            if (not ph_utils.is_ip(ip_hostname)):
                return action_result.set_status(phantom.APP_ERROR, "Invalid IP or Hostname supplied to scan endpoint.")

        scan_policy_id = param[SCAN_POLICY]
        if len(str(scan_policy_id)) > 10:
            return action_result.set_status(phantom.APP_ERROR, "Invalid Scan policy ID. Please run 'list policies' to get policy IDs.")

        # Calculate scan start time with a defined delay
        scan_start = datetime.datetime.utcnow() + datetime.timedelta(minutes=SCAN_DELAY)
        scan_start = scan_start.strftime(DATETIME_FORMAT)
        # can probably remove some of these options
        scan_data = {"name": "Scan Launched from Phantom", "repository": {"id": 1},
                    "schedule": {"start": scan_start, "repeatRule": "FREQ=NOW;INTERVAL=1", "type": "now"},
                    "reports": [], "type": "policy", "policy": {"id": scan_policy_id}, "zone": {"id": -1},
                    "ipList": str(ip_hostname), "credentials": [], "maxScanTime": "unlimited"}

        ret_val, resp_json = self._make_rest_call('/scan', action_result, json=scan_data, method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(resp_json["response"])
        action_result.set_summary({'name': resp_json["response"]["name"]})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_vulnerabilities(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        list_vuln_host = param[IP_HOSTNAME].strip()
        if (not ph_utils.is_ip(list_vuln_host)):
            if len(list_vuln_host) > 255 or set(' !"\'@#$%^&*(){};[]|').intersection(list_vuln_host):
                return action_result.set_status(phantom.APP_ERROR, "Invalid IP or Hostname supplied to list vulnerabilities.")

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

        ret_val, resp_json = self._make_rest_call("/analysis", action_result, json=query_string, method="post")

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
        ret_val, resp_json = self._make_rest_call("/policy", action_result)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        action_result.add_data(resp_json["response"])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _update_asset(self, param):
        """
        Update asset with provided name and fields. Creates new asset if it doesn't exist.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        asset_name = param['asset_name']
        update_fields = self.load_dirty_json(param['update_fields'])

        endpoint = '/asset'

        ret_val, resp_json = self._make_rest_call(endpoint, action_result, params={'fields': 'id,name'})
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for sc_asset in resp_json['response']['manageable'] + resp_json['response']['usable']:
            if sc_asset['name'] == asset_name:
                self.save_progress('Asset found, attempting to update it.')
                endpoint = '{}/{}'.format(endpoint, sc_asset['id'])

                ret_val, resp_json = self._make_rest_call(endpoint, action_result, json=update_fields, method="patch")
                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                action_result.add_data(resp_json)

                return action_result.set_status(phantom.APP_SUCCESS, 'Successfully updated asset.')

        self.save_progress('Asset does not exist, attempting to create it.')
        # Asset doesn't exist, creating new one with provided name.
        if 'type' not in update_fields:
            update_fields['type'] = 'static'

        update_fields['name'] = asset_name

        ret_val, resp_json = self._make_rest_call(endpoint, action_result, json=update_fields, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully created new asset.')

    def _update_group(self, param):
        """
        Update group with provided name and fields. Returns error if the group doesn't exist.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        group_name = param['group_name']
        update_fields = self.load_dirty_json(param['update_fields'])

        endpoint = '/group'

        ret_val, resp_json = self._make_rest_call(endpoint, action_result, params={'fields': 'id,name'})
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for sc_group in resp_json['response']:
            if sc_group['name'] == group_name:
                self.save_progress('Group found, attempting to update it.')
                endpoint = '{}/{}'.format(endpoint, sc_group['id'])

                ret_val, resp_json = self._make_rest_call(endpoint, action_result, json=update_fields, method="patch")
                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                action_result.add_data(resp_json)

                return action_result.set_status(phantom.APP_SUCCESS, 'Successfully updated group.')

        # Group does not exist
        message = 'Group ({}) not found.'.format(group_name)
        return action_result.set_status(phantom.APP_ERROR, message)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_GET_IP_VULNERABILITIES):
            ret_val = self._list_vulnerabilities(param)
        elif (action_id == self.ACTION_ID_SCAN_ENDPOINT):
            ret_val = self._scan_endpoint(param)
        elif (action_id == self.ACTION_ID_LIST_SCAN_POLICIES):
            ret_val = self._list_policies(param)
        elif (action_id == self.ACTION_ID_UPDATE_ASSET):
            ret_val = self._update_asset(param)
        elif (action_id == self.ACTION_ID_UPDATE_GROUP):
            ret_val = self._update_group(param)
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
