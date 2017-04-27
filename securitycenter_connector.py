# --
# File: ssmachine_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016
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
from securitycenter_consts import *
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
import requests
import time

class SecurityCenterConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(SecurityCenterConnector, self).__init__()

        self._headers = None

    def initialize(self):

        config = self.get_config()

        self._rest_url = config.get("sc_instnace")
        json = dict()
        json['username'] = config.get("sc_username")
        json['password'] = config.get('sc_password')
        ret_val, resp = self._make_rest_call('/token', self, json=json, method='post')
        self._headers = {'X-Securitycenter': resp.json()['response']['token']}
        self._cookie = resp.cookie
        return ret_val

    def finalize(self):

        # Logout
        ret_val, resp = self._make_rest_call('/token', self, headers=self._headers, method='delete')
        return ret_val

    def _parse_response(self, result, r):

        # It's ok if r.text is None, dump that, if the result object supports recording it
        if hasattr(result, 'add_debug_data'):
            result.add_debug_data({'r_text': r.text if r else 'r is None'})

        if not (200 <= r.status_code < 300):
            return (result.set_status(phantom.APP_ERROR,
                                     "Call returned error, status_code: {0}, data: {1}".format(r.status_code, r.content)),
                                     r.status_code, r.headers.get('content-type'), r.content)

        return phantom.APP_SUCCESS, r

    def _make_rest_call(self, endpoint, result, params={}, headers={}, json={}, cookie={}, method="get", stream=False):

        url = "{0}{1}".format(self._rest_url, endpoint)

        if self._headers is not None:
            (headers.update(self._headers))

        request_func = getattr(requests, method)

        if not request_func:
            return result.set_status(phantom.APP_ERROR, "Invalid method call: {0} for requests module".format(method)), None

        try:
            r = request_func(url, headers=headers, params=params, json=json, cookie=cookie, stream=stream)
        except Exception as e:
            return result.set_status(phantom.APP_ERROR, "REST Api to server failed", e), None

        ret_val, resp = self._parse_response(result, r)

        # Any http or parsing error is handled by the _parse_response function
        if phantom.is_fail(ret_val):
            return result.get_status(), resp.content

        return phantom.APP_SUCCESS, resp

    def _test_connectivity(self):

        self.save_progress("Checking connectivity to your SecurityCenter instnace...")

        if not self._token:
            self.append_to_message('Test connectivity failed')
            return self.get_status()

        return self.set_status_save_progress(ret_val, "Connectivity to SecurityCenter was successful.")

    def _handle_scan_results(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        params = dict()
        params['start_time'] = param["stime"]
        params['end_time'] = param["etime"]

        ret_val, scans = self._make_rest_call('/scanResult', action_result, params, method='get')
        for scan in scans:
            json={

            }
            ret_val, vulns = self._make_rest_call('/analysis', action_result, params, method='post')
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Find a good way to display scan results that come from Json or something

        return action_result.get_status()

    def _handle_scan_targets(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        json = dict()
        json['ips'] = param["ips"]
        timeout = param['timeout']
        ret_val, scan_properties = self._make_rest_call('/scan', action_result, json=json, method='post')
        scanID = scan_properties.json()['response']['id']
        ret_val, scan_result_properties = self._make_rest_call('/scan/'+scanID+'/launch', action_result, json=json, method='post')
        scanresultID = scan_result_properties.json()['response']['id']
        while timeout > 0:
            ret_val, scan_result_status = self._make_rest_call('/scanResult/'+scanresultID, action_result, method='get')
            if scan_result_status.json()['response']['status'] in ['completed', 'partial']:
                ret_val, scan_results = self._make_rest_call('/analysis', action_result, json=json, method='post')
                if (phantom.is_fail(ret_val)):
                    return action_result.get_status()
                return phantom.APP_SUCCESS, scan_results
            time.sleep(30)
            timeout -= .5

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        return action_result.get_status()

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == "get_scan_results"):
            ret_val = self._handle_scan_results(param)
        elif (action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity()

        return ret_val


if __name__ == '__main__':

    import sys
    import json

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
