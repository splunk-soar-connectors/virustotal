# --
# File: virustotal_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.app import BaseConnector
from phantom.app import ActionResult
from phantom.vault import Vault

# THIS Connector imports
from virustotal_consts import *

# Other imports used by this connector
import os
import re
import uuid
import time
import magic
import shutil
import hashlib
import requests
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class VirustotalConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_QUERY_FILE = "lookup_file"
    ACTION_ID_QUERY_URL = "lookup_url"
    ACTION_ID_QUERY_DOMAIN = "lookup_domain"
    ACTION_ID_QUERY_IP = "lookup_ip"
    ACTION_ID_GET_FILE = "get_file"
    ACTION_ID_GET_REPORT = "get_report"
    ACTION_ID_DETONATE_FILE = "detonate_file"

    MAGIC_FORMATS = [
      (re.compile('^PE.* Windows'), ['pe file'], '.exe'),
      (re.compile('^MS-DOS executable'), ['pe file'], '.exe'),
      (re.compile('^PDF '), ['pdf'], '.pdf'),
      (re.compile('^MDMP crash'), ['process dump'], '.dmp'),
      (re.compile('^Macromedia Flash'), ['flash'], '.flv'),
      (re.compile('^tcpdump capture'), ['pcap'], '.pcap'),
    ]

    def __init__(self):

        # Call the BaseConnectors init first
        super(VirustotalConnector, self).__init__()

        self._apikey = None
        self._rate_limit = None
        self._verify_ssl = None

    def _process_empty_reponse(self, response, action_result):

        if (200 <= response.status_code < 205):
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

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

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            self.save_progress('Cannot parse JSON')
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON", e), None)

        if (200 <= r.status_code < 205):
            return RetVal(phantom.APP_SUCCESS, resp_json)

        action_result.add_data(resp_json)
        message = r.text.replace('{', '{{').replace('}', '}}')
        return RetVal( action_result.set_status( phantom.APP_ERROR, "Error from server, Status Code: {0} data returned: {1}".format(r.status_code, message)), resp_json)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # There are just too many differences in the response to handle all of them in the same function
        if ('json' in r.headers.get('Content-Type', '')):
            return self._process_json_response(r, action_result)

        if ('html' in r.headers.get('Content-Type', '')):
            return self._process_html_response(r, action_result)

        # it's not an html or json, handle if it is a successfull empty reponse
        if (200 <= r.status_code < 205) and (not r.text):
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, action_result, endpoint, params={}, body={}, headers={}, files=None, method="get"):
        """ Returns 2 values, use RetVal """

        url = "https://www.virustotal.com/vtapi/v2" + endpoint

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unsupported method: {0}".format(method)), None)
        except Exception as e:
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Handled exception: {0}".format(str(e))), None)

        # Check rate limit
        if self._rate_limit:
            self._check_rate_limit()

        try:
            response = request_func(url, params=params, json=body, headers=headers, files=files, verify=self._verify_ssl)
        except Exception as e:
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error connecting: {0}".format(str(e))), None)

        if self._rate_limit:
            self._track_rate_limit(response.headers.get('Date'))

        self.debug_print(response.url)
        self.debug_print(response.text)

        if response.status_code == 204:
            return RetVal(action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT.format(code=response.status_code)), None)

        return self._process_response(response, action_result)

    def _check_rate_limit(self, count=1):
        """ Check to see if the rate limit is within the "4 requests per minute". Wait and check again if the request is too soon.

        Returns:
            boolean: True, when the rate limitation is not greater than or equal to the allocated amount
        """
        self.debug_print('Checking rate limit')

        state = self.load_state()
        if not state or not state.get('rate_limit_timestamps'):
            self.save_state({'rate_limit_timestamps': []})
            return True

        # Cleanup existing timestamp list to only have the timestamps within the last 60 seconds
        timestamps = state['rate_limit_timestamps']
        current_time = int(time.time())
        for timestamp in timestamps:
            time_diff = current_time - timestamp
            if time_diff > 60:
                timestamps.remove(timestamp)

        # Save new cleaned list
        self.save_state({'rate_limit_timestamps': timestamps})

        # If there are too many within the last minute, we will wait the min_time_diff and try again
        if len(timestamps) >= 4:
            wait_time = 61 - (current_time - min(t for t in timestamps))

            self.send_progress('Rate limit check #{0}. Waiting {1} seconds for rate limitation to pass and will try again.'.format(count, wait_time))
            time.sleep(wait_time)
            # Use recursive call to try again
            return self._check_rate_limit(count + 1)

        return True

    def _track_rate_limit(self, timestamp):
        """ Track timestamp of VirusTotal requests to stay within rate limitations

        Args:
            timestamp (str): Timestamp from the last requests call (e.g., 'Tue, 12 Jun 2018 16:39:37 GMT')

        Returns:
            boolean: True
        """
        self.debug_print('Tracking rate limit')

        if not timestamp:
            epoch = int(time.time())
        else:
            epoch = int(time.mktime(time.strptime(timestamp, '%a, %d %b %Y %H:%M:%S GMT')))

        state = self.load_state()
        timestamps = state.get('rate_limit_timestamps', [])
        timestamps.append(epoch)

        self.save_state({'rate_limit_timestamps': timestamps})

        return True

    def _query_ip_domain(self, param, object_name, query_url):

        object_value = param[object_name]
        action_result = self.add_action_result(ActionResult(dict(param)))

        item_summary = action_result.set_summary({})
        item_summary[VIRUSTOTAL_JSON_DETECTED_URLS] = 0

        params = {object_name: object_value, VIRUSTOTAL_JSON_APIKEY: self._apikey}

        self.save_progress(VIRUSTOTAL_MSG_CONNECTING)

        config = self.get_config()

        try:
            r = requests.get(query_url, params=params, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            self.debug_print('_query_ip_domain', e)
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_CONNECTION_ERROR, e)

        # It's ok if r.text is None, dump that
        action_result.add_debug_data({'r_text': r.text if r else 'r is None'})

        if (r.status_code == 204):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT.format(code=r.status_code))

        if (r.status_code != 200):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_RETURNED_ERROR_CODE.format(code=r.status_code))

        try:
            response_dict = r.json()
        except Exception as e:
            self.debug_print("Response from server not a valid JSON", e)
            return action_result.set_status(phantom.APP_ERROR, "Response from server not a valid JSON")

        # It's been noticed that VT sometimes sends back a list with a single item, instead of a dictionary
        # Happened a couple of times on customer site
        if (type(response_dict) == list):
            self.debug_print("Got a list, will be using the first item")
            response_dict = response_dict[0]

        if (type(response_dict) != dict):
            return action_result.set_status(phantom.APP_ERROR, "Response from server not a type that is expected")

        action_result.add_data(response_dict)

        if ('response_code' not in response_dict):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_ERR_MSG_OBJECT_QUERIED, object_name=object_name, object_value=object_value)

        action_result.set_status(phantom.APP_SUCCESS)

        if (response_dict['response_code'] == 0):
            action_result.set_status(phantom.APP_SUCCESS, VIRUSTOTAL_MSG_OBJECT_NOT_FOUND,
                    object_name=object_name.capitalize())

        if ('Alexa rank' in response_dict):
            item_summary[VIRUSTOTAL_JSON_ALEXA_RANK] = response_dict['Alexa rank']

        if ('detected_urls' in response_dict):
            item_summary[VIRUSTOTAL_JSON_DETECTED_URLS] = len(response_dict['detected_urls'])

        if ('detected_downloaded_samples' in response_dict):
            item_summary[VIRUSTOTAL_JSON_DOWNLOADED_SAMPLES] = len(response_dict['detected_downloaded_samples'])

        if ('detected_communicating_samples' in response_dict):
            item_summary[VIRUSTOTAL_JSON_COMMUNICATING_SAMPLES] = len(response_dict['detected_communicating_samples'])

        return action_result.get_status()

    def _query_file_url(self, param, json_key, query_url):

        object_value = param[json_key]
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {'resource': object_value, VIRUSTOTAL_JSON_APIKEY: self._apikey}

        config = self.get_config()

        # Format the request with the URL and the params
        self.save_progress(VIRUSTOTAL_MSG_CREATED_URL, query_url=query_url)
        try:
            r = requests.get(query_url, params=params, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            self.debug_print("_query_file_url", e)
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_CONNECTION_ERROR, e)

        # It's ok if r.text is None, dump that
        action_result.add_debug_data({'r_text': r.text if r else ''})

        self.debug_print("status_code", r.status_code)

        if (r.status_code == 204):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT.format(code=r.status_code))

        if (r.status_code != 200):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_RETURNED_ERROR_CODE.format(code=r.status_code))

        try:
            result = r.json()
        except Exception as e:
            self.debug_print("Response from server not a valid JSON", e)
            return action_result.set_status(phantom.APP_ERROR, "Response from server not a valid JSON")

        # It's been noticed that VT sometimes sends back a list with a single item, instead of a dictionary
        # Happened a couple of times on customer site
        if (type(result) == list):
            self.debug_print("Got a list, will be using the first item")
            result = result[0]

        if (type(result) != dict):
            return action_result.set_status(phantom.APP_ERROR, "Response from server not a type that is expected")

        # add the data
        action_result.add_data(result)

        # update the summary
        action_result.update_summary({VIRUSTOTAL_JSON_TOTAL_SCANS: result.get('total', 0),
            VIRUSTOTAL_JSON_POSITIVES: result.get('positives', 0)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _query_url(self, param):

        json_key = phantom.APP_JSON_URL
        query_url = URL_API_URL

        return self._query_file_url(param, json_key, query_url)

    def _query_file(self, param):

        json_key = phantom.APP_JSON_HASH
        query_url = FILE_API_URL

        return self._query_file_url(param, json_key, query_url)

    def _query_ip(self, param):

        query_url = IP_API_URL
        object_name = phantom.APP_JSON_IP

        return self._query_ip_domain(param, object_name, query_url)

    def _query_domain(self, param):

        query_url = DOMAIN_API_URL
        object_name = phantom.APP_JSON_DOMAIN

        return self._query_ip_domain(param, object_name, query_url)

    def _update_action_result_for_detonate_file(self, action_result, json_resp):
        action_result.add_data(json_resp)

        # update the summary
        action_result.update_summary({
            VIRUSTOTAL_JSON_TOTAL_SCANS: json_resp.get('total', 0),
            VIRUSTOTAL_JSON_POSITIVES: json_resp.get('positives', 0)
        })
        return action_result.set_status(phantom.APP_SUCCESS)

    def _poll_for_result(self, action_result, scan_id, poll_interval):

        attempt = 1
        endpoint = '/file/report'
        params = {'apikey': self._apikey, 'resource': scan_id}
        # Since we sleep 1 minute between each poll, the poll_interval is
        # equal to the number of attempts
        poll_attempts = poll_interval
        while attempt <= poll_attempts:
            self.save_progress("Polling attempt {0} of {1}".format(attempt, poll_attempts))
            ret_val, json_resp = self._make_rest_call(action_result, endpoint, params, method="post")
            if phantom.is_fail(ret_val):
                return ret_val
            self.debug_print(json_resp)
            if json_resp.get('response_code') == 1:
                return self._update_action_result_for_detonate_file(action_result, json_resp)
            if json_resp.get('response_code') == 0:
                return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_RESOURCE_NOT_FOUND)

            attempt += 1
            time.sleep(60)

        action_result.update_summary({'scan_id': scan_id})
        return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_MAX_POLLS_REACHED)

    def _detonate_file(self, param):

        action_result = self.add_action_result(ActionResult(param))
        config = self.get_config()
        params = {'apikey': self._apikey}
        vault_id = param['vault_id']

        try:
            file_info = Vault.get_file_info(vault_id=vault_id, container_id=self.get_container_id())[0]
            self.debug_print(file_info)

            file_path = file_info['path']
            file_name = file_info['name']
            file_sha256 = file_info['metadata']['sha256']
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to retrieve file from vault: {0}".format(e))

        params['resource'] = file_sha256

        ret_val, json_resp = self._make_rest_call(action_result, '/file/report', params=params, method="post")
        if phantom.is_fail(ret_val):
            return ret_val

        try:
            response_code = json_resp['response_code']
        except KeyError:
            return action_result.set_status(phantom.APP_ERROR, "Malformed response object, missing response_code.")

        if response_code == 1:  # Resource found on server
            return self._update_action_result_for_detonate_file(action_result, json_resp)
        if response_code == 0:  # Not found on server
            files = {'file': (file_name, open(file_path, 'rb'))}
            params = {'apikey': self._apikey}
            ret_val, json_resp = self._make_rest_call(action_result, '/file/scan', params=params, files=files, method="post")
            if phantom.is_fail(ret_val):
                return ret_val
            try:
                scan_id = json_resp['scan_id']
            except KeyError:
                return action_result.set_status(phantom.APP_ERROR, "Malformed response object, missing scan_id.")

        poll_interval = int(config.get('poll_interval', 5))
        return self._poll_for_result(action_result, scan_id, poll_interval)

    def _get_report(self, param):

        action_result = self.add_action_result(ActionResult(param))
        config = self.get_config()
        scan_id = param['scan_id']
        poll_interval = int(config.get('poll_interval', 5))
        return self._poll_for_result(action_result, scan_id, poll_interval)

    def _get_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()

        json_key = phantom.APP_JSON_HASH
        file_hash = param[json_key]

        query_url = GET_FILE_API_URL

        params = {json_key: file_hash, VIRUSTOTAL_JSON_APIKEY: self._apikey}

        # Format the request with the URL and the params
        self.save_progress(VIRUSTOTAL_MSG_CREATED_URL, query_url=query_url)
        try:
            r = requests.get(query_url, params=params, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            self.debug_print("_get_file", e)
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_CONNECTION_ERROR, e)

        self.debug_print("status_code", r.status_code)

        if (r.status_code == 204):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT.format(code=r.status_code))

        if (r.status_code == 403):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_FORBIDDEN.format(code=r.status_code))

        if (r.status_code == 404):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_NOT_FOUND.format(code=r.status_code))

        if (r.status_code != 200):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_RETURNED_ERROR_CODE.format(code=r.status_code))

        return self._save_file_to_vault(action_result, r, file_hash)

    def _save_file_to_vault(self, action_result, response, file_hash):

        # Create a tmp directory on the vault partition
        guid = uuid.uuid4()
        local_dir = '/vault/tmp/{}'.format(guid)
        self.save_progress("Using temp directory: {0}".format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to create temporary folder '/vault/tmp'.", e)

        file_path = "{0}/{1}".format(local_dir, file_hash)

        # open and download the file
        with open(file_path, 'wb') as f:
            f.write(response.content)

        contains = []
        file_ext = ''
        magic_str = magic.from_file(file_path)
        for regex, cur_contains, extension in self.MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)
                if (not file_ext):
                    file_ext = extension

        file_name = '{}{}'.format(file_hash, file_ext)

        # move the file to the vault
        vault_ret_dict = Vault.add_attachment(file_path, self.get_container_id(), file_name=file_name, metadata={'contains': contains})
        curr_data = {}

        if (vault_ret_dict['succeeded']):
            curr_data[phantom.APP_JSON_VAULT_ID] = vault_ret_dict[phantom.APP_JSON_HASH]
            curr_data[phantom.APP_JSON_NAME] = file_name
            if (contains):
                curr_data['file_type'] = ','.join(contains)
            action_result.add_data(curr_data)
            action_result.update_summary(curr_data)
            action_result.set_status(phantom.APP_SUCCESS, "File successfully retrieved and added to vault")
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict['message'])

        # remove the /tmp/<> temporary directory
        shutil.rmtree(local_dir)

        return action_result.get_status()

    def _test_asset_connectivity(self, param):

        # Create a hash of a random string
        random_string = phantom.get_random_chars(size=10)
        md5sum = hashlib.md5(random_string).hexdigest()

        params = {'resource': md5sum, VIRUSTOTAL_JSON_APIKEY: self._apikey}

        self.save_progress(VIRUSTOTAL_MSG_CONNECTING)

        config = self.get_config()

        try:
            r = requests.get(FILE_API_URL, params=params, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            self.debug_print('_test_asset_connectivity', e)
            self.set_status(phantom.APP_ERROR, VIRUSTOTAL_ERR_CONNECTIVITY_TEST, e)
            self.append_to_message(VIRUSTOTAL_MSG_CHECK_APIKEY)
            # self.save_progress('{0}. {1}'.format(VIRUSTOTAL_ERR_CONNECTIVITY_TEST, VIRUSTOTAL_MSG_CHECK_APIKEY))
            return self.get_status()

        if (r.status_code == 204):
            return self.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT.format(code=r.status_code))

        if (r.status_code != 200):
            self.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_RETURNED_ERROR_CODE.format(code=r.status_code))
            self.append_to_message(VIRUSTOTAL_MSG_CHECK_APIKEY)
            # self.save_progress('{0}. {1}'.format(VIRUSTOTAL_ERR_CONNECTIVITY_TEST, VIRUSTOTAL_MSG_CHECK_APIKEY))
            return self.get_status()

        result = r.json()

        if ('resource' in result):
            self.set_status_save_progress(phantom.APP_SUCCESS, VIRUSTOTAL_SUCC_CONNECTIVITY_TEST)
        else:
            self.set_status_save_progress(phantom.APP_ERROR, VIRUSTOTAL_ERR_CONNECTIVITY_TEST)

        return self.get_status()

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()
        config = self.get_config()
        self._apikey = config[VIRUSTOTAL_JSON_APIKEY]
        self._rate_limit = config[VIRUSTOTAL_JSON_RATE_LIMIT]
        self._verify_ssl = config[phantom.APP_JSON_VERIFY]

        if (action == self.ACTION_ID_QUERY_FILE):
            result = self._query_file(param)
        elif (action == self.ACTION_ID_QUERY_URL):
            result = self._query_url(param)
        elif (action == self.ACTION_ID_QUERY_DOMAIN):
            result = self._query_domain(param)
        elif (action == self.ACTION_ID_QUERY_IP):
            result = self._query_ip(param)
        elif (action == self.ACTION_ID_GET_FILE):
            result = self._get_file(param)
        elif (action == self.ACTION_ID_DETONATE_FILE):
            result = self._detonate_file(param)
        elif (action == self.ACTION_ID_GET_REPORT):
            result = self._get_report(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            result = self._test_asset_connectivity(param)

        return result

    def finalize(self):

        # Init the positives
        total_positives = 0

        # Loop through the action results that we had added before
        for action_result in self.get_action_results():
            action = self.get_action_identifier()
            if (action != self.ACTION_ID_QUERY_URL) and (action != self.ACTION_ID_QUERY_FILE):
                continue
            # get the summary of the current one
            summary = action_result.get_summary()

            if (VIRUSTOTAL_JSON_POSITIVES not in summary):
                continue

            # If the detection is true
            if (summary[VIRUSTOTAL_JSON_POSITIVES] > 0):
                total_positives += 1

        self.update_summary({VIRUSTOTAL_JSON_TOTAL_POSITIVES: total_positives})


if __name__ == '__main__':

    import sys
    import pudb
    import json

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = VirustotalConnector()
        connector.print_progress_message = True
        result = connector._handle_action(json.dumps(in_json), None)

        print result

    exit(0)
