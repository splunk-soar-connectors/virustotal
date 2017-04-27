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
import magic
import shutil
import hashlib
import requests

requests.packages.urllib3.disable_warnings()


class VirustotalConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_QUERY_FILE = "lookup_file"
    ACTION_ID_QUERY_URL = "lookup_url"
    ACTION_ID_QUERY_DOMAIN = "lookup_domain"
    ACTION_ID_QUERY_IP = "lookup_ip"
    ACTION_ID_GET_FILE = "get_file"

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
