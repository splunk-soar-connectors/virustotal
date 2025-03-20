# File: virustotal_connector.py
#
# Copyright (c) 2016-2025 Splunk Inc.
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
# Phantom imports
import calendar
import hashlib
import ipaddress
import json

# Other imports used by this connector
import os
import re
import shutil
import sys
import time
import uuid

import magic
import phantom.app as phantom
import phantom.rules as ph_rules
import requests
from bs4 import BeautifulSoup, UnicodeDammit
from phantom.app import ActionResult, BaseConnector
from phantom.vault import Vault

# THIS Connector imports
from virustotal_consts import *


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
    ACTION_ID_DETONTATE_URL = "detonate_url"

    MAGIC_FORMATS = [
        (re.compile("^PE.* Windows"), ["pe file"], ".exe"),
        (re.compile("^MS-DOS executable"), ["pe file"], ".exe"),
        (re.compile("^PDF "), ["pdf"], ".pdf"),
        (re.compile("^MDMP crash"), ["process dump"], ".dmp"),
        (re.compile("^Macromedia Flash"), ["flash"], ".flv"),
        (re.compile("^tcpdump capture"), ["pcap"], ".pcap"),
    ]

    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()

        self._python_version = None
        self._state = None
        self._apikey = None
        self._requests_per_minute = None
        self._verify_ssl = None
        self._poll_interval = None

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.

        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str -
        Python 2')
        """
        try:
            if input_str and self._python_version < 3:
                input_str = UnicodeDammit(input_str).unicode_markup.encode("utf-8")
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_code = VIRUSTOTAL_UNKNOWN_ERROR_CODE_MESSAGE
                    error_message = e.args[0]
            else:
                error_code = VIRUSTOTAL_UNKNOWN_ERROR_CODE_MESSAGE
                error_message = VIRUSTOTAL_UNKNOWN_ERROR_MESSAGE
        except:
            error_code = VIRUSTOTAL_UNKNOWN_ERROR_CODE_MESSAGE
            error_message = VIRUSTOTAL_UNKNOWN_ERROR_MESSAGE
        try:
            error_message = self._handle_py_ver_compat_for_input_str(error_message)
        except TypeError:
            error_message = VIRUSTOTAL_ERROR_MESSAGE
        except:
            error_message = VIRUSTOTAL_UNKNOWN_ERROR_MESSAGE

        return f"Error Code: {error_code}. Error Message: {error_message}"

    def _is_ip(self, input_ip_address):
        """
        Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """
        ip_address_input = input_ip_address
        try:
            ipaddress.ip_address(UnicodeDammit(ip_address_input).unicode_markup)
        except:
            return False
        return True

    def _process_empty_response(self, response, action_result):
        if 200 <= response.status_code < 205:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):
        # An html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")

            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()

            error_text = soup.text.encode("utf-8")
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except:
            error_text = "Cannot parse error details"

        if error_text:
            message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"
        else:
            message = f"Status Code: {status_code}. Error:\n{VIRUSTOTAL_MESSAGE_GENERAL_ISSUE}\n"

        message = message.replace("{", "{{").replace("}", "}}")

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            self.save_progress("Cannot parse JSON")
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON", e), None)

        if 200 <= r.status_code < 205:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # It's been noticed that VT sometimes sends back a list with a single item, instead of a dictionary
        # Happened a couple of times on customer site
        if type(resp_json) == list:
            self.debug_print("Got a list, will be using the first item")
            resp_json = resp_json[0]

        if type(resp_json) != dict:
            return action_result.set_status(phantom.APP_ERROR, "Response from server not a type that is expected")

        action_result.add_data(resp_json)
        message = r.text.replace("{", "{{").replace("}", "}}")
        return RetVal(
            action_result.set_status(phantom.APP_ERROR, f"Error from server, Status Code: {r.status_code} data returned: {message}"), resp_json
        )

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text.encode("utf-8")})
            action_result.add_debug_data({"r_headers": r.headers})

        # There are just too many differences in the response to handle all of them in the same function
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not an html or json, handle if it is a successful empty response
        if (200 <= r.status_code < 205) and (not r.text):
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {} Data from server: {}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, action_result, endpoint, params=None, body=None, headers=None, files=None, method="get"):
        """Returns 2 values, use RetVal"""

        url = BASE_URL + endpoint
        self.save_progress(VIRUSTOTAL_MESSAGE_CREATED_URL, url=url)

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Unsupported method: {method}"), None)
        except Exception as e:
            # Set the action_result status to error, the handler function will most probably return as is
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Handled exception: {error_message}"), None)

        # if number of requests are provided by user then check for limit.
        if self._requests_per_minute:
            self._check_rate_limit()

        try:
            response = request_func(url, params=params, json=body, headers=headers, files=files, verify=self._verify_ssl)
        except Exception as e:
            # Set the action_result status to error, the handler function will most probably return as is
            # Adding regex to hide sensitive information from the error message
            error_message = self._get_error_message_from_exception(e)
            error_message = re.sub(r"(apikey=)([0-9]+([a-zA-Z]+[0-9]+)+)", r"\1xxxxxxxxxxxxxxxxx", error_message)
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Error connecting: {error_message}"), None)

        if self._requests_per_minute:
            self._track_rate_limit(response.headers.get("Date"))

        self.debug_print(response.url)

        if response.status_code == 204:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT.format(code=response.status_code)), None
            )

        return self._process_response(response, action_result)

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :return: integer value of the parameter or None in case of failure
        """

        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_VALIDATE_INTEGER_MESSAGE.format(key=key)), None
                parameter = int(parameter)

            except Exception:
                return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_VALIDATE_INTEGER_MESSAGE.format(key=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_VALIDATE_NON_NEGATIVE_INTEGER_MESSAGE.format(key=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_VALIDATE_POSITIVE_INTEGER_MESSAGE.format(key=key)), None

        return phantom.APP_SUCCESS, parameter

    def _check_rate_limit(self, count=1):
        """Check to see if the rate limit is within the "4 requests per minute". Wait and check again if the request is too soon.

        Returns:
            boolean: True, when the rate limitation is not greater than or equal to the allocated amount
        """
        self.debug_print("Checking rate limit")

        state = self.load_state()
        if not state or not state.get("rate_limit_timestamps"):
            self.save_state({"rate_limit_timestamps": []})
            return True

        # Cleanup existing timestamp list to only have the timestamps within the last 60 seconds
        # Replace the 61 to 60 seconds because it was printing the line no 300 multiple times while running test connectivity.
        # So there should be 1 seconds difference between timestamps and waittime.
        # Also in older version as well as virustotalv3 we have 60 seconds.
        timestamps = state["rate_limit_timestamps"]
        current_time = int(time.time())
        timestamps = [time for time in timestamps if current_time - time <= 60]

        # Save new cleaned list
        self.save_state({"rate_limit_timestamps": timestamps})

        # If there are too many within the last minute, we will wait the min_time_diff and try again
        # if len(timestamps) >= 4:
        if len(timestamps) >= self._requests_per_minute:
            wait_time = 61 - (current_time - min(t for t in timestamps))

            self.send_progress(f"Rate limit check #{count}. Waiting {wait_time} seconds for rate limitation to pass and will try again.")
            time.sleep(wait_time)
            # Use recursive call to try again
            return self._check_rate_limit(count + 1)

        return True

    def _track_rate_limit(self, timestamp):
        """Track timestamp of VirusTotal requests to stay within rate limitations

        Args:
            timestamp (str): Timestamp from the last requests call (e.g., 'Tue, 12 Jun 2018 16:39:37 GMT')

        Returns:
            boolean: True
        """
        self.debug_print("Tracking rate limit")

        if not timestamp:
            epoch = int(time.time())
        else:
            epoch = int(calendar.timegm(time.strptime(timestamp, "%a, %d %b %Y %H:%M:%S GMT")))

        state = self.load_state()
        timestamps = state.get("rate_limit_timestamps", [])
        timestamps.append(epoch)

        self.save_state({"rate_limit_timestamps": timestamps})

        return True

    def _query_ip_domain(self, param, object_name, query_url):
        action_result = self.add_action_result(ActionResult(dict(param)))

        object_value = param[object_name]

        item_summary = action_result.set_summary({})
        item_summary[VIRUSTOTAL_JSON_DETECTED_URLS] = 0

        params = {object_name: object_value, VIRUSTOTAL_JSON_APIKEY: self._apikey}

        self.save_progress(VIRUSTOTAL_MESSAGE_CONNECTING)

        ret_val, json_resp = self._make_rest_call(action_result, query_url, params=params)
        if phantom.is_fail(ret_val):
            return ret_val

        # add the data
        action_result.add_data(json_resp)

        if "response_code" not in json_resp:
            return action_result.set_status(
                phantom.APP_ERROR, VIRUSTOTAL_ERROR_MESSAGE_OBJECT_QUERIED, object_name=object_name, object_value=object_value
            )

        action_result.set_status(phantom.APP_SUCCESS)

        if json_resp["response_code"] == 0:
            action_result.set_status(phantom.APP_SUCCESS, VIRUSTOTAL_MESSAGE_OBJECT_NOT_FOUND, object_name=object_name.capitalize())

        if "Alexa rank" in json_resp:
            item_summary[VIRUSTOTAL_JSON_ALEXA_RANK] = json_resp["Alexa rank"]

        if "detected_urls" in json_resp:
            item_summary[VIRUSTOTAL_JSON_DETECTED_URLS] = len(json_resp["detected_urls"])

        if "detected_downloaded_samples" in json_resp:
            item_summary[VIRUSTOTAL_JSON_DOWNLOADED_SAMPLES] = len(json_resp["detected_downloaded_samples"])

        if "detected_communicating_samples" in json_resp:
            item_summary[VIRUSTOTAL_JSON_COMMUNICATING_SAMPLES] = len(json_resp["detected_communicating_samples"])

        return action_result.get_status()

    def _query_file_url(self, param, json_key, query_url):
        object_value = param[json_key]
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {"resource": object_value, VIRUSTOTAL_JSON_APIKEY: self._apikey}

        # Format the request with the URL and the params
        self.save_progress(VIRUSTOTAL_MESSAGE_CREATED_URL, query_url=query_url)

        ret_val, json_resp = self._make_rest_call(action_result, query_url, params=params)
        if phantom.is_fail(ret_val):
            return ret_val

        # add the data
        action_result.add_data(json_resp)

        # update the summary
        action_result.update_summary(
            {VIRUSTOTAL_JSON_TOTAL_SCANS: json_resp.get("total", 0), VIRUSTOTAL_JSON_POSITIVES: json_resp.get("positives", 0)}
        )

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_url(self, param):
        json_key = phantom.APP_JSON_URL
        query_url = URL_API_ENDPOINT

        return self._query_file_url(param, json_key, query_url)

    def _lookup_file(self, param):
        json_key = phantom.APP_JSON_HASH
        query_url = FILE_API_ENDPOINT

        return self._query_file_url(param, json_key, query_url)

    def _lookup_ip(self, param):
        query_url = IP_API_ENDPOINT
        object_name = phantom.APP_JSON_IP

        return self._query_ip_domain(param, object_name, query_url)

    def _lookup_domain(self, param):
        query_url = DOMAIN_API_ENDPOINT
        object_name = phantom.APP_JSON_DOMAIN

        return self._query_ip_domain(param, object_name, query_url)

    def _update_action_result_for_detonate(self, action_result, json_resp):
        action_result.add_data(json_resp)

        try:
            scan_id = json_resp["scan_id"]
        except KeyError:
            return action_result.set_status(phantom.APP_ERROR, "Malformed response object, missing scan_id.")

        # update the summary
        action_result.update_summary(
            {
                "scan_id": scan_id,
                VIRUSTOTAL_JSON_TOTAL_SCANS: json_resp.get("total", 0),
                VIRUSTOTAL_JSON_POSITIVES: json_resp.get("positives", 0),
            }
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _poll_for_result(self, action_result, scan_id, poll_interval, report_type="file"):
        attempt = 1
        params = {"apikey": self._apikey, "resource": scan_id}
        if report_type == "file":
            endpoint = FILE_API_ENDPOINT
        elif report_type == "url":
            endpoint = URL_API_ENDPOINT
        else:
            endpoint = FILE_API_ENDPOINT

        # Since we sleep 1 minute between each poll, the poll_interval is
        # equal to the number of attempts
        poll_attempts = poll_interval
        while attempt <= poll_attempts:
            self.save_progress(f"Polling attempt {attempt} of {poll_attempts}")
            ret_val, json_resp = self._make_rest_call(action_result, endpoint, params, method="post")
            if phantom.is_fail(ret_val):
                return ret_val
            self.debug_print(json_resp)
            if json_resp.get("response_code") == 1:
                return self._update_action_result_for_detonate(action_result, json_resp)
            if json_resp.get("response_code") == 0:
                return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_RESOURCE_NOT_FOUND)

            attempt += 1
            time.sleep(60)

        action_result.update_summary({"scan_id": scan_id})
        return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_MAX_POLLS_REACHED)

    def _detonate_file(self, param):
        action_result = self.add_action_result(ActionResult(param))
        params = {"apikey": self._apikey}
        vault_id = param["vault_id"]
        try:
            _, _, file_info = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
            file_info = next(iter(file_info))
            self.debug_print(file_info)

            file_path = file_info["path"]
            file_name = file_info["name"]
            file_sha256 = file_info["metadata"]["sha256"]
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            if VIRUSTOTAL_EXPECTED_ERROR_MESSAGE in error_message:
                return action_result.set_status(phantom.APP_ERROR, "Unable to retrieve file from vault. Invalid vault_id.")
            else:
                return action_result.set_status(phantom.APP_ERROR, f"Unable to retrieve file from vault: {error_message}")

        params["resource"] = file_sha256

        ret_val, json_resp = self._make_rest_call(action_result, FILE_API_ENDPOINT, params=params, method="post")
        if phantom.is_fail(ret_val):
            return ret_val

        try:
            response_code = json_resp["response_code"]
        except KeyError:
            return action_result.set_status(phantom.APP_ERROR, "Malformed response object, missing response_code.")

        if response_code == 1:  # Resource found on server
            return self._update_action_result_for_detonate(action_result, json_resp)
        if response_code == 0:  # Not found on server
            files = {"file": (file_name, open(file_path, "rb"))}
            params = {"apikey": self._apikey}
            ret_val, json_resp = self._make_rest_call(action_result, UPLOAD_FILE_ENDPOINT, params=params, files=files, method="post")
            if phantom.is_fail(ret_val):
                return ret_val
            try:
                scan_id = json_resp["scan_id"]
            except KeyError:
                return action_result.set_status(phantom.APP_ERROR, "Malformed response object, missing scan_id.")

        return self._poll_for_result(action_result, scan_id, self._poll_interval)

    def _detonate_url(self, param):
        action_result = self.add_action_result(ActionResult(param))
        params = {"apikey": self._apikey}
        params["resource"] = param["url"]
        # the 'scan' param will tell VT to automatically
        # queue a scan for the URL if a report is not found
        params["scan"] = 1

        # check if report already exists
        ret_val, json_resp = self._make_rest_call(action_result, URL_API_ENDPOINT, params=params, method="post")
        if phantom.is_fail(ret_val):
            return ret_val
        try:
            response_code = json_resp["response_code"]
        except KeyError:
            return action_result.set_status(phantom.APP_ERROR, "Malformed response object, missing response_code.")

        if response_code == 1 and "positives" in json_resp:  # Resource found on server
            return self._update_action_result_for_detonate(action_result, json_resp)
        if response_code == -1:
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_INVALID_URL)

        # Not found on server, detonate now
        try:
            scan_id = json_resp["scan_id"]
            action_result.update_summary({"scan_id": scan_id})
        except KeyError:
            return action_result.set_status(phantom.APP_ERROR, "Malformed response object, missing scan_id.")

        return self._poll_for_result(action_result, scan_id, self._poll_interval, report_type="url")

    def _get_report(self, param):
        action_result = self.add_action_result(ActionResult(param))
        scan_id = param["scan_id"]
        report_type = param["report_type"]
        return self._poll_for_result(action_result, scan_id, self._poll_interval, report_type)

    def _get_file(self, param):
        """Note: Need to have this action utilize the _make_rest_call method, but we are unable to test it with our current API key."""
        action_result = self.add_action_result(ActionResult(dict(param)))

        json_key = phantom.APP_JSON_HASH
        file_hash = param[json_key]

        query_url = BASE_URL + GET_FILE_API_ENDPOINT

        params = {json_key: file_hash, VIRUSTOTAL_JSON_APIKEY: self._apikey}

        # if number of requests are provided by user then check for limit.
        if self._requests_per_minute:
            self._check_rate_limit()

        # Format the request with the URL and the params
        self.save_progress(VIRUSTOTAL_MESSAGE_CREATED_URL, query_url=query_url)
        try:
            r = requests.get(query_url, params=params, verify=self._verify_ssl, timeout=DEFAULT_REQUEST_TIMEOUT)
        except Exception as e:
            self.debug_print("_get_file", e)
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_CONNECTION_ERROR, e)

        if self._requests_per_minute:
            self._track_rate_limit(r.headers.get("Date"))

        self.debug_print("status_code", r.status_code)

        if r.status_code == 204:
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT.format(code=r.status_code))

        if r.status_code == 403:
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_FORBIDDEN.format(code=r.status_code))

        if r.status_code == 404:
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_ERROR_NOT_FOUND.format(code=r.status_code))

        if r.status_code != 200:
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_SERVER_RETURNED_ERROR_CODE.format(code=r.status_code))

        return self._save_file_to_vault(action_result, r, file_hash)

    def _save_file_to_vault(self, action_result, response, file_hash):
        # Create a tmp directory on the vault partition

        guid = uuid.uuid4()

        if hasattr(Vault, "get_vault_tmp_dir"):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = "/vault/tmp"

        local_dir = temp_dir + f"/{guid}"
        self.save_progress(f"Using temp directory: {guid}")

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Unable to create temporary folder {temp_dir}.", e)

        file_path = f"{local_dir}/{file_hash}"

        # open and download the file
        with open(file_path, "wb") as f:
            f.write(response.content)

        contains = []
        file_ext = ""
        magic_str = magic.from_file(file_path)
        for regex, cur_contains, extension in self.MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)
                if not file_ext:
                    file_ext = extension

        file_name = f"{file_hash}{file_ext}"

        # move the file to the vault
        vault_ret_dict = Vault.add_attachment(file_path, self.get_container_id(), file_name=file_name, metadata={"contains": contains})

        curr_data = {}

        if vault_ret_dict["succeeded"]:
            curr_data[phantom.APP_JSON_VAULT_ID] = vault_ret_dict[phantom.APP_JSON_HASH]
            curr_data[phantom.APP_JSON_NAME] = file_name
            if contains:
                curr_data["file_type"] = ",".join(contains)
            action_result.add_data(curr_data)
            action_result.update_summary(curr_data)
            action_result.set_status(phantom.APP_SUCCESS, "File successfully retrieved and added to vault")
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict["message"])

        # remove the /tmp/<> temporary directory
        shutil.rmtree(local_dir)

        return action_result.get_status()

    def _test_asset_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Create a hash of a random string
        random_string = phantom.get_random_chars(size=10)
        # Python 3 hashlib requires bytes when hashing
        sha256sum = hashlib.sha256(random_string.encode("utf-8")).hexdigest()

        params = {"resource": sha256sum, VIRUSTOTAL_JSON_APIKEY: self._apikey}

        self.save_progress(VIRUSTOTAL_MESSAGE_CONNECTING)

        ret_val, json_resp = self._make_rest_call(action_result, FILE_API_ENDPOINT, params=params)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_MESSAGE_CHECK_APIKEY)

        if "resource" in json_resp:
            action_result.set_status(phantom.APP_SUCCESS, VIRUSTOTAL_SUCC_CONNECTIVITY_TEST)
        else:
            action_result.set_status(phantom.APP_ERROR, VIRUSTOTAL_ERROR_CONNECTIVITY_TEST)

        self.save_progress(action_result.get_message())
        return action_result.get_status()

    def handle_action(self, param):
        """Function that handles all the actions

        Args:
            param (dict): Parameters sent in by a user or playbook

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()

        if action == self.ACTION_ID_QUERY_FILE:
            result = self._lookup_file(param)
        elif action == self.ACTION_ID_QUERY_URL:
            result = self._lookup_url(param)
        elif action == self.ACTION_ID_QUERY_DOMAIN:
            result = self._lookup_domain(param)
        elif action == self.ACTION_ID_QUERY_IP:
            result = self._lookup_ip(param)
        elif action == self.ACTION_ID_GET_FILE:
            result = self._get_file(param)
        elif action == self.ACTION_ID_DETONATE_FILE:
            result = self._detonate_file(param)
        elif action == self.ACTION_ID_DETONTATE_URL:
            result = self._detonate_url(param)
        elif action == self.ACTION_ID_GET_REPORT:
            result = self._get_report(param)
        elif action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            result = self._test_asset_connectivity(param)

        return result

    def _initialize_error(self, msg, exception=None):
        if self.get_action_identifier() == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            self.save_progress(msg)
            self.save_progress(self._get_error_message_from_exception(exception))
            self.set_status(phantom.APP_ERROR, "Test Connectivity Failed")
        else:
            self.set_status(phantom.APP_ERROR, msg, exception)
        return phantom.APP_ERROR

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

            if VIRUSTOTAL_JSON_POSITIVES not in summary:
                continue

            # If the detection is true
            if summary[VIRUSTOTAL_JSON_POSITIVES] > 0:
                total_positives += 1

        self.update_summary({VIRUSTOTAL_JSON_TOTAL_POSITIVES: total_positives})

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        if self._state is None:
            self._state = dict()

        self.set_validator("ipv6", self._is_ip)

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")
        # get the asset config
        try:
            config = self.get_config()
        except:
            return phantom.APP_ERROR

        self._apikey = config[VIRUSTOTAL_JSON_APIKEY]
        self._verify_ssl = True

        try:
            if int(config.get("poll_interval", 5)) > 0:
                self._poll_interval = int(config.get("poll_interval", 5))
            else:
                return self.set_status(phantom.APP_ERROR, VIRUSTOTAL_POLL_INTERVAL_ERROR_MESSAGE)

        except ValueError:
            return self.set_status(phantom.APP_ERROR, VIRUSTOTAL_POLL_INTERVAL_ERROR_MESSAGE)

        # Validate the 'requests_per_minute' parameter.
        ret_val, self._requests_per_minute = self._validate_integers(self, config.get("requests_per_minute"), "requests_per_minute")
        if phantom.is_fail(ret_val):
            return self.get_status()

        return phantom.APP_SUCCESS


if __name__ == "__main__":
    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument("-v", "--verify", action="store_true", help="verify", required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            sys.exit()

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = VirustotalConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit()
