# File: virustotal_consts.py
#
# Copyright (c) 2016-2021 Splunk Inc.
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
# Status/Progress Messages
VIRUSTOTAL_MSG_CREATED_URL = "Created Query URL: {url}"
VIRUSTOTAL_ERR_MSG_OBJECT_QUERIED = "VirusTotal query for {object_name} '{object_value}' failed"
VIRUSTOTAL_MSG_CONNECTING = "Querying VirusTotal"
VIRUSTOTAL_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
VIRUSTOTAL_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
VIRUSTOTAL_MSG_CHECK_APIKEY = 'Please check your API KEY or the network connectivity'  # pragma: allowlist secret
VIRUSTOTAL_MSG_GENERAL_ISSUE = 'Either API key is wrong, network connectivity is hampered, or any other issue might have happened'
VIRUSTOTAL_MSG_OBJECT_NOT_FOUND = '{object_name} not found in results. Not in the service database'
VIRUSTOTAL_SERVER_RETURNED_ERROR_CODE = "Server returned error code: {code}"
VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT = (
    "Server returned error code: {code}. Exceeded API request rate limit. Try enabling rate limitation for this asset."
)
VIRUSTOTAL_SERVER_ERROR_FORBIDDEN = "Server returned error code: {code}. API key does not have permission for this action."
VIRUSTOTAL_SERVER_ERROR_NOT_FOUND = "Server returned error code: {code}. Requested file not found."
VIRUSTOTAL_SERVER_CONNECTION_ERROR = "Server connection error"
VIRUSTOTAL_RESOURCE_NOT_FOUND = "Resource not found in VirusTotal database"
VIRUSTOTAL_INVALID_URL = "Invalid URL specified. Please validate the input and try again"
VIRUSTOTAL_MAX_POLLS_REACHED = "Reached max polling attempts. Try rerunning the action with the 'scan_id' parameter"
VIRUSTOTAL_EXPECTED_ERROR_MSG = "List index out of range"
VIRUSTOTAL_UNKNOWN_ERROR_CODE_MESSAGE = "Error code unavailable"
VIRUSTOTAL_UNKNOWN_ERROR_MESSAGE = "Unknown error occurred. Please check the asset configuration and|or action parameters."
VIRUSTOTAL_POLL_INTERVAL_ERROR_MESSAGE = (
    "Please provide a valid positive integer for 'Number of minutes to poll for a detonation result' parameter."
)
VIRUSTOTAL_VALIDATE_INTEGER_MESSAGE = "Please provide a valid integer value in the {key} parameter"
VIRUSTOTAL_ERROR_MESSAGE = (
    "Error occurred while connecting to the VirusTotal server. Please check the asset configuration and|or the action parameters."
)
VIRUSTOTAL_VALIDATE_NON_NEGATIVE_INTEGER_MESSAGE = "Please provide a valid non-negative integer value in the {key} parameter"
VIRUSTOTAL_VALIDATE_POSITIVE_INTEGER_MESSAGE = "Please provide a positive integer value in the {key} parameter"

# Jsons used in params, result, summary etc.
VIRUSTOTAL_JSON_APIKEY = "apikey"  # pragma: allowlist secret
VIRUSTOTAL_JSON_POSITIVES = "positives"
VIRUSTOTAL_JSON_TOTAL_SCANS = "total_scans"
VIRUSTOTAL_JSON_TOTAL_POSITIVES = "total_positives"
VIRUSTOTAL_JSON_DETECTED_URLS = "detected_urls"
VIRUSTOTAL_JSON_ALEXA_RANK = "alexa_rank"
VIRUSTOTAL_JSON_DOWNLOADED_SAMPLES = "downloaded_samples"
VIRUSTOTAL_JSON_COMMUNICATING_SAMPLES = "communicating_samples"

# Other constants used in the connector
BASE_URL = 'https://www.virustotal.com/vtapi/v2/'
FILE_API_ENDPOINT = 'file/report'
UPLOAD_FILE_ENDPOINT = 'file/scan'
GET_FILE_API_ENDPOINT = 'file/download'
URL_API_ENDPOINT = 'url/report'
DETONATE_URL_ENDPOINT = 'url/scan'
DOMAIN_API_ENDPOINT = 'domain/report'
IP_API_ENDPOINT = 'ip-address/report'
