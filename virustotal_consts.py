# --
# File: virustotal_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --


# Status/Progress Messages
VIRUSTOTAL_MSG_CREATED_URL = "Created Query URL: {query_url}"
VIRUSTOTAL_MSG_GOT_RESP = "Got Response from VirusTotal"
VIRUSTOTAL_SUCC_MSG_OBJECT_QUERIED = "VirusTotal query for {object_name} '{object_value}' finished"
VIRUSTOTAL_ERR_MSG_OBJECT_QUERIED = "VirusTotal query for {object_name} '{object_value}' failed"
VIRUSTOTAL_MSG_CONNECTING = "Querying VirusTotal"
VIRUSTOTAL_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
VIRUSTOTAL_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
VIRUSTOTAL_MSG_CHECK_APIKEY = 'Please check your APIKEY or the network connectivity'
VIRUSTOTAL_MSG_OBJECT_NOT_FOUND = '{object_name} not found in results. Not in the service database'
VIRUSTOTAL_SERVER_RETURNED_ERROR_CODE = "Server returned error code: {code}"
VIRUSTOTAL_SERVER_ERROR_RATE_LIMIT = "Server returned error code: {code}. Exceeded API request rate limit."
VIRUSTOTAL_SERVER_ERROR_FORBIDDEN = "Server returned error code: {code}. API key does not have permission for this action."
VIRUSTOTAL_SERVER_ERROR_NOT_FOUND = "Server returned error code: {code}. Requested file not found."
VIRUSTOTAL_NO_RESPONSE = "Server did not return a response for the object queried"
VIRUSTOTAL_SERVER_CONNECTION_ERROR = "Server connection error"
VIRUSTOTAL_MISSING_PARAMETERS = "Missing parameters. At least one of 'scan_id' or 'file_vault_id' required."
VIRUSTOTAL_RESOURCE_NOT_FOUND = "Resource not found in VirusTotal database"
VIRUSTOTAL_MAX_POLLS_REACHED = "Reached max polling attempts. Try rerunning the action with the 'scan_id' parameter"

# Jsons used in params, result, summary etc.
VIRUSTOTAL_JSON_APIKEY = "apikey"
VIRUSTOTAL_JSON_DETECTIONS = "detections"
VIRUSTOTAL_JSON_FOUND = "found"
VIRUSTOTAL_JSON_POSITIVES = "positives"
VIRUSTOTAL_JSON_TOTAL_SCANS = "total_scans"
VIRUSTOTAL_JSON_TOTAL_POSITIVES = "total_positives"
VIRUSTOTAL_JSON_DETECTED_URLS = "detected_urls"
VIRUSTOTAL_JSON_VERBOSE_MSG = "message"
VIRUSTOTAL_JSON_ALEXA_RANK = "alexa_rank"
VIRUSTOTAL_JSON_DOWNLOADED_SAMPLES = "downloaded_samples"
VIRUSTOTAL_JSON_COMMUNICATING_SAMPLES = "communicating_samples"

# Other constants used in the connector
FILE_API_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
GET_FILE_API_URL = 'https://www.virustotal.com/vtapi/v2/file/download'
URL_API_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
DOMAIN_API_URL = 'https://www.virustotal.com/vtapi/v2/domain/report'
IP_API_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
UPLOAD_FILE_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
