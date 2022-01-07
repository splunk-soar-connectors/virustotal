[comment]: # "Auto-generated SOAR connector documentation"
# VirusTotal

Publisher: Splunk  
Connector Version: 2\.2\.2  
Product Vendor: VirusTotal  
Product Name: VirusTotal  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app integrates with the VirusTotal cloud to implement investigative and reputation actions using v2 APIs

[comment]: # " File: readme.md"
[comment]: # " Copyright (c) 2016-2021 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
**Playbook Backward Compatibility**

-   One old asset parameter is removed and new asset parameter has been added to the asset
    configuration given below. Hence, it is requested to the end-user please update their existing
    playbooks and provide values to this new parameter to ensure the correct functioning of the
    playbooks created on the earlier versions of the app.

      

    -   **For version 2.2.X :**

          

        -   Test Connectivity - **requests_per_minute** parameter has been added
        -   Test Connectivity - **rate_limit** parameter has been removed.

    -   **For version 2.1.X :**

          

        -   Test Connectivity - **rate_limit** parameter has been added

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Virustotal server. Below are the
default ports used by Splunk SOAR.

|         SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a VirusTotal asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**apikey** |  required  | password | VirusTotal API key
**poll\_interval** |  optional  | numeric | Number of minutes to poll for a detonation result \(Default\: 5\)
**requests\_per\_minute** |  optional  | numeric | Maximum number of requests per minute \(For public API, it can be set as 4\.\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[file reputation](#action-file-reputation) - Queries VirusTotal for file reputation info  
[url reputation](#action-url-reputation) - Queries VirusTotal for URL info  
[domain reputation](#action-domain-reputation) - Queries VirusTotal for domain info  
[ip reputation](#action-ip-reputation) - Queries VirusTotal for IP info  
[get file](#action-get-file) - Downloads a file from VirusTotal, and adds it to the vault  
[get report](#action-get-report) - Get the results using the scan id from a detonate file or detonate url action  
[detonate file](#action-detonate-file) - Upload a file to Virus Total and retrieve the analysis results  
[detonate url](#action-detonate-url) - Load a URL to Virus Total and retrieve analysis results  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'file reputation'
Queries VirusTotal for file reputation info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash to query | string |  `hash`  `sha256`  `sha1`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `sha256`  `sha1`  `md5` 
action\_result\.data\.\*\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.permalink | string |  `url` 
action\_result\.data\.\*\.positives | numeric | 
action\_result\.data\.\*\.resource | string |  `sha1` 
action\_result\.data\.\*\.response\_code | numeric | 
action\_result\.data\.\*\.scan\_date | string | 
action\_result\.data\.\*\.scan\_id | string |  `virustotal scan id` 
action\_result\.data\.\*\.scans\.\*\.detected | boolean | 
action\_result\.data\.\*\.scans\.\*\.result | string | 
action\_result\.data\.\*\.scans\.\*\.update | string | 
action\_result\.data\.\*\.scans\.\*\.version | string | 
action\_result\.data\.\*\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.total | numeric | 
action\_result\.data\.\*\.verbose\_msg | string | 
action\_result\.summary\.positives | numeric | 
action\_result\.summary\.total\_scans | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_positives | numeric |   

## action: 'url reputation'
Queries VirusTotal for URL info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.filescan\_id | string | 
action\_result\.data\.\*\.permalink | string |  `url` 
action\_result\.data\.\*\.positives | numeric | 
action\_result\.data\.\*\.resource | string |  `url` 
action\_result\.data\.\*\.response\_code | numeric | 
action\_result\.data\.\*\.scan\_date | string | 
action\_result\.data\.\*\.scan\_id | string |  `virustotal scan id` 
action\_result\.data\.\*\.scans\.\*\.detail | string | 
action\_result\.data\.\*\.scans\.\*\.detected | boolean | 
action\_result\.data\.\*\.scans\.\*\.result | string | 
action\_result\.data\.\*\.total | numeric | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.verbose\_msg | string | 
action\_result\.summary\.detections | boolean | 
action\_result\.summary\.found | boolean | 
action\_result\.summary\.positives | numeric | 
action\_result\.summary\.total\_scans | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_positives | numeric |   

## action: 'domain reputation'
Queries VirusTotal for domain info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.categories | string | 
action\_result\.data\.\*\.detected\_communicating\_samples\.\*\.date | string | 
action\_result\.data\.\*\.detected\_communicating\_samples\.\*\.positives | numeric | 
action\_result\.data\.\*\.detected\_communicating\_samples\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.detected\_communicating\_samples\.\*\.total | numeric | 
action\_result\.data\.\*\.detected\_downloaded\_samples\.\*\.date | string | 
action\_result\.data\.\*\.detected\_downloaded\_samples\.\*\.positives | numeric | 
action\_result\.data\.\*\.detected\_downloaded\_samples\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.detected\_downloaded\_samples\.\*\.total | numeric | 
action\_result\.data\.\*\.detected\_referrer\_samples\.\*\.date | string | 
action\_result\.data\.\*\.detected\_referrer\_samples\.\*\.positives | numeric | 
action\_result\.data\.\*\.detected\_referrer\_samples\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.detected\_referrer\_samples\.\*\.total | numeric | 
action\_result\.data\.\*\.detected\_urls\.\*\.positives | numeric | 
action\_result\.data\.\*\.detected\_urls\.\*\.scan\_date | string | 
action\_result\.data\.\*\.detected\_urls\.\*\.total | numeric | 
action\_result\.data\.\*\.detected\_urls\.\*\.url | string |  `url`  `file name` 
action\_result\.data\.\*\.pcaps | string |  `sha256` 
action\_result\.data\.\*\.resolutions\.\*\.ip\_address | string |  `ip` 
action\_result\.data\.\*\.resolutions\.\*\.last\_resolved | string | 
action\_result\.data\.\*\.response\_code | numeric | 
action\_result\.data\.\*\.subdomains | string |  `domain` 
action\_result\.data\.\*\.undetected\_communicating\_samples\.\*\.date | string | 
action\_result\.data\.\*\.undetected\_communicating\_samples\.\*\.positives | numeric | 
action\_result\.data\.\*\.undetected\_communicating\_samples\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.undetected\_communicating\_samples\.\*\.total | numeric | 
action\_result\.data\.\*\.undetected\_downloaded\_samples\.\*\.date | string | 
action\_result\.data\.\*\.undetected\_downloaded\_samples\.\*\.positives | numeric | 
action\_result\.data\.\*\.undetected\_downloaded\_samples\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.undetected\_downloaded\_samples\.\*\.total | numeric | 
action\_result\.data\.\*\.undetected\_referrer\_samples\.\*\.date | string | 
action\_result\.data\.\*\.undetected\_referrer\_samples\.\*\.positives | numeric | 
action\_result\.data\.\*\.undetected\_referrer\_samples\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.undetected\_referrer\_samples\.\*\.total | numeric | 
action\_result\.data\.\*\.undetected\_urls\.\* | string | 
action\_result\.data\.\*\.verbose\_msg | string | 
action\_result\.data\.\*\.whois | string | 
action\_result\.data\.\*\.whois\_timestamp | numeric | 
action\_result\.summary\.alexa\_rank | numeric | 
action\_result\.summary\.communicating\_samples | numeric | 
action\_result\.summary\.detected\_urls | numeric | 
action\_result\.summary\.downloaded\_samples | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_positives | numeric |   

## action: 'ip reputation'
Queries VirusTotal for IP info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.as\_owner | string | 
action\_result\.data\.\*\.asn | numeric | 
action\_result\.data\.\*\.continent | string | 
action\_result\.data\.\*\.country | string | 
action\_result\.data\.\*\.detected\_communicating\_samples\.\*\.date | string | 
action\_result\.data\.\*\.detected\_communicating\_samples\.\*\.positives | numeric | 
action\_result\.data\.\*\.detected\_communicating\_samples\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.detected\_communicating\_samples\.\*\.total | numeric | 
action\_result\.data\.\*\.detected\_downloaded\_samples\.\*\.date | string | 
action\_result\.data\.\*\.detected\_downloaded\_samples\.\*\.positives | numeric | 
action\_result\.data\.\*\.detected\_downloaded\_samples\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.detected\_downloaded\_samples\.\*\.total | numeric | 
action\_result\.data\.\*\.detected\_referrer\_samples\.\*\.date | string | 
action\_result\.data\.\*\.detected\_referrer\_samples\.\*\.positives | numeric | 
action\_result\.data\.\*\.detected\_referrer\_samples\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.detected\_referrer\_samples\.\*\.total | numeric | 
action\_result\.data\.\*\.detected\_urls\.\*\.positives | numeric | 
action\_result\.data\.\*\.detected\_urls\.\*\.scan\_date | string | 
action\_result\.data\.\*\.detected\_urls\.\*\.total | numeric | 
action\_result\.data\.\*\.detected\_urls\.\*\.url | string |  `url`  `file name` 
action\_result\.data\.\*\.network | string | 
action\_result\.data\.\*\.resolutions\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.resolutions\.\*\.last\_resolved | string | 
action\_result\.data\.\*\.response\_code | numeric | 
action\_result\.data\.\*\.undetected\_communicating\_samples\.\*\.date | string | 
action\_result\.data\.\*\.undetected\_communicating\_samples\.\*\.positives | numeric | 
action\_result\.data\.\*\.undetected\_communicating\_samples\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.undetected\_communicating\_samples\.\*\.total | numeric | 
action\_result\.data\.\*\.undetected\_downloaded\_samples\.\*\.date | string | 
action\_result\.data\.\*\.undetected\_downloaded\_samples\.\*\.positives | numeric | 
action\_result\.data\.\*\.undetected\_downloaded\_samples\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.undetected\_downloaded\_samples\.\*\.total | numeric | 
action\_result\.data\.\*\.undetected\_referrer\_samples\.\*\.positives | numeric | 
action\_result\.data\.\*\.undetected\_referrer\_samples\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.undetected\_referrer\_samples\.\*\.total | numeric | 
action\_result\.data\.\*\.undetected\_urls\.\* | string | 
action\_result\.data\.\*\.verbose\_msg | string | 
action\_result\.summary\.communicating\_samples | numeric | 
action\_result\.summary\.detected\_urls | numeric | 
action\_result\.summary\.downloaded\_samples | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_positives | numeric |   

## action: 'get file'
Downloads a file from VirusTotal, and adds it to the vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash of file to get | string |  `hash`  `sha256`  `sha1`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `sha256`  `sha1`  `md5` 
action\_result\.data\.\*\.file\_type | string | 
action\_result\.data\.\*\.name | string |  `md5` 
action\_result\.data\.\*\.vault\_id | string |  `vault id`  `sha1` 
action\_result\.summary\.file\_type | string | 
action\_result\.summary\.name | string |  `md5` 
action\_result\.summary\.vault\_id | string |  `vault id`  `sha1` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_positives | numeric |   

## action: 'get report'
Get the results using the scan id from a detonate file or detonate url action

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**scan\_id** |  required  | Scan ID | string |  `virustotal scan id` 
**report\_type** |  required  | Type of report to download | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.report\_type | string | 
action\_result\.parameter\.scan\_id | string |  `virustotal scan id` 
action\_result\.data\.\*\.filescan\_id | string | 
action\_result\.data\.\*\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.permalink | string |  `url` 
action\_result\.data\.\*\.positives | numeric | 
action\_result\.data\.\*\.resource | string | 
action\_result\.data\.\*\.response\_code | numeric | 
action\_result\.data\.\*\.scan\_date | string | 
action\_result\.data\.\*\.scan\_id | string |  `virustotal scan id` 
action\_result\.data\.\*\.scans\.\*\.detected | boolean | 
action\_result\.data\.\*\.scans\.\*\.result | string | 
action\_result\.data\.\*\.scans\.\*\.update | string | 
action\_result\.data\.\*\.scans\.\*\.version | string | 
action\_result\.data\.\*\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.total | numeric | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.verbose\_msg | string | 
action\_result\.summary\.positives | numeric | 
action\_result\.summary\.scan\_id | string | 
action\_result\.summary\.total\_scans | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_positives | numeric |   

## action: 'detonate file'
Upload a file to Virus Total and retrieve the analysis results

Type: **investigate**  
Read only: **True**

<b>detonate file</b> will send a file to Virus Total for analysis\. Virus Total, however, takes an indefinite amount of time to complete this scan\. This action will poll for the results for a short amount of time\. If it can not get the finished results in this amount of time, it will fail and return in the summary <b>scan id</b>\. This should be used with the <b>get report</b> action to finish the scan\.<br>If you attempt to upload a file which has already been scanned by Virus Total, it will not rescan the file but instead will return those already existing results\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | The Vault ID of the file to scan | string |  `vault id`  `sha1` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.vault\_id | string |  `vault id`  `sha1` 
action\_result\.data\.\*\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.permalink | string |  `url` 
action\_result\.data\.\*\.positives | numeric | 
action\_result\.data\.\*\.resource | string |  `sha256` 
action\_result\.data\.\*\.response\_code | numeric | 
action\_result\.data\.\*\.scan\_date | string | 
action\_result\.data\.\*\.scan\_id | string |  `virustotal scan id` 
action\_result\.data\.\*\.scans\.\*\.detected | boolean | 
action\_result\.data\.\*\.scans\.\*\.result | string | 
action\_result\.data\.\*\.scans\.\*\.update | string | 
action\_result\.data\.\*\.scans\.\*\.version | string | 
action\_result\.data\.\*\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.total | numeric | 
action\_result\.data\.\*\.verbose\_msg | string | 
action\_result\.summary\.positives | numeric | 
action\_result\.summary\.scan\_id | string |  `virustotal scan id` 
action\_result\.summary\.total\_scans | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_positives | numeric |   

## action: 'detonate url'
Load a URL to Virus Total and retrieve analysis results

Type: **investigate**  
Read only: **True**

<b>detonate url</b> will send a URL to Virus Total for analysis\. Virus Total, however, takes an indefinite amount of time to complete this scan\. This action will poll for the results for a short amount of time\. If it can not get the finished results in this amount of time, it will fail and return in the summary <b>scan id</b>\. This should be used with the <b>get report</b> action to finish the scan\.<br>If you attempt to upload a URL which has already been scanned by Virus Total, it will not rescan the URL but instead will return those already existing results\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to detonate | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url`  `domain` 
action\_result\.data\.\*\.filescan\_id | string | 
action\_result\.data\.\*\.permalink | string |  `url` 
action\_result\.data\.\*\.positives | numeric | 
action\_result\.data\.\*\.resource | string |  `url` 
action\_result\.data\.\*\.response\_code | numeric | 
action\_result\.data\.\*\.scan\_date | string | 
action\_result\.data\.\*\.scan\_id | string |  `virustotal scan id` 
action\_result\.data\.\*\.scans\.\*\.detected | boolean | 
action\_result\.data\.\*\.scans\.\*\.result | string | 
action\_result\.data\.\*\.total | numeric | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.verbose\_msg | string | 
action\_result\.summary\.positives | numeric | 
action\_result\.summary\.scan\_id | string |  `virustotal scan id` 
action\_result\.summary\.total\_scans | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_positives | numeric | 