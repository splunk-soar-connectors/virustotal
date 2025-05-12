# VirusTotal

Publisher: Splunk \
Connector Version: 2.2.7 \
Product Vendor: VirusTotal \
Product Name: VirusTotal \
Minimum Product Version: 5.0.0

This app integrates with the VirusTotal cloud to implement investigative and reputation actions using v2 APIs

**Playbook Backward Compatibility**

- One old asset parameter is removed and new asset parameter has been added to the asset
  configuration given below. Hence, it is requested to the end-user please update their existing
  playbooks and provide values to this new parameter to ensure the correct functioning of the
  playbooks created on the earlier versions of the app.

  - **For version 2.2.X :**

    - Test Connectivity - **requests_per_minute** parameter has been added
    - Test Connectivity - **rate_limit** parameter has been removed.

  - **For version 2.1.X :**

    - Test Connectivity - **rate_limit** parameter has been added

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Virustotal server. Below are the
default ports used by Splunk SOAR.

|         SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|----------------------|--------------------|------|
|         http | tcp | 80 |
|         https | tcp | 443 |

### Configuration variables

This table lists the configuration variables required to operate VirusTotal. These variables are specified when configuring a VirusTotal asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**apikey** | required | password | VirusTotal API key |
**poll_interval** | optional | numeric | Number of minutes to poll for a detonation result (Default: 5) |
**requests_per_minute** | optional | numeric | Maximum number of requests per minute (For public API, it can be set as 4.) |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity \
[file reputation](#action-file-reputation) - Queries VirusTotal for file reputation info \
[url reputation](#action-url-reputation) - Queries VirusTotal for URL info \
[domain reputation](#action-domain-reputation) - Queries VirusTotal for domain info \
[ip reputation](#action-ip-reputation) - Queries VirusTotal for IP info \
[get file](#action-get-file) - Downloads a file from VirusTotal, and adds it to the vault \
[get report](#action-get-report) - Get the results using the scan id from a detonate file or detonate url action \
[detonate file](#action-detonate-file) - Upload a file to Virus Total and retrieve the analysis results \
[detonate url](#action-detonate-url) - Load a URL to Virus Total and retrieve analysis results

## action: 'test connectivity'

Validate the asset configuration for connectivity

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'file reputation'

Queries VirusTotal for file reputation info

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | File hash to query | string | `hash` `sha256` `sha1` `md5` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.hash | string | `hash` `sha256` `sha1` `md5` | 6c1948f7edf115cd1f13cd170b882077930be150 |
action_result.data.\*.md5 | string | `hash` `md5` | 494303294715f5ffad7ad3f43b73b00b |
action_result.data.\*.permalink | string | `url` | https://www.test.com/file/27ce020f7cdb4b775b80bd6e3ef1d16079401e0d45cfd28ffbd8c63ff2ddf7d7/analysis/1548112684/ |
action_result.data.\*.positives | numeric | | 64 |
action_result.data.\*.resource | string | `sha1` | 6c1948f7edf115cd1f13cd170b882077930be150 |
action_result.data.\*.response_code | numeric | | 1 |
action_result.data.\*.scan_date | string | | 2019-01-21 23:18:04 |
action_result.data.\*.scan_id | string | `virustotal scan id` | 27ce020f7cdb4b775b80bd6e3ef1d16079401e0d45cfd28ffbd8c63ff2ddf7d7-1548112684 |
action_result.data.\*.scans.\*.detected | boolean | | |
action_result.data.\*.scans.\*.result | string | | |
action_result.data.\*.scans.\*.update | string | | |
action_result.data.\*.scans.\*.version | string | | |
action_result.data.\*.sha1 | string | `hash` `sha1` | 6c1948f7edf115cd1f13cd170b882077930be150 |
action_result.data.\*.sha256 | string | `hash` `sha256` | 27ce020f7cdb4b775b80bd6e3ef1d16079401e0d45cfd28ffbd8c63ff2ddf7d7 |
action_result.data.\*.total | numeric | | 72 |
action_result.data.\*.verbose_msg | string | | Scan finished, information embedded |
action_result.summary.positives | numeric | | 64 |
action_result.summary.total_scans | numeric | | 72 |
action_result.message | string | | Positives: 64, Total scans: 72 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
summary.total_positives | numeric | | 1 |

## action: 'url reputation'

Queries VirusTotal for URL info

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to query | string | `url` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.url | string | `url` | https://www.test.com |
action_result.data.\*.filescan_id | string | | |
action_result.data.\*.permalink | string | `url` | https://www.test.com/url/d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86/analysis/1549011607/ |
action_result.data.\*.positives | numeric | | 0 |
action_result.data.\*.resource | string | `url` | https://www.test.com |
action_result.data.\*.response_code | numeric | | 1 |
action_result.data.\*.scan_date | string | | 2019-02-01 09:00:07 |
action_result.data.\*.scan_id | string | `virustotal scan id` | d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86-1549011607 |
action_result.data.\*.scans.\*.detail | string | | |
action_result.data.\*.scans.\*.detected | boolean | | |
action_result.data.\*.scans.\*.result | string | | |
action_result.data.\*.total | numeric | | 66 |
action_result.data.\*.url | string | `url` | https://www.test.com/ |
action_result.data.\*.verbose_msg | string | | Scan finished, scan information embedded in this object |
action_result.summary.detections | boolean | | |
action_result.summary.found | boolean | | |
action_result.summary.positives | numeric | | 0 |
action_result.summary.total_scans | numeric | | 66 |
action_result.message | string | | Positives: 0, Total scans: 66 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
summary.total_positives | numeric | | 0 |

## action: 'domain reputation'

Queries VirusTotal for domain info

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to query | string | `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.domain | string | `domain` | test.com |
action_result.data.\*.categories | string | | search engines and portals |
action_result.data.\*.detected_communicating_samples.\*.date | string | | 2019-02-01 07:43:22 |
action_result.data.\*.detected_communicating_samples.\*.positives | numeric | | 56 |
action_result.data.\*.detected_communicating_samples.\*.sha256 | string | `sha256` | d98246798d0025fbfeeeae3fa0dbfc7aadc7c61b5560a51f043250b5e16b61e1 |
action_result.data.\*.detected_communicating_samples.\*.total | numeric | | 71 |
action_result.data.\*.detected_downloaded_samples.\*.date | string | | 2018-12-15 02:21:06 |
action_result.data.\*.detected_downloaded_samples.\*.positives | numeric | | 1 |
action_result.data.\*.detected_downloaded_samples.\*.sha256 | string | `sha256` | 169f959197cc4f23ee7fc955708b467385c85f61ae34d58c29c246e106ffa60c |
action_result.data.\*.detected_downloaded_samples.\*.total | numeric | | 69 |
action_result.data.\*.detected_referrer_samples.\*.date | string | | 2019-01-22 00:20:30 |
action_result.data.\*.detected_referrer_samples.\*.positives | numeric | | 18 |
action_result.data.\*.detected_referrer_samples.\*.sha256 | string | `sha256` | b84e5d161f26a8fbc34f2dd5a72c8f6660b3793e56659682c14112fd02e8a437 |
action_result.data.\*.detected_referrer_samples.\*.total | numeric | | 70 |
action_result.data.\*.detected_urls.\*.positives | numeric | | 2 |
action_result.data.\*.detected_urls.\*.scan_date | string | | 2019-01-31 10:16:38 |
action_result.data.\*.detected_urls.\*.total | numeric | | 66 |
action_result.data.\*.detected_urls.\*.url | string | `url` `file name` | https://test.com/url?q=http%3A%2F%2Fqlql.ru%2FFAG |
action_result.data.\*.pcaps | string | `sha256` | 0e6db89e84666d8b620be803315c2fdd5c94f38c87000665b4870bf124aea156 |
action_result.data.\*.resolutions.\*.ip_address | string | `ip` | 103.241.58.24 |
action_result.data.\*.resolutions.\*.last_resolved | string | | 2018-09-12 23:04:32 |
action_result.data.\*.response_code | numeric | | 1 |
action_result.data.\*.subdomains | string | `domain` | profiles.test.com |
action_result.data.\*.undetected_communicating_samples.\*.date | string | | 2019-01-31 09:27:18 |
action_result.data.\*.undetected_communicating_samples.\*.positives | numeric | | 0 |
action_result.data.\*.undetected_communicating_samples.\*.sha256 | string | `sha256` | c655aa8e162e9f8935e2be8ccdb0ebfabb5696eb0e0f6e9e1b65e163082614fc |
action_result.data.\*.undetected_communicating_samples.\*.total | numeric | | 71 |
action_result.data.\*.undetected_downloaded_samples.\*.date | string | | 2019-01-31 03:02:39 |
action_result.data.\*.undetected_downloaded_samples.\*.positives | numeric | | 0 |
action_result.data.\*.undetected_downloaded_samples.\*.sha256 | string | `sha256` | 908b020e301271d46a789be079e26611ce77d53f06766140248997a99c6ebd35 |
action_result.data.\*.undetected_downloaded_samples.\*.total | numeric | | 70 |
action_result.data.\*.undetected_referrer_samples.\*.date | string | | 2019-01-31 20:32:40 |
action_result.data.\*.undetected_referrer_samples.\*.positives | numeric | | 0 |
action_result.data.\*.undetected_referrer_samples.\*.sha256 | string | `sha256` | d3f7ae7ade2d708654f54b61703dd3aa42f93be75618ccba17a4110e529e4a5c |
action_result.data.\*.undetected_referrer_samples.\*.total | numeric | | 69 |
action_result.data.\*.undetected_urls.\* | string | | 2018-11-15 19:09:07 |
action_result.data.\*.verbose_msg | string | | Domain found in dataset |
action_result.data.\*.whois | string | | Domain Name: test.COM Registry Domain ID: 2138514_DOMAIN_COM-VRSN Registrar WHOIS Server: whois.markmonitor.com Registrar URL: http://www.markmonitor.com Updated Date: 2018-02-21T18:36:40Z Creation Date: 1997-09-15T04:00:00Z Registry Expiry Date: 2020-09-14T04:00:00Z Registrar: MarkMonitor Inc. Registrar IANA ID: 292 Registrar Abuse Contact Email: abusecomplaints@markmonitor.com Registrar Abuse Contact Phone: +1.2083895740 Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited Name Server: NS1.test.COM Name Server: NS2.test.COM Name Server: NS3.test.COM Name Server: NS4.test.COM DNSSEC: unsigned Domain Name: test.com Updated Date: 2018-02-21T10:45:07-0800 Creation Date: 1997-09-15T00:00:00-0700 Registrar Registration Expiration Date: 2020-09-13T21:00:00-0700 Registrar: MarkMonitor, Inc. Domain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited) Domain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited) Domain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited) Domain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited) Domain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited) Domain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited) Registrant Country: US Admin Organization: test LLC Admin State/Province: CA Admin Country: US Tech Organization: test LLC Tech State/Province: CA Tech Country: US Name Server: ns2.test.com Name Server: ns4.test.com Name Server: ns1.test.com Name Server: ns3.test.com |
action_result.data.\*.whois_timestamp | numeric | | 1547237868 |
action_result.summary.alexa_rank | numeric | | 10 |
action_result.summary.communicating_samples | numeric | | 100 |
action_result.summary.detected_urls | numeric | | 100 |
action_result.summary.downloaded_samples | numeric | | 100 |
action_result.message | string | | Downloaded samples: 100, Detected urls: 100, Alexa rank: 10, Communicating samples: 100 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
summary.total_positives | numeric | | 0 |

## action: 'ip reputation'

Queries VirusTotal for IP info

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to query | string | `ip` `ipv6` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.as_owner | string | | Test Inc. |
action_result.data.\*.asn | numeric | | 15169 |
action_result.data.\*.continent | string | | NA |
action_result.data.\*.country | string | | US |
action_result.data.\*.detected_communicating_samples.\*.date | string | | 2019-02-01 08:27:02 |
action_result.data.\*.detected_communicating_samples.\*.positives | numeric | | 1 |
action_result.data.\*.detected_communicating_samples.\*.sha256 | string | `sha256` | 95aea1163cd742d895f048de9b7f7ae83149ba2515b174dc6d5cfd910cb07ee3 |
action_result.data.\*.detected_communicating_samples.\*.total | numeric | | 61 |
action_result.data.\*.detected_downloaded_samples.\*.date | string | | 2017-09-28 14:00:34 |
action_result.data.\*.detected_downloaded_samples.\*.positives | numeric | | 1 |
action_result.data.\*.detected_downloaded_samples.\*.sha256 | string | `sha256` | 2b977b6342a624097b669fd2347ffbcbdc8a814369b5f431835793dbaa2251c8 |
action_result.data.\*.detected_downloaded_samples.\*.total | numeric | | 57 |
action_result.data.\*.detected_referrer_samples.\*.date | string | | 2018-02-14 12:35:57 |
action_result.data.\*.detected_referrer_samples.\*.positives | numeric | | 25 |
action_result.data.\*.detected_referrer_samples.\*.sha256 | string | `sha256` | 6c16bbddc9dcbf447c44afb11387115ac657852fcdf30cf068cf6e11e8786212 |
action_result.data.\*.detected_referrer_samples.\*.total | numeric | | 70 |
action_result.data.\*.detected_urls.\*.positives | numeric | | 9 |
action_result.data.\*.detected_urls.\*.scan_date | string | | 2019-02-01 07:31:41 |
action_result.data.\*.detected_urls.\*.total | numeric | | 67 |
action_result.data.\*.detected_urls.\*.url | string | `url` `file name` | http://vanmaulop10.com/now/index.php?mail= |
action_result.data.\*.network | string | | 8.8.8.0/24 |
action_result.data.\*.resolutions.\*.hostname | string | `host name` | \*.o365answers.com |
action_result.data.\*.resolutions.\*.last_resolved | string | | 2015-12-10 00:00:00 |
action_result.data.\*.response_code | numeric | | 1 |
action_result.data.\*.undetected_communicating_samples.\*.date | string | | 2019-02-01 09:03:52 |
action_result.data.\*.undetected_communicating_samples.\*.positives | numeric | | 0 |
action_result.data.\*.undetected_communicating_samples.\*.sha256 | string | `sha256` | 414296de0c223c28910d99797701d4fa192208f4e30c32b0dc07da7602d7a4fb |
action_result.data.\*.undetected_communicating_samples.\*.total | numeric | | 57 |
action_result.data.\*.undetected_downloaded_samples.\*.date | string | | 2019-01-30 20:23:21 |
action_result.data.\*.undetected_downloaded_samples.\*.positives | numeric | | 0 |
action_result.data.\*.undetected_downloaded_samples.\*.sha256 | string | `sha256` | 23926e9185d8d43c02807a838ffb373cc1977726094a4e46807c66ada9dd7660 |
action_result.data.\*.undetected_downloaded_samples.\*.total | numeric | | 71 |
action_result.data.\*.undetected_referrer_samples.\*.positives | numeric | | 0 |
action_result.data.\*.undetected_referrer_samples.\*.sha256 | string | `sha256` | 01e110d94eec3ec8abed7c9bb34fd7bcc3bd06c397ec83676431fc193be3b68e |
action_result.data.\*.undetected_referrer_samples.\*.total | numeric | | 55 |
action_result.data.\*.undetected_urls.\* | string | | 2018-10-01 03:53:53 |
action_result.data.\*.verbose_msg | string | | IP address in dataset |
action_result.summary.communicating_samples | numeric | | 100 |
action_result.summary.detected_urls | numeric | | 100 |
action_result.summary.downloaded_samples | numeric | | 11 |
action_result.message | string | | Downloaded samples: 11, Detected urls: 100, Communicating samples: 100 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
summary.total_positives | numeric | | 0 |

## action: 'get file'

Downloads a file from VirusTotal, and adds it to the vault

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | Hash of file to get | string | `hash` `sha256` `sha1` `md5` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.hash | string | `hash` `sha256` `sha1` `md5` | BDB97B8DE2D22B86B3BDB4B43B4C50BF |
action_result.data.\*.file_type | string | | |
action_result.data.\*.name | string | `md5` | BDB97B8DE2D22B86B3BDB4B43B4C50BF |
action_result.data.\*.vault_id | string | `vault id` `sha1` | 1052507b5c178307bf333e48237af2530c365d73 |
action_result.summary.file_type | string | | |
action_result.summary.name | string | `md5` | BDB97B8DE2D22B86B3BDB4B43B4C50BF |
action_result.summary.vault_id | string | `vault id` `sha1` | 1052507b5c178307bf333e48237af2530c365d73 |
action_result.message | string | | File successfully retrieved and added to vault |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
summary.total_positives | numeric | | 0 |

## action: 'get report'

Get the results using the scan id from a detonate file or detonate url action

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**scan_id** | required | Scan ID | string | `virustotal scan id` |
**report_type** | required | Type of report to download | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.report_type | string | | url |
action_result.parameter.scan_id | string | `virustotal scan id` | 955fe006aaaecd31559afd572eec28ff19fdde56e48c411798deba09f020d746-1548744623 |
action_result.data.\*.filescan_id | string | | |
action_result.data.\*.md5 | string | `hash` `md5` | |
action_result.data.\*.permalink | string | `url` | https://www.test.com/url/955fe006aaaecd31559afd572eec28ff19fdde56e48c411798deba09f020d746/analysis/1548744623/ |
action_result.data.\*.positives | numeric | | 0 |
action_result.data.\*.resource | string | | 955fe006aaaecd31559afd572eec28ff19fdde56e48c411798deba09f020d746-1548744623 |
action_result.data.\*.response_code | numeric | | 1 |
action_result.data.\*.scan_date | string | | 2019-01-29 06:50:23 |
action_result.data.\*.scan_id | string | `virustotal scan id` | 955fe006aaaecd31559afd572eec28ff19fdde56e48c411798deba09f020d746-1548744623 |
action_result.data.\*.scans.\*.detected | boolean | | |
action_result.data.\*.scans.\*.result | string | | |
action_result.data.\*.scans.\*.update | string | | |
action_result.data.\*.scans.\*.version | string | | |
action_result.data.\*.sha1 | string | `hash` `sha1` | |
action_result.data.\*.sha256 | string | `hash` `sha256` | |
action_result.data.\*.total | numeric | | 66 |
action_result.data.\*.url | string | `url` | https://www.splunk.com/ |
action_result.data.\*.verbose_msg | string | | Scan finished, scan information embedded in this object |
action_result.summary.positives | numeric | | 0 |
action_result.summary.scan_id | string | | 955fe006aaaecd31559afd572eec28ff19fdde56e48c411798deba09f020d746-1548744623 |
action_result.summary.total_scans | numeric | | 66 |
action_result.message | string | | Positives: 0, Scan id: 955fe006aaaecd31559afd572eec28ff19fdde56e48c411798deba09f020d746-1548744623, Total scans: 66 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
summary.total_positives | numeric | | 0 |

## action: 'detonate file'

Upload a file to Virus Total and retrieve the analysis results

Type: **investigate** \
Read only: **True**

<b>detonate file</b> will send a file to Virus Total for analysis. Virus Total, however, takes an indefinite amount of time to complete this scan. This action will poll for the results for a short amount of time. If it can not get the finished results in this amount of time, it will fail and return in the summary <b>scan id</b>. This should be used with the <b>get report</b> action to finish the scan.<br>If you attempt to upload a file which has already been scanned by Virus Total, it will not rescan the file but instead will return those already existing results.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | The Vault ID of the file to scan | string | `vault id` `sha1` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.vault_id | string | `vault id` `sha1` | 6c1948f7edf115cd1f13cd170b882077930be150 |
action_result.data.\*.md5 | string | `hash` `md5` | 494303294715f5ffad7ad3f43b73b00b |
action_result.data.\*.permalink | string | `url` | https://www.test.com/file/27ce020f7cdb4b775b80bd6e3ef1d16079401e0d45cfd28ffbd8c63ff2ddf7d7/analysis/1548112684/ |
action_result.data.\*.positives | numeric | | 64 |
action_result.data.\*.resource | string | `sha256` | 27ce020f7cdb4b775b80bd6e3ef1d16079401e0d45cfd28ffbd8c63ff2ddf7d7 |
action_result.data.\*.response_code | numeric | | 1 |
action_result.data.\*.scan_date | string | | 2019-01-21 23:18:04 |
action_result.data.\*.scan_id | string | `virustotal scan id` | 27ce020f7cdb4b775b80bd6e3ef1d16079401e0d45cfd28ffbd8c63ff2ddf7d7-1548112684 |
action_result.data.\*.scans.\*.detected | boolean | | |
action_result.data.\*.scans.\*.result | string | | |
action_result.data.\*.scans.\*.update | string | | |
action_result.data.\*.scans.\*.version | string | | |
action_result.data.\*.sha1 | string | `hash` `sha1` | 6c1948f7edf115cd1f13cd170b882077930be150 |
action_result.data.\*.sha256 | string | `hash` `sha256` | 27ce020f7cdb4b775b80bd6e3ef1d16079401e0d45cfd28ffbd8c63ff2ddf7d7 |
action_result.data.\*.total | numeric | | 72 |
action_result.data.\*.verbose_msg | string | | Scan finished, information embedded |
action_result.summary.positives | numeric | | 64 |
action_result.summary.scan_id | string | `virustotal scan id` | 27ce020f7cdb4b775b80bd6e3ef1d16079401e0d45cfd28ffbd8c63ff2ddf7d7-1548112684 |
action_result.summary.total_scans | numeric | | 72 |
action_result.message | string | | Positives: 64, Scan id: 27ce020f7cdb4b775b80bd6e3ef1d16079401e0d45cfd28ffbd8c63ff2ddf7d7-1548112684, Total scans: 72 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
summary.total_positives | numeric | | 0 |

## action: 'detonate url'

Load a URL to Virus Total and retrieve analysis results

Type: **investigate** \
Read only: **True**

<b>detonate url</b> will send a URL to Virus Total for analysis. Virus Total, however, takes an indefinite amount of time to complete this scan. This action will poll for the results for a short amount of time. If it can not get the finished results in this amount of time, it will fail and return in the summary <b>scan id</b>. This should be used with the <b>get report</b> action to finish the scan.<br>If you attempt to upload a URL which has already been scanned by Virus Total, it will not rescan the URL but instead will return those already existing results.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to detonate | string | `url` `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.url | string | `url` `domain` | https://www.test.com |
action_result.data.\*.filescan_id | string | | |
action_result.data.\*.permalink | string | `url` | https://www.test.com/url/d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86/analysis/1549015805/ |
action_result.data.\*.positives | numeric | | 0 |
action_result.data.\*.resource | string | `url` | https://www.test.com |
action_result.data.\*.response_code | numeric | | 1 |
action_result.data.\*.scan_date | string | | 2019-02-01 10:10:05 |
action_result.data.\*.scan_id | string | `virustotal scan id` | d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86-1549015805 |
action_result.data.\*.scans.\*.detected | boolean | | |
action_result.data.\*.scans.\*.result | string | | |
action_result.data.\*.total | numeric | | 66 |
action_result.data.\*.url | string | `url` | https://www.test.com/ |
action_result.data.\*.verbose_msg | string | | Scan finished, scan information embedded in this object |
action_result.summary.positives | numeric | | 0 |
action_result.summary.scan_id | string | `virustotal scan id` | d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86-1549015805 |
action_result.summary.total_scans | numeric | | 66 |
action_result.message | string | | Positives: 0, Scan id: d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86-1549015805, Total scans: 66 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
summary.total_positives | numeric | | 0 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
