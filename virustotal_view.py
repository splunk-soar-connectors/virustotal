# File: virustotal_view.py
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
from phantom.json_keys import *

from virustotal_consts import *


def file_reputation(provides, all_results, context):

    tally = {'total_positives': 0, 'total_found': 0, 'total_queried': 0}

    results = []
    action_results = []

    for summary, action_results in all_results:
        if not summary or not action_results:
            continue
        tally['total_positives'] += int(summary.get(VIRUSTOTAL_JSON_TOTAL_POSITIVES, 0))
        tally['total_found'] += int(summary.get(APP_JSON_TOTAL_OBJECTS_SUCCESS, 0))
        tally['total_queried'] += int(summary.get(APP_JSON_TOTAL_OBJECTS_TO_ACT_ON, 0))

        for result in action_results:
            parameter = result.get_param()
            result_summary = result.get_summary()
            results.append((parameter.get(APP_JSON_HASH, '').lower(), result_summary.get(VIRUSTOTAL_JSON_POSITIVES, 0),
                result_summary.get(VIRUSTOTAL_JSON_TOTAL_SCANS, 0)))

    parameters = {}
    if tally['total_queried']:
        percentage = int((tally['total_positives'] / float(tally['total_queried'])) * 100)
    else:
        percentage = 0
    parameters['percentage'] = percentage
    parameters['result_summary'] = [
        ('Queried', [tally['total_queried']]),
        ('Found', [tally['total_found']]),
        ('Detected', [tally['total_positives']]),
        ('Detection ratio', [percentage]),
    ]

    parameters['additional_text'] = '{percentage}% detection ratio'.format(**parameters)

    context['parameters'] = parameters
    context['results'] = results
    context['title_text_color'] = 'white'
    context['body_color'] = '#0F75BC'
    context['title_color'] = 'white'
    return 'virustotal_template.html'


def _get_ctx_result(result, provides):

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result["check_param"] = False

    if len(list(param.keys())) > 1:
        ctx_result["check_param"] = True

    ctx_result['param'] = param
    ctx_result["action_name"] = provides
    if summary:
        ctx_result['summary'] = summary

    if not data:
        ctx_result['data'] = {}
        return ctx_result

    ctx_result['data'] = data

    return ctx_result


def display_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == 'domain reputation':
        return 'virustotal_domain_reputation.html'
    if provides == 'ip reputation':
        return 'virustotal_ip_reputation.html'
