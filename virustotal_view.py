# File: virustotal_view.py
# Copyright (c) 2016-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

from virustotal_consts import *
from phantom.json_keys import *


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
