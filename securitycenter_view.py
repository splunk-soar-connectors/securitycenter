# --
# File: ssmachine_view.py
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

# import json

from ssmachine_consts import *
from phantom.vault import Vault


def get_ctx_result(result):

    ctx_result = {}
    # param = result.get_param()
    summary = result.get_summary()

    vault_id = summary.get('vault_id')

    ctx_result['vault_id'] = summary.get('vault_id')
    ctx_result['vault_file_name'] = summary.get('name')
    if (vault_id):
        ctx_result['vault_file_path'] = Vault.get_file_path(vault_id)

    try:
        ctx_result['message'] = result.get_message()
    except:
        pass
    return ctx_result


def display_scrshot(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    # print context
    return 'display_scrshot.html'
