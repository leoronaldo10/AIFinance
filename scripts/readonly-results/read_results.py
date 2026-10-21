"""GitHub-only OIDC -> STS -> one private OSS object. No ECS APIs."""
import base64
import html
import json
import os
import re
import sys
import urllib.parse
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_common import (Refused, need, loads, decode, sha256, REPOSITORY,
                           REPOSITORY_ID, OWNER_ID, ENVIRONMENT, WORKFLOW)
from cloud_io import request, credentials, region, object_request


def check_claims(token):
    need(isinstance(token, str) and len(token) <= 20000, 'oidc_token_size')
    try:
        parts = token.split('.')
        need(len(parts) == 3, 'oidc_token_format')
        claims = loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)))
    except Exception:
        raise Refused('oidc_claims_invalid') from None
    # These local checks are defense in depth, NOT signature verification. STS verifies the JWT.
    expected = {'iss': 'https://token.actions.githubusercontent.com', 'aud': 'sts.aliyuncs.com',
                'repository': REPOSITORY, 'repository_id': REPOSITORY_ID,
                'repository_owner_id': OWNER_ID, 'environment': ENVIRONMENT,
                'ref': 'refs/heads/main', 'event_name': 'workflow_dispatch'}
    need(isinstance(claims, dict) and all(claims.get(k) == v for k, v in expected.items()), 'oidc_claims_mismatch')
    reusable = claims.get('job_workflow_ref', '')
    need(isinstance(reusable, str) and re.fullmatch(re.escape(WORKFLOW) + '[a-f0-9]{40}', reusable), 'oidc_workflow_mismatch')
    subject = ('repository_id:' + REPOSITORY_ID + ':repository_owner_id:' + OWNER_ID +
               ':environment:' + ENVIRONMENT + ':job_workflow_ref:' + reusable)
    need(claims.get('sub') == subject, 'oidc_subject_mismatch')
    return claims


def oidc_credentials(account):
    url = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL', '')
    u = urllib.parse.urlsplit(url)
    need(u.scheme == 'https' and u.hostname is not None and
         u.hostname.endswith('.actions.githubusercontent.com') and
         not u.username and not u.password and not u.fragment and u.port in (None, 443), 'github_oidc_endpoint')
    bearer = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN', '')
    need(bool(bearer) and not any(c.isspace() for c in bearer), 'github_oidc_unavailable')
    query = [(k, v) for k, v in urllib.parse.parse_qsl(u.query) if k != 'audience']
    query.append(('audience', 'sts.aliyuncs.com'))
    url = urllib.parse.urlunsplit(u._replace(query=urllib.parse.urlencode(query)))
    token = loads(request(url, headers={'Authorization': 'Bearer ' + bearer}, limit=32768)).get('value')
    check_claims(token)
    form = {'Action': 'AssumeRoleWithOIDC', 'Version': '2015-04-01', 'Format': 'JSON',
            'RoleArn': 'acs:ram::' + account + ':role/aifinance-results-reader',
            'OIDCProviderArn': 'acs:ram::' + account + ':oidc-provider/github-aifinance-readonly',
            'RoleSessionName': 'results-' + os.environ.get('GITHUB_RUN_ID', 'unknown'),
            'DurationSeconds': '900', 'OIDCToken': token}
    response = loads(request('https://sts.cn-beijing.aliyuncs.com/', 'POST',
                            {'Content-Type': 'application/x-www-form-urlencoded'},
                            urllib.parse.urlencode(form).encode(), limit=32768))
    return credentials(response.get('Credentials'))


def main():
    need(len(sys.argv) == 1, 'no_arguments_required')
    for key, value in {'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_REPOSITORY_ID': REPOSITORY_ID,
                       'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch'}.items():
        need(os.environ.get(key) == value, 'github_context_mismatch')
    account = os.environ.get('AIFINANCE_ALIBABA_ACCOUNT_ID', '')
    need(re.fullmatch('[0-9]{8,32}', account), 'account_id_required')
    area = region(os.environ.get('AIFINANCE_OSS_REGION', ''))
    expected = os.environ.get('AIFINANCE_RESULTS_SHA256', '')
    need(re.fullmatch('[a-f0-9]{64}', expected), 'independent_result_sha256_required')
    creds = oidc_credentials(account)
    data = object_request('GET', area, creds)
    need(sha256(data) == expected, 'result_sha256_mismatch')
    result = decode(data)
    # One prefixed JSON line; embedded newlines are escaped, so content cannot inject workflow commands.
    print('AIFINANCE_PUBLIC_RESULT=' + json.dumps(result, ensure_ascii=True, separators=(',', ':')))
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as f:
            f.write('## Retry-002 public results\n\nSHA256: `' + expected + '`\n\n<pre>' +
                    html.escape(json.dumps(result, ensure_ascii=False, indent=2)) + '</pre>\n')


if __name__ == '__main__':
    try:
        main()
    except Refused as e:
        print('AIFINANCE_RESULT_REFUSED=' + str(e)); sys.exit(1)
    except Exception:
        print('AIFINANCE_RESULT_REFUSED=operation_failed_details_suppressed'); sys.exit(1)
