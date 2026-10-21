"""Bounded fixed-destination HTTPS; OSS V4 signing with Python's standard library.

No SDK installation on ECS. Signature algorithm follows Alibaba's V4 specification;
the official published signature vector is exercised by the offline tests.
Never log responses, exception messages, headers, signatures or credentials.
"""
import base64
import datetime as dt
import hashlib
import hmac
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from result_common import BUCKET, KEY, MAX_BYTES, Refused, need, loads


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused('redirect_refused')


def request(url, method='GET', headers=None, data=None, limit=MAX_BYTES, metadata=False):
    u = urllib.parse.urlsplit(url)
    need(not u.username and not u.password and not u.fragment, 'request_url')
    if metadata:
        need(u.scheme == 'http' and u.netloc == '100.100.100.200' and
             u.path.startswith('/latest/') and not u.query, 'metadata_destination')
    else:
        need(u.scheme == 'https' and u.port in (None, 443), 'https_required')
    # Ignore proxy environment for link-local IMDS. HTTPS may use the configured controlled proxy.
    handlers = [NoRedirect()]
    if metadata:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    try:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        with opener.open(req, timeout=10) as response:
            need(response.status == 200, 'http_status')
            raw = response.read(limit + 1)
            need(len(raw) <= limit, 'http_response_size')
            return raw
    except Refused:
        raise
    except Exception:
        raise Refused('network_request_failed') from None


def credentials(value):
    need(isinstance(value, dict), 'credentials_missing')
    for key in ('AccessKeyId', 'AccessKeySecret', 'SecurityToken'):
        v = value.get(key)
        need(isinstance(v, str) and 0 < len(v) <= 20000 and not any(c.isspace() for c in v), 'credentials_invalid')
    try:
        expiry = dt.datetime.fromisoformat(value['Expiration'].replace('Z', '+00:00'))
        need(expiry > dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=60), 'credentials_expired')
    except (KeyError, TypeError, ValueError):
        raise Refused('credentials_expiry_invalid') from None
    return value


def region(value):
    need(isinstance(value, str) and re.fullmatch(r'[a-z]{2}-[a-z0-9-]{2,32}', value), 'oss_region_required')
    return value


def signing_key(secret, date, area):
    key = ('aliyun_v4' + secret).encode()
    for part in (date, area, 'oss', 'aliyun_v4_request'):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    return key


def canonical_request(method, bucket, key, headers, additional=()):
    selected = {k.lower(): v.strip() for k, v in headers.items()
                if k.lower().startswith('x-oss-') or k.lower() in ('content-type', 'content-md5') or k.lower() in additional}
    lines = ''.join(k + ':' + selected[k] + '\n' for k in sorted(selected))
    uri = urllib.parse.quote('/' + bucket + '/' + key, safe='/~')
    return '\n'.join((method, uri, '', lines, ';'.join(sorted(additional)), 'UNSIGNED-PAYLOAD'))


def authorization(method, bucket, key, headers, creds, area, additional=()):
    date = headers['x-oss-date'][:8]
    scope = date + '/' + area + '/oss/aliyun_v4_request'
    canonical = canonical_request(method, bucket, key, headers, additional)
    message = 'OSS4-HMAC-SHA256\n' + headers['x-oss-date'] + '\n' + scope + '\n' + hashlib.sha256(canonical.encode()).hexdigest()
    signature = hmac.new(signing_key(creds['AccessKeySecret'], date, area), message.encode(), hashlib.sha256).hexdigest()
    extra = 'AdditionalHeaders=' + ';'.join(sorted(additional)) + ', ' if additional else ''
    return 'OSS4-HMAC-SHA256 Credential=' + creds['AccessKeyId'] + '/' + scope + ', ' + extra + 'Signature=' + signature


def object_request(method, area, creds, data=None, internal=False):
    region(area); credentials(creds)
    need(method in ('GET', 'PUT'), 'object_method')
    need((method == 'PUT' and isinstance(data, bytes) and 0 < len(data) <= MAX_BYTES) or
         (method == 'GET' and data is None and not internal), 'object_request_scope')
    host = BUCKET + '.oss-' + area + ('-internal' if internal else '') + '.aliyuncs.com'
    headers = {'x-oss-date': dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ'),
               'x-oss-content-sha256': 'UNSIGNED-PAYLOAD', 'x-oss-security-token': creds['SecurityToken']}
    if method == 'PUT':
        headers.update({'content-type': 'application/json; charset=utf-8',
                        'content-md5': base64.b64encode(hashlib.md5(data).digest()).decode(),
                        'x-oss-object-acl': 'private', 'x-oss-storage-class': 'Standard',
                        'x-oss-server-side-encryption': 'AES256',
                        'x-oss-forbid-overwrite': 'true', 'cache-control': 'no-store'})
    headers['Authorization'] = authorization(method, BUCKET, KEY, headers, creds, area)
    return request('https://' + host + '/' + KEY, method, headers, data,
                   limit=MAX_BYTES if method == 'GET' else 4096)


def instance_credentials():
    base = 'http://100.100.100.200/latest/'
    token = request(base + 'api/token', 'PUT', {'X-aliyun-ecs-metadata-token-ttl-seconds': '60'},
                    limit=4096, metadata=True).decode()
    need(bool(token) and not any(c.isspace() for c in token), 'imds_token')
    headers = {'X-aliyun-ecs-metadata-token': token}
    def get(path):
        return request(base + 'meta-data/' + path, headers=headers, limit=32768, metadata=True)
    need(get('instance-id').decode().strip() == 'i-2zedybs3fftu1d9vnx39', 'instance_mismatch')
    need(get('region-id').decode().strip() == 'cn-beijing', 'instance_region_mismatch')
    # Any existing role with a different name is a conflict, not a fallback.
    name = 'aifinance-results-writer'
    need(get('ram/security-credentials/').decode().strip() == name, 'instance_role_conflict_or_missing')
    value = loads(get('ram/security-credentials/' + name))
    need(value.get('Code') == 'Success', 'imds_credentials_failed')
    return credentials(value)
