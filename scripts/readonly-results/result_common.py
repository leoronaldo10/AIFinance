"""Fixed retry-002 public result format. No database, cloud or shell side effects."""
import datetime as dt
import hashlib
import json
import re
import unicodedata
from urllib.parse import urlsplit, parse_qsl

BUCKET = 'backupforecs20261009'
KEY = 'aifinance-public-results/retry-002/result-v1.json'
MAX_BYTES = 65536
REPOSITORY = 'leoronaldo10/AIFinance'
REPOSITORY_ID = '1396876434'
OWNER_ID = '311357003'
ENVIRONMENT = 'aifinance-readonly-results'
WORKFLOW = REPOSITORY + '/.github/workflows/read-results-reusable.yml@'
SOURCES = {
    'collect-accounting-today': ('accountingtoday.com', 'www.accountingtoday.com'),
    'collect-dynamics-finance': ('microsoft.com', 'www.microsoft.com'),
    'collect-journal-accountancy': ('journalofaccountancy.com', 'www.journalofaccountancy.com'),
}
SECRET = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:LTAI|AKIA|ASIA)[A-Za-z0-9]{12,}|\bSTS\.[A-Za-z0-9]{12,}|'
                    r'\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{12,}|'
                    r'\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}|'
                    r'(?:access.?key.?secret|security.?token|password|authorization)\s*[=:]\s*\S+|'
                    r'postgres(?:ql)?://', re.I)


class Refused(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


def loads(data):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refused('json_constant')))
    except (ValueError, UnicodeError):
        raise Refused('invalid_json') from None


def text(value, maximum, empty=False):
    need(isinstance(value, str) and (empty or bool(value)), 'invalid_text')
    need(len(value) <= maximum and not SECRET.search(value), 'unsafe_or_oversize_text')
    need(not any(unicodedata.category(c) in ('Cc', 'Cf') for c in value), 'text_control_character')
    return value


def timestamp(value, nullable=False):
    if value is None and nullable:
        return
    need(isinstance(value, str) and len(value) <= 40, 'invalid_timestamp')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise Refused('invalid_timestamp') from None
    need(parsed.tzinfo is not None, 'timestamp_timezone_required')


def validate(value):
    need(isinstance(value, dict) and set(value) == {
        'schema_version', 'batch_id', 'collection_status', 'exported_at', 'articles'}, 'result_fields')
    need(type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['batch_id'] == 'retry-002' and value['collection_status'] == 'matched_retry_002', 'result_identity')
    timestamp(value['exported_at'])
    articles = value['articles']
    need(isinstance(articles, list) and len(articles) == 3, 'article_count')
    sources, ids = set(), set()
    for a in articles:
        need(isinstance(a, dict) and set(a) == {'id', 'title', 'source_id', 'source_name',
             'original_url', 'published_at', 'collected_at', 'summary'}, 'article_fields')
        need(isinstance(a['source_id'], str) and a['source_id'] in SOURCES, 'source_not_allowed')
        sources.add(a['source_id'])
        need(isinstance(a['id'], str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', a['id']), 'article_id')
        ids.add(a['id'])
        text(a['title'], 1000); text(a['source_name'], 200); text(a['summary'], 6000, empty=True)
        text(a['original_url'], 2048)
        u = urlsplit(a['original_url'])
        need(u.scheme == 'https' and u.hostname in SOURCES[a['source_id']] and
             not u.username and not u.password and u.port in (None, 443) and not u.fragment, 'public_source_url')
        need(not any(re.search(r'token|signature|credential|password|secret|access.?key', k, re.I)
                     for k, _ in parse_qsl(u.query)), 'credential_url')
        timestamp(a['published_at'], nullable=True); timestamp(a['collected_at'])
    need(sources == set(SOURCES) and len(ids) == 3, 'duplicate_article_or_source')
    return value


def encode(value):
    validate(value)
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
    need(len(data) <= MAX_BYTES, 'result_size')
    return data


def decode(data):
    need(0 < len(data) <= MAX_BYTES, 'result_size')
    return validate(loads(data))


def sha256(data):
    return hashlib.sha256(data).hexdigest()
