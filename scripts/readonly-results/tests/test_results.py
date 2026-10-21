import base64
import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import result_common as common
import cloud_io as cloud
import read_results as reader
import export_results as exporter


def fixture():
    return {'schema_version': 1, 'batch_id': 'retry-002', 'collection_status': 'matched_retry_002',
            'exported_at': '2026-10-19T00:00:00Z', 'articles': [
                {'id': 'article-' + str(i), 'source_id': source, 'source_name': 'Public source',
                 'title': 'Public title', 'original_url': 'https://' + hosts[-1] + '/news/example',
                 'published_at': None, 'collected_at': '2026-10-19T00:00:00Z', 'summary': 'Public RSS summary'}
                for i, (source, hosts) in enumerate(common.SOURCES.items())]}


def creds():
    return {'AccessKeyId': 'TEST_ONLY_ID', 'AccessKeySecret': 'TEST_ONLY_SECRET',
            'SecurityToken': 'TEST_ONLY_TOKEN',
            'Expiration': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=15)).isoformat()}


def claims():
    ref = common.WORKFLOW + 'a' * 40
    return {'iss': 'https://token.actions.githubusercontent.com', 'aud': 'sts.aliyuncs.com',
            'repository': common.REPOSITORY, 'repository_id': common.REPOSITORY_ID,
            'repository_owner_id': common.OWNER_ID, 'environment': common.ENVIRONMENT,
            'ref': 'refs/heads/main', 'event_name': 'workflow_dispatch', 'job_workflow_ref': ref,
            'sub': 'repository_id:' + common.REPOSITORY_ID + ':repository_owner_id:' + common.OWNER_ID +
                   ':environment:' + common.ENVIRONMENT + ':job_workflow_ref:' + ref}


def token(value):
    return 'test.' + base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=') + '.test'


class ResultTests(unittest.TestCase):
    def test_roundtrip_only_three_public_rows(self):
        data = common.encode(fixture())
        self.assertEqual(common.decode(data), fixture())
        self.assertLess(len(data), common.MAX_BYTES)

    def test_additional_fields_refused(self):
        for level in ('result', 'article'):
            value = fixture()
            (value if level == 'result' else value['articles'][0])['database_url'] = 'not-public'
            with self.assertRaises(common.Refused): common.encode(value)

    def test_wrong_batch_duplicate_sources_count(self):
        changes = [lambda x: x.update(batch_id='retry-003'), lambda x: x['articles'].pop(),
                   lambda x: x['articles'].__setitem__(1, x['articles'][0])]
        for change in changes:
            value = fixture(); change(value)
            with self.assertRaises(common.Refused): common.encode(value)

    def test_secrets_and_controls_refused_without_echo(self):
        for secret in ('password=hunter2', 'STS.' + 'x' * 20, 'LTAI' + 'x' * 20,
                       'ghp_' + 'x' * 30, 'postgresql://u:p@host/db', '\n::warning::inject', '\x1b[31m'):
            value = fixture(); value['articles'][0]['summary'] = secret
            with self.assertRaises(common.Refused) as raised: common.encode(value)
            self.assertNotIn(secret, str(raised.exception))

    def test_credential_and_unapproved_urls_refused(self):
        for url in ('http://www.accountingtoday.com/a', 'https://evil.example/a',
                    'https://user:password@www.accountingtoday.com/a',
                    'https://www.accountingtoday.com/a?token=abc', 'https://www.accountingtoday.com:444/a'):
            value = fixture(); value['articles'][0]['original_url'] = url
            with self.assertRaises(common.Refused): common.encode(value)

    def test_size_limit_duplicate_json_and_nonfinite(self):
        for data in (b' ' * (common.MAX_BYTES + 1), b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(common.Refused): common.decode(data)
        value = fixture(); value['articles'][0]['summary'] = 'x' * 6001
        with self.assertRaises(common.Refused): common.encode(value)


class CloudTests(unittest.TestCase):
    def test_official_v4_vector(self):
        headers = {'content-disposition': 'attachment', 'content-length': '3',
                   'content-md5': 'ICy5YqxZB1uWSwcVLSNLcA==', 'content-type': 'text/plain',
                   'x-oss-content-sha256': 'UNSIGNED-PAYLOAD', 'x-oss-date': '20250411T064124Z'}
        additional = ('content-disposition', 'content-length')
        canonical = cloud.canonical_request('PUT', 'examplebucket', 'exampleobject', headers, additional)
        self.assertEqual(hashlib.sha256(canonical.encode()).hexdigest(), 'c46d96390bdbc2d739ac9363293ae9d710b14e48081fcb22cd8ad54b63136eca')
        # The documentation redacts the actual secret; its displayed derived key is the usable vector.
        with patch.object(cloud, 'signing_key', return_value=bytes.fromhex('3543b7686e65eda71e5e5ca19d548d78423c37e8ddba4dc9d83f90228b457c76')):
            auth = cloud.authorization('PUT', 'examplebucket', 'exampleobject', headers,
                                       {'AccessKeyId': 'TEST_ONLY', 'AccessKeySecret': 'unused'}, 'cn-hangzhou', additional)
        self.assertTrue(auth.endswith('053edbf550ebd239b32a9cdfd93b0b2b3f2d223083aa61f75e9ac16856d61f23'))

    def test_official_sdk_key_derivation_vector(self):
        # aliyun/alibabacloud-oss-python-sdk-v2 @129ff73707d9b03c98a63bdd9ad1fb9505a946df
        # tests/unit/signer/test_v4.py::test_auth_header uses public dummy ak/sk.
        headers = {'x-oss-head1': 'value', 'content-type': 'text/plain',
                   'x-oss-content-sha256': 'UNSIGNED-PAYLOAD',
                   'x-oss-date': dt.datetime.fromtimestamp(1702743657, dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}
        canonical = cloud.canonical_request('PUT', 'bucket', '1234+-/123/1.txt', headers)
        query = '%2Bparam1=value3&%2Bparam2&%7Cparam1=value4&%7Cparam2&param1=value1&param2'
        canonical = canonical.replace('\n\n', '\n' + query + '\n', 1)
        with patch.object(cloud, 'canonical_request', return_value=canonical):
            auth = cloud.authorization('PUT', 'bucket', '1234+-/123/1.txt', headers,
                                       {'AccessKeyId': 'ak', 'AccessKeySecret': 'sk'}, 'cn-hangzhou')
        self.assertTrue(auth.endswith('e21d18daa82167720f9b1047ae7e7f1ce7cb77a31e8203a7d5f4624fa0284afe'))

    def test_put_private_exact_object_no_redirect_or_query(self):
        with patch.object(cloud, 'request', return_value=b'') as call:
            cloud.object_request('PUT', 'cn-beijing', creds(), common.encode(fixture()), internal=True)
        args = call.call_args.args
        self.assertEqual(args[0], 'https://' + common.BUCKET + '.oss-cn-beijing-internal.aliyuncs.com/' + common.KEY)
        self.assertEqual(args[2]['x-oss-object-acl'], 'private')
        self.assertEqual(args[2]['x-oss-server-side-encryption'], 'AES256')
        self.assertEqual(args[2]['x-oss-forbid-overwrite'], 'true')
        self.assertNotIn('?', args[0])

    def test_get_only_exact_object_and_public_https(self):
        with patch.object(cloud, 'request', return_value=b'test') as call:
            cloud.object_request('GET', 'cn-beijing', creds())
        self.assertEqual(call.call_args.args[0], 'https://' + common.BUCKET + '.oss-cn-beijing.aliyuncs.com/' + common.KEY)
        for method in ('DELETE', 'POST', 'HEAD'):
            with self.assertRaises(common.Refused): cloud.object_request(method, 'cn-beijing', creds())

    def test_region_injection_and_stale_credentials(self):
        for value in ('', 'cn-beijing/evil', 'cn-beijing.aliyuncs.com@evil', 'cn-beijing?x=1'):
            with self.assertRaises(common.Refused): cloud.region(value)
        value = creds(); value['Expiration'] = '2020-01-01T00:00:00Z'
        with self.assertRaises(common.Refused): cloud.credentials(value)

    def test_redirect_refused(self):
        with self.assertRaises(common.Refused): cloud.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.example')

    def test_http_error_suppresses_credentials(self):
        with patch.object(cloud.urllib.request, 'build_opener', side_effect=ValueError('TEST_SECRET')):
            # Opener setup itself is local; main catches this too, but request errors must never be printed.
            with self.assertRaises(ValueError): cloud.request('https://example.invalid')
        with patch.object(cloud.urllib.request.OpenerDirector, 'open', side_effect=ValueError('TEST_SECRET')):
            with self.assertRaises(common.Refused) as raised: cloud.request('https://example.invalid')
        self.assertNotIn('TEST_SECRET', str(raised.exception))

    def test_imds_requires_exact_instance_role_no_fallback(self):
        good = [b'token', b'i-2zedybs3fftu1d9vnx39', b'cn-beijing', b'aifinance-results-writer',
                json.dumps(dict(creds(), Code='Success')).encode()]
        with patch.object(cloud, 'request', side_effect=good) as call:
            cloud.instance_credentials()
            self.assertTrue(all(c.kwargs.get('metadata') for c in call.call_args_list))
        for index, replacement in ((1, b'other-instance'), (3, b'backup-role'), (3, b'')):
            bad = list(good); bad[index] = replacement
            with patch.object(cloud, 'request', side_effect=bad), self.assertRaises(common.Refused): cloud.instance_credentials()


class ReaderTests(unittest.TestCase):
    def test_claims_match(self):
        self.assertEqual(reader.check_claims(token(claims())), claims())

    def test_fork_pr_environment_workflow_and_subject_refused(self):
        for key, value in {'repository_id': 'other', 'repository_owner_id': 'other', 'ref': 'refs/pull/1/merge',
                           'event_name': 'pull_request_target', 'environment': 'other',
                           'job_workflow_ref': common.WORKFLOW + 'refs/heads/main', 'sub': 'repo:anything',
                           'aud': 'other', 'iss': 'https://evil.example'}.items():
            data = claims(); data[key] = value
            with self.assertRaises(common.Refused): reader.check_claims(token(data))

    def env(self, data):
        return {'GITHUB_REPOSITORY': common.REPOSITORY, 'GITHUB_REPOSITORY_ID': common.REPOSITORY_ID,
                'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'AIFINANCE_ALIBABA_ACCOUNT_ID': '1234567890123456', 'AIFINANCE_OSS_REGION': 'cn-beijing',
                'AIFINANCE_RESULTS_SHA256': common.sha256(data)}

    def test_read_result_and_sanitized_html(self):
        value = fixture(); value['articles'][0]['title'] = '<script>not markup</script>'
        data = common.encode(value)
        with tempfile.TemporaryDirectory() as td:
            env = self.env(data); env['GITHUB_STEP_SUMMARY'] = td + '/summary'
            out = io.StringIO()
            with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['reader']), \
                 patch.object(reader, 'oidc_credentials', return_value=creds()), \
                 patch.object(reader, 'object_request', return_value=data), contextlib.redirect_stdout(out): reader.main()
            self.assertTrue(out.getvalue().startswith('AIFINANCE_PUBLIC_RESULT='))
            self.assertNotIn('<script>', Path(env['GITHUB_STEP_SUMMARY']).read_text())
            self.assertNotIn('TEST_ONLY_SECRET', out.getvalue())

    def test_wrong_digest_no_public_output(self):
        data = common.encode(fixture()); env = self.env(data); env['AIFINANCE_RESULTS_SHA256'] = '0' * 64
        out = io.StringIO()
        with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['reader']), \
             patch.object(reader, 'oidc_credentials', return_value=creds()), \
             patch.object(reader, 'object_request', return_value=data), contextlib.redirect_stdout(out), self.assertRaises(common.Refused): reader.main()
        self.assertEqual(out.getvalue(), '')

    def test_missing_config_never_requests_oidc(self):
        env = self.env(common.encode(fixture())); env.pop('AIFINANCE_RESULTS_SHA256')
        with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['reader']), \
             patch.object(reader, 'oidc_credentials') as call, self.assertRaises(common.Refused): reader.main()
        call.assert_not_called()


class ExportTests(unittest.TestCase):
    def test_query_failure_prevents_put(self):
        names = ('export_results.py', 'result_common.py', 'cloud_io.py', 'retry002.sql')
        manifest = {n: common.sha256(b'test') for n in names}
        def fake_read(path, maximum=65536):
            if path.name == 'runtime-hashes.json': return json.dumps(manifest).encode()
            if path.name == 'aifinance-results-retry002.json':
                return b'{"oss_region":"cn-beijing","internal_endpoint":true,"instance_role_confirmed":true}'
            return b'test'
        with patch.object(sys, 'argv', ['export']), patch.object(exporter.os, 'geteuid', return_value=0), \
             patch.object(exporter, 'ROOT', Path(exporter.__file__).resolve().parent), \
             patch.object(exporter.socket, 'gethostname', return_value='iZ2zedybs3fftu1d9vnx39Z'), \
             patch.object(exporter, 'read_small', side_effect=fake_read), patch.object(exporter, 'bounds', return_value=(1,2)), \
             patch.object(exporter, 'query', side_effect=common.Refused('fixed_readonly_query_failed')), \
             patch.object(exporter, 'object_request') as put, self.assertRaises(common.Refused): exporter.main()
        put.assert_not_called()

    def test_policies_are_exact_object_only(self):
        root = Path(__file__).resolve().parents[1] / 'policies'
        for filename, action in [('oss-reader-policy.json','oss:GetObject'), ('oss-writer-policy.json','oss:PutObject')]:
            document = json.loads((root / filename).read_text())
            self.assertEqual(len(document['Statement']), 1)
            rule = document['Statement'][0]
            self.assertEqual(rule['Action'], action)
            self.assertEqual(rule['Resource'], 'acs:oss:*:*:' + common.BUCKET + '/' + common.KEY)
            if action == 'oss:PutObject': self.assertEqual(rule['Condition']['StringEquals']['oss:x-oss-object-acl'], 'private')

    def test_wrong_host_never_touches_db_or_cloud(self):
        with patch.object(sys, 'argv', ['export']), patch.object(exporter.os, 'geteuid', return_value=0), \
             patch.object(exporter, 'ROOT', Path(exporter.__file__).resolve().parent), \
             patch.object(exporter.socket, 'gethostname', return_value='wrong'), patch.object(exporter, 'query') as query, \
             patch.object(exporter, 'instance_credentials') as credentials, self.assertRaises(common.Refused): exporter.main()
        query.assert_not_called(); credentials.assert_not_called()

    def test_nonroot_and_arguments_refused(self):
        for uid, argv in ((1000, ['export']), (0, ['export', 'run'])):
            with patch.object(exporter.os, 'geteuid', return_value=uid), patch.object(sys, 'argv', argv), self.assertRaises(common.Refused): exporter.main()


if __name__ == '__main__':
    unittest.main()
