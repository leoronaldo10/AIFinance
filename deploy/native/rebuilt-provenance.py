#!/usr/bin/env python3
"""Independent, fixed GitHub evidence verification. Never downloads artifact URLs.

Approval and GitHub readers are separate trust inputs. The operation caller's
source dictionary is not an approval or a substitute for authenticated evidence.
"""
import base64
import hashlib
import io
import re
import zipfile

REPO = 'leoronaldo10/AIFinance'
WORKFLOW = '.github/workflows/deploy-rebuilt.yml'
SHA = r'[0-9a-f]{40}'
DIGEST = r'[0-9a-f]{64}'
LIMIT = 128 * 1024 * 1024


class Refused(Exception):
    pass


def require(value):
    if not value:
        raise Refused('independent_build_evidence_rejected')


def verify(revision, digest, bundle, approval_reader, github, checkout_reader):
    """Verify a supplied GitHub ZIP against API digest, then exact inner tar bytes.

    approval_reader is administrator-controlled, not taken from action arguments.
    github.get is authenticated fixed-origin HTTPS; tests inject an independent fake.
    checkout_reader reads the actual clean local checkout, not an action field.
    """
    require(isinstance(revision, str) and re.fullmatch(SHA, revision))
    require(isinstance(digest, str) and re.fullmatch(DIGEST, digest))
    approval = approval_reader()
    require(isinstance(approval, dict) and approval.get('accepted') is True and
            type(approval.get('version')) is int and approval['version'] == 1 and approval.get('repository') == REPO)
    require(checkout_reader() == revision)
    entry = approval.get('artifacts', {}).get(revision)
    require(isinstance(entry, dict) and entry.get('sha256') == digest)
    for key in ('run_id', 'artifact_id', 'workflow_id', 'run_attempt'):
        require(type(entry.get(key)) is int and entry[key] > 0)
    require(isinstance(entry.get('workflow_sha256'), str) and re.fullmatch(DIGEST, entry['workflow_sha256']))
    require(isinstance(bundle, bytes) and 0 < len(bundle) <= LIMIT + 1024 * 1024)
    root = '/repos/' + REPO
    workflow = github.get(root + '/actions/workflows/deploy-rebuilt.yml')
    run = github.get(root + '/actions/runs/' + str(entry['run_id']))
    meta = github.get(root + '/actions/artifacts/' + str(entry['artifact_id']))
    source = github.get(root + '/contents/' + WORKFLOW + '?ref=' + revision)
    require(workflow.get('id') == entry['workflow_id'] and workflow.get('path') == WORKFLOW)
    require(run.get('id') == entry['run_id'] and run.get('workflow_id') == entry['workflow_id'] and
            run.get('path') == WORKFLOW and run.get('head_sha') == revision and
            run.get('run_attempt') == entry['run_attempt'] and run.get('event') == 'workflow_dispatch' and
            run.get('status') == 'completed' and run.get('conclusion') == 'success' and
            run.get('repository', {}).get('full_name') == REPO and
            run.get('head_repository', {}).get('full_name') == REPO)
    require(meta.get('id') == entry['artifact_id'] and meta.get('name') == 'aifinance-' + revision and
            meta.get('expired') is False and
            meta.get('workflow_run', {}).get('id') == entry['run_id'] and
            meta.get('workflow_run', {}).get('head_sha') == revision and
            meta.get('digest') == 'sha256:' + hashlib.sha256(bundle).hexdigest())
    require(source.get('path') == WORKFLOW and source.get('encoding') == 'base64' and
            isinstance(source.get('content'), str))
    try:
        workflow_bytes = base64.b64decode(source['content'].replace('\n', ''), validate=True)
        require(hashlib.sha256(workflow_bytes).hexdigest() == entry['workflow_sha256'])
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            names = [revision + '.tar.gz', revision + '.tar.gz.sha256']
            require(sorted(archive.namelist()) == sorted(names))
            tar, sums = (archive.getinfo(name) for name in names)
            require(0 < tar.file_size <= LIMIT and sums.file_size <= 256 and
                    not tar.flag_bits & 1 and not sums.flag_bits & 1)
            with archive.open(tar) as stream:
                data = stream.read(LIMIT + 1)
            require(len(data) == tar.file_size and hashlib.sha256(data).hexdigest() == digest)
            require(archive.read(sums) == (digest + '  ' + names[0] + '\n').encode())
    except (ValueError, KeyError, OSError, zipfile.BadZipFile, RuntimeError):
        raise Refused('independent_build_evidence_rejected') from None
    return data, dict(repository=REPO, revision=revision, sha256=digest,
                      checks_passed=True, build_run=str(entry['run_id']))
