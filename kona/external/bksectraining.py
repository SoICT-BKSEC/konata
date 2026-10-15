"""Konata external provider for the BKSEC Training platform.

Syncs a challenge repository into a deployed BKSEC Training instance (a
Cloudflare Worker serving its API under ``/api``). It implements the same
``ExternalProviderABC`` contract as ``rctf.py`` and ``ctfd.py``; configure it
with a ``[bksectraining]`` section (``KonaBKSECTrainingCredentials``).

How it differs from the rCTF provider, and why it is shorter:
  * ``POST /api/admin/challenges`` UPSERTS BY SLUG (201 the first time, 200
    after), so a re-run is idempotent server-side: there is no "fetch remote,
    diff every attribute, PUT by id" dance, we just post the desired state.
  * Auth is a single ``Authorization: Bearer <key>``, where the key is a
    personal API key with the ``admin:sync`` scope. It can create and update
    challenges, files and announcements but cannot delete anything or log in.
  * Files are deduplicated by SHA-256 (``POST /api/admin/files/query``) before
    uploading.

Mapping limits, marked TODO below:
  * Scoring: ``core:static`` and ``core:quadratic`` (CTFd's "logarithmic"
    decay curve). Any other decay function is refused rather than mis-mapped.
  * Flags: plain-string and ``flags/static`` providers map to
    ``strategy=case_sensitive``; other providers raise NotImplementedError.
  * Instancer config and SSH login metadata map to ``private_metadata.deploy``.
    Admin-bot blocks are dropped with a warning; prerequisites are not synced.
"""

from __future__ import annotations

import hashlib
import mimetypes
import re
from datetime import UTC, datetime
from http import HTTPStatus
from io import BytesIO
from typing import TYPE_CHECKING, Any

import yaml
from httpx import AsyncClient, Timeout
from loguru import logger

from kona.util.http import raise_for_status

from .abc import ExternalProviderABC


if TYPE_CHECKING:
    from pathlib import Path

    from kona.schema.models import KonaBKSECTrainingCredentials, KonaChallengeItem, KonaGlobalConfig


# api/src/shared/challenge.ts:15 — slug identity, lowercase kebab/underscore.
_SLUG_OK = re.compile(r'^[-_a-z][-_a-z\d]+$')

# Image references in a description: markdown `![alt](src "title")` and raw
# `<img src="...">`. Only the src matters — it is matched by basename against
# the challenge's attachments to decide which files are inline images.
_IMAGE_SRC = re.compile(
    r"""!\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+["'][^)]*["'])?\s*\)"""
    r"""|<img\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


def _inline_image_names(description: str) -> set[str]:
    """Basenames of relative images the description embeds.

    Absolute URLs are left alone — they are not ours to resolve. The web app
    rewrites a relative src to the matching file's ``/api/files/:ref`` URL at
    render time, so the stored description never carries an instance-specific
    ref and survives re-uploads unchanged.
    """
    names: set[str] = set()
    for match in _IMAGE_SRC.finditer(description):
        src = match.group(1) or match.group(2)
        if re.match(r'^(?:[a-z][a-z\d+.-]*:|//|/)', src, re.IGNORECASE):
            continue
        names.add(src.split('?', 1)[0].split('#', 1)[0].rsplit('/', 1)[-1])
    return names


# private_metadata.solve.source selects the SUBMISSION EVALUATOR, and
# services/submission.ts:205-224 accepts exactly two values: "flag" (compare
# against solve.flag) and "manual" (queue for review). Anything else falls
# through to `NotImplementedError: The challenge is not solvable`.
#
# Do NOT confuse this with ScoringStrategyEntry.source ("core" | "config",
# services/score.ts:51), which only records where a scoring strategy was
# defined. They are unrelated fields that happen to share a name — and because
# solve.source is typed as a plain String(maxLength:64), a wrong value is
# accepted at import and only fails when a player first submits a flag.
_SOLVE_SOURCE_FLAG = 'flag'

# shared/challenge.ts:91 — Type.Record(String({maxLength:64}), String({maxLength:64}))
_TAG_MAX_LENGTH = 64

# shared/challenge.ts — private_metadata.deploy.{config,timeout_minutes} bounds.
_DEPLOY_CONFIG_MAX = 65536
_DEPLOY_TIMEOUT_MAX_MIN = 1440
_DEPLOY_TIMEOUT_DEFAULT_MIN = 30

# Scoring strategies, verified against GET /api/admin/scoring_strategies on a
# live instance (services/score.ts:14 registers them under a "core:" prefix).
_STRATEGY_STATIC = 'core:static'
_STRATEGY_QUADRATIC = 'core:quadratic'

# the platform's `core:quadratic` IS CTFd's dynamic-scoring curve:
#   max(minimum, ceil(((minimum - initial) / decay^2) * max(0, n-1)^2 + initial))  # noqa: ERA001
# CTFd calls that curve "logarithmic", which is also Konata's default
# `scoring.ctfd.decay_function`. Any other decay function is a different curve
# and is refused rather than silently mapped onto this one.
_CTFD_DECAY_FUNCTION_QUADRATIC = 'logarithmic'


class BKSECTrainingProvider(ExternalProviderABC):
    kind = 'bksectraining'
    display_name = 'BKSEC Training'

    def __init__(self, global_config: KonaGlobalConfig, credentials: KonaBKSECTrainingCredentials) -> None:
        self.global_config = global_config
        self.credentials = credentials
        # KonaSecretOrValue resolves against the global [secrets] table.
        self.admin_token = credentials.admin_token.load(global_config)
        self.challenges_on_remote: list[dict] = []
        self.synced_remote_ids: set[str | int] = set()
        self._initialised = False

    @property
    def _client(self) -> AsyncClient:
        headers = dict(self.credentials.extra_headers)
        headers['Authorization'] = f'Bearer {self.admin_token}'
        return AsyncClient(
            base_url=str(self.credentials.base_url).rstrip('/'),
            headers=headers,
            timeout=Timeout(timeout=60),
        )

    async def setup(self) -> None:
        """Probe connectivity and snapshot the remote challenge list. Runs ONCE.

        ``kona/core/sync.py`` calls ``setup()`` again after *every* challenge to
        "refresh the local cache". For this adapter that refresh is pure cost:
        it re-probes ``/healthz`` and re-fetches the full challenge list (which
        grows with every challenge synced) on every iteration, i.e. two extra
        round trips per challenge and O(n^2) bytes overall. On a link with a
        ~1.2 s round trip that was ~36% of a 91-challenge sync.

        Skipping the repeat is also semantically better, not merely faster.
        ``challenges_on_remote`` is only read by
        ``report_untracked_challenges``, which diffs it against
        ``synced_remote_ids``; the ids of challenges created during this run are
        recorded from each upsert response anyway, so the pre-sync snapshot is
        exactly the "what was already there that we did not touch" set that
        report wants.
        """
        if self._initialised:
            return

        # Connectivity probe, sent WITHOUT the key: /healthz is public and, like
        # every route that grants no key scope, answers 403 to a key. A non-200
        # here means the origin or the /api base path is wrong, before we blame
        # the key.
        async with AsyncClient(
            base_url=str(self.credentials.base_url).rstrip('/'),
            headers=dict(self.credentials.extra_headers),
            timeout=Timeout(timeout=60),
        ) as probe:
            health = await probe.get('/api/healthz')
        if health.status_code != HTTPStatus.OK:
            msg = (
                f'GET /api/healthz returned {health.status_code}; check base_url '
                f'points at the deployed Worker origin (it serves the API under /api).'
            )
            raise RuntimeError(msg)

        async with self._client as client:
            r = await client.get('/api/admin/challenges')
            if r.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
                msg = (
                    f'GET /api/admin/challenges returned {r.status_code}: the token '
                    f'is missing, expired, revoked or lacks the admin:sync scope. '
                    f'Create a personal API key with the admin:sync scope and set '
                    f'it as admin_token.'
                )
                raise RuntimeError(msg)
            raise_for_status(r)

            # Normalise to the keys ExternalProviderABC.report_untracked_challenges
            # reads (id / category / name). the platform's admin list returns
            # id/slug/title/tags (admin_challenge.ts:56), with category living in
            # the tags record.
            remote = r.json()['data']
            self.challenges_on_remote = [
                {
                    **chal,
                    'name': chal.get('title', chal.get('slug')),
                    'category': (chal.get('tags') or {}).get('category', 'uncategorized'),
                }
                for chal in remote
            ]
        self._initialised = True
        logger.info(f'Retrieved {len(self.challenges_on_remote)} BKSEC Training challenges from remote')

    async def _upload_file(self, file: Path) -> int:
        """Return the numeric BKSEC Training file id, reusing an existing upload by hash."""
        digest = hashlib.sha256(file.read_bytes()).hexdigest()

        async with self._client as client:
            # POST /api/admin/files/query returns a {hash: id} map for the hashes
            # it already stores (services/file.ts:250). A hit means an identical
            # file is already uploaded — reuse its id, do not re-upload.
            q = await client.post('/api/admin/files/query', json={'hashes': [digest]})
            raise_for_status(q)
            known: dict[str, int] = q.json()['data']
            if digest in known:
                logger.info(f'File {file.name} already uploaded to BKSEC Training (id {known[digest]})')
                return known[digest]

        mime = mimetypes.guess_type(file.name)[0] or 'application/octet-stream'
        async with self._client as client:
            logger.info(f'Uploading {file.name} to BKSEC Training')
            r = await client.post(
                '/api/admin/files',
                # The stored mime is what /api/files/:ref serves (with nosniff),
                # so a real image type is what lets an inline <img> render.
                files={'file': (file.name, BytesIO(file.read_bytes()), mime)},
            )
            raise_for_status(r)
            return r.json()['data']['id']

    def _flag_entries(self, challenge: KonaChallengeItem) -> list[dict[str, str]]:
        """Map Konata flags → BKSEC Training ``private_metadata.solve.flag`` entries.

        BKSEC Training flag entries are ``{data, strategy}`` (shared/challenge.ts:36).
        Only static flags are mapped here; ``strategy`` is ``case_sensitive`` to
        match the seed challenge and the ported fixtures.
        """
        rctf = challenge.flags.rctf
        raw = rctf if isinstance(rctf, list) else [rctf]
        entries: list[dict[str, str]] = []
        for item in raw:
            if isinstance(item, str):
                if item:
                    entries.append({'data': item, 'strategy': 'case_sensitive'})
                continue
            # RCTFFlag: only the static provider maps cleanly onto core flags.
            provider = getattr(item, 'provider', None)
            config = getattr(item, 'config', None)
            if provider in ('flags/static', 'static') and isinstance(config, dict):
                value = config.get('flag') or config.get('value')
                if value:
                    entries.append({'data': str(value), 'strategy': 'case_sensitive'})
                    continue
            # TODO(bksec): map regex / dynamic flag providers once BKSEC Training exposes the
            # corresponding solve strategies (GET the private_metadata schema at
            # /api/admin/challenges/schema/private_metadata).
            msg = (
                f'Challenge {challenge.challenge_id}: flag {item!r} is not a static '
                f"flag; the platform's core adapter only maps static flags for now."
            )
            raise NotImplementedError(msg)
        return entries

    def _score_block(self, challenge: KonaChallengeItem) -> dict[str, Any]:
        """Map Konata scoring → BKSEC Training ``private_metadata.score``.

        Two strategies are mapped, both with param names read off the live
        instance rather than guessed:

        * ``core:static``   — ``{base}``
        * ``core:quadratic`` — ``{initial, minimum, decay}``

        ``core:exponential`` takes ``{initial, minimum, k, j}``; Konata has no
        field carrying ``k``/``j``, so it is not reachable from this schema.
        """
        scoring = challenge.scoring
        # Treat "the floor equals the ceiling" as a static challenge regardless
        # of the declared rctf kind — that is unambiguously a fixed score.
        if scoring.initial_value == scoring.minimum_value:
            return {'params': {'base': float(scoring.initial_value)}, 'strategy': _STRATEGY_STATIC}

        decay_function = scoring.ctfd.decay_function
        if decay_function != _CTFD_DECAY_FUNCTION_QUADRATIC:
            msg = (
                f'Challenge {challenge.challenge_id}: scoring.ctfd.decay_function='
                f"{decay_function!r} is a different curve from the platform's "
                f'{_STRATEGY_QUADRATIC}. Use {_CTFD_DECAY_FUNCTION_QUADRATIC!r}, or add '
                f'a matching strategy under core.score and map it here.'
            )
            raise NotImplementedError(msg)

        decay = scoring.ctfd.decay
        if decay <= 0:
            # decay is squared in the denominator — 0 would divide by zero
            # inside the scoring expression, on every scoreboard recompute.
            msg = (
                f'Challenge {challenge.challenge_id}: scoring.ctfd.decay must be > 0 for '
                f'{_STRATEGY_QUADRATIC} (it is squared in the denominator); got {decay}.'
            )
            raise ValueError(msg)

        return {
            'params': {
                'initial': float(scoring.initial_value),
                'minimum': float(scoring.minimum_value),
                'decay': float(decay),
            },
            'strategy': _STRATEGY_QUADRATIC,
        }

    @staticmethod
    def _tags(challenge: KonaChallengeItem) -> dict[str, str]:
        """Map Konata's ``list[str]`` tags onto the platform's ``Record<string,string>``.

        BKSEC Training tags are a Record (shared/challenge.ts:91) and several features key
        off specific entries — notably level progression, which reads
        ``category``, ``level`` and ``difficulty`` (lib/progression.ts). Konata
        carries category/author as first-class fields but everything else as a
        flat list, so a ``key=value`` entry is split into a real pair and a bare
        entry keeps the previous self-keyed behaviour.
        """
        # `categories` (PLURAL, comma-separated) is what the frontend reads
        # (web/src/lib/utils/challenges.ts:45); a challenge without it renders as
        # "uncategorized" no matter what else it carries. The backend's level
        # gate reads `category` (singular) and now also accepts the plural form,
        # so emitting only the plural keeps one spelling on the wire instead of
        # two redundant tag chips on every card.
        tags: dict[str, str] = {
            'categories': challenge.category,
            'author': challenge.author,
        }
        for t in challenge.tags:
            key, sep, value = t.partition('=')
            key, value = key.strip(), value.strip()
            if sep and key and value:
                tags[key] = value
            else:
                tags[t] = t
        for key, value in tags.items():
            # shared/challenge.ts:91 caps both sides at 64 chars; a silent
            # server-side 400 halfway through a sync is worse than failing here.
            if len(key) > _TAG_MAX_LENGTH or len(value) > _TAG_MAX_LENGTH:
                msg = (
                    f'Challenge {challenge.challenge_id}: tag {key!r}={value!r} exceeds '
                    f"the platform's {_TAG_MAX_LENGTH}-character limit for tag keys and values."
                )
                raise ValueError(msg)
        return tags

    @staticmethod
    def _deploy_block(challenge: KonaChallengeItem) -> dict[str, Any] | None:
        """Map Konata ``instancer_config`` -> BKSEC Training ``private_metadata.deploy``.

        BKSEC Training delegates per-user challenge instances to **instancerd**, and
        stores the instancerd challenge YAML verbatim in ``deploy.config``
        (shared/challenge.ts). ``POST /api/admin/challenges`` forwards that
        string to instancerd's ``POST /v1/validate`` before saving
        (routes/admin_challenge.ts:35), so a malformed config is a 400 at
        import rather than a failure the first time a player clicks Deploy —
        but it also means **the platform must be able to reach instancerd for
        any deploy-bearing challenge to save at all**, otherwise the save is a
        502.

        Konata's ``instancer_config`` was modelled on Klodd, so only the fields
        that carry over are used: ``config`` (the instancerd YAML),
        ``timeout_milliseconds``, and the BKSEC Training ``ssh`` extension.
        ``expose`` is NOT re-encoded here — instancerd
        reads its own exposure list from ``x-instancer.expose`` inside the very
        same YAML, and emitting a second, possibly divergent copy is how the two
        drift apart.
        """
        ic = challenge.instancer_config
        if ic is None:
            return None

        config = ic.config
        if isinstance(config, str):
            config_str = config
        elif config:
            # A mapping in the TOML is dumped back to YAML, which is what
            # instancerd parses. Preserve key order so the file stays readable
            # in the admin UI.
            config_str = yaml.safe_dump(config, sort_keys=False, allow_unicode=True)
        else:
            msg = (
                f'Challenge {challenge.challenge_id}: instancer_config carries no `config`. '
                f'BKSEC Training stores the instancerd challenge YAML verbatim, so there is nothing '
                f'to send.'
            )
            raise ValueError(msg)

        if len(config_str) > _DEPLOY_CONFIG_MAX:
            msg = (
                f'Challenge {challenge.challenge_id}: deploy config is {len(config_str)} bytes, '
                f"over the platform's {_DEPLOY_CONFIG_MAX}-byte limit."
            )
            raise ValueError(msg)

        ms = ic.timeout_milliseconds
        minutes = _DEPLOY_TIMEOUT_DEFAULT_MIN if ms is None else max(1, round(ms / 60000))
        # shared/challenge.ts bounds this 1..1440; clamp rather than let the
        # server reject the whole challenge over a timeout.
        minutes = min(minutes, _DEPLOY_TIMEOUT_MAX_MIN)

        deploy: dict[str, Any] = {'enabled': True, 'config': config_str, 'timeout_minutes': minutes}
        ssh = getattr(ic, 'ssh', None)
        if ssh is not None:
            deploy['ssh'] = ssh.model_dump(exclude_none=True)
        return deploy

    @staticmethod
    def _visible_at(challenge: KonaChallengeItem) -> str | None:
        ms = challenge.release_time_ms
        if ms is None:
            return None
        # BKSEC Training TypeDate is ISO-8601 with a trailing Z (shared/challenge.ts:11).
        return datetime.fromtimestamp(ms / 1000, UTC).isoformat().replace('+00:00', 'Z')

    async def sync_challenge(
        self,
        challenge: KonaChallengeItem,
        attachment_paths: list[Path],
        rendered_description: str,
    ) -> None:
        slug = challenge.challenge_id
        if not _SLUG_OK.match(slug):
            msg = (
                f'Challenge id {slug!r} is not a valid BKSEC Training slug '
                '(^[-_a-z][-_a-z\\d]+$). Set a compliant challenge id.'
            )
            raise ValueError(msg)

        if challenge.admin_bot is not None:
            logger.warning(f'Challenge {slug}: BKSEC Training has no admin-bot support; that block is dropped.')

        file_ids = [await self._upload_file(p) for p in attachment_paths]
        inline_images = _inline_image_names(rendered_description)

        private_metadata: dict[str, Any] = {
            'solve': {
                'source': _SOLVE_SOURCE_FLAG,
                'flag': self._flag_entries(challenge),
            },
            'score': self._score_block(challenge),
            # An attachment the description embeds as an image is shown inline,
            # not offered again in the download list.
            'files': [
                {'id': fid, 'is_attachment': p.name not in inline_images}
                for p, fid in zip(attachment_paths, file_ids, strict=True)
            ],
        }
        deploy = self._deploy_block(challenge)
        if deploy is not None:
            private_metadata['deploy'] = deploy

        challenge_dict: dict[str, Any] = {
            'slug': slug,
            'title': challenge.name,
            'description': rendered_description,
            'private_metadata': private_metadata,
            'tags': self._tags(challenge),
            'hidden': challenge.hidden,
            # TODO(bksec): Konata expresses dependencies differently; BKSEC Training prerequisites
            # are numeric challenge ids and need a second pass once all slugs are
            # synced and their ids are known.
            'prerequisites': [],
            'max_attempts': challenge.scoring.ctfd.max_attempts,
            'visible_at': self._visible_at(challenge),
        }

        async with self._client as client:
            r = await client.post('/api/admin/challenges', json=challenge_dict)
            raise_for_status(r)
            body = r.json()['data']
            # Track the numeric id the upsert resolved the slug to, so the base
            # class's untracked-challenge report can diff against the remote list.
            self.synced_remote_ids.add(body['id'])
            verb = 'created' if r.status_code == HTTPStatus.CREATED else 'updated'
            logger.info(f'Challenge {challenge.name} ({slug}) {verb} in BKSEC Training (id {body["id"]})')
