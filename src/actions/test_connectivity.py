# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Ported from legacy _handle_test_connectivity / _handle_interactive_login
# (mattermost_connector.py). Legacy's exact fallback order is preserved:
# try personal_token first if configured; only fall through to the OAuth App
# flow (client_id/client_secret) when the PAT probe fails with a 401 *and*
# OAuth credentials are also configured. If PAT succeeds, OAuth is never
# attempted even if client_id/client_secret are also present. The interactive
# browser flow (_handle_interactive_login's state-file + sleep/poll) is
# replaced by auth.py's complete_oauth_authorization, which polls auth_state
# behind the SDK's OAuth webhook callback (see webhooks.py).

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from ..auth import build_oauth_auth, build_pat_auth, complete_oauth_authorization
from ..consts import (
    MATTERMOST_API_BASE_URL,
    MATTERMOST_CONFIG_PARAMS_REQUIRED_CONNECTIVITY,
    MATTERMOST_CURRENT_USER_ENDPOINT,
    MATTERMOST_MAKING_CONNECTION_MSG,
    MATTERMOST_OAUTH_CALLBACK_ROUTE,
    MATTERMOST_OAUTH_URL_MSG,
    MATTERMOST_TEST_CONNECTIVITY_FAILED_MSG,
    MATTERMOST_TEST_CONNECTIVITY_PASSED_MSG,
    MATTERMOST_WAITING_FOR_AUTHORIZATION_MSG,
)

if TYPE_CHECKING:
    from soar_sdk.app import App

    from ..app import Asset

logger = getLogger()


def _probe_current_user(asset: Asset, auth: httpx.Auth) -> httpx.Response:
    """GET /users/me — the canonical connectivity probe (matches legacy's url)."""
    base_url = MATTERMOST_API_BASE_URL.format(server_url=asset.server_url.rstrip("/"))
    url = f"{base_url}{MATTERMOST_CURRENT_USER_ENDPOINT}"
    try:
        with httpx.Client(
            timeout=30.0, verify=bool(asset.verify_server_cert)
        ) as client:
            return client.get(url, auth=auth, headers={"Accept": "application/json"})
    except httpx.RequestError as exc:
        raise ActionFailure(f"Error connecting to Mattermost API: {exc}") from exc


def run_test_connectivity(
    soar: SOARClient, asset: Asset, *, app: App | None = None
) -> None:
    """Validate the asset configuration for connectivity using supplied configuration."""
    if not asset.personal_token and not (asset.client_id and asset.client_secret):
        raise ActionFailure(MATTERMOST_CONFIG_PARAMS_REQUIRED_CONNECTIVITY)

    logger.progress(MATTERMOST_MAKING_CONNECTION_MSG)

    if asset.personal_token:
        response = _probe_current_user(asset, build_pat_auth(asset))
        if response.is_success:
            logger.progress(MATTERMOST_TEST_CONNECTIVITY_PASSED_MSG)
            return
        # Only fall through to OAuth when the PAT failure is a 401 *and*
        # OAuth credentials are configured — otherwise report the PAT
        # failure directly, matching legacy's _handle_test_connectivity.
        if response.status_code != 401 or not (asset.client_id and asset.client_secret):
            logger.progress(MATTERMOST_TEST_CONNECTIVITY_FAILED_MSG)
            raise ActionFailure(
                f"{MATTERMOST_TEST_CONNECTIVITY_FAILED_MSG}: HTTP {response.status_code}"
            )

    if app is None:  # pragma: no cover - defensive; app is always supplied at runtime
        raise ActionFailure(
            f"{MATTERMOST_TEST_CONNECTIVITY_FAILED_MSG}: OAuth flow unavailable."
        )

    redirect_uri = app.get_webhook_url(MATTERMOST_OAUTH_CALLBACK_ROUTE)
    asset_id = str(soar.get_asset_id())

    def announce_url(auth_url: str) -> None:
        logger.progress(
            f"{MATTERMOST_OAUTH_URL_MSG}\n{auth_url}\n\n{MATTERMOST_WAITING_FOR_AUTHORIZATION_MSG}"
        )

    complete_oauth_authorization(
        asset,
        asset_id=asset_id,
        redirect_uri=redirect_uri,
        announce_url=announce_url,
    )

    response = _probe_current_user(asset, build_oauth_auth(asset))
    if not response.is_success:
        logger.progress(MATTERMOST_TEST_CONNECTIVITY_FAILED_MSG)
        raise ActionFailure(
            f"{MATTERMOST_TEST_CONNECTIVITY_FAILED_MSG}: HTTP {response.status_code}"
        )

    logger.progress(MATTERMOST_TEST_CONNECTIVITY_PASSED_MSG)
