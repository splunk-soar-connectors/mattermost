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

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TYPE_CHECKING

import httpx
from soar_sdk.auth import (
    OAuthBearerAuth,
    OAuthConfig,
    SOARAssetOAuthClient,
    StaticTokenAuth,
)
from soar_sdk.auth.client import ConfigurationChangedError, OAuthToken
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .consts import (
    MATTERMOST_ACCESS_TOKEN_URL,
    MATTERMOST_API_BASE_URL,
    MATTERMOST_AUTHORIZE_URL,
    MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG,
    MATTERMOST_CURRENT_USER_ENDPOINT,
    MATTERMOST_TC_STATUS_SLEEP,
)


if TYPE_CHECKING:
    from .asset import Asset


logger = getLogger()
OAUTH_POLL_TIMEOUT = 300


def build_pat_auth(asset: Asset) -> StaticTokenAuth:
    """Build bearer authentication for a Mattermost personal token."""
    return StaticTokenAuth(asset.personal_token)


def _build_oauth_config(
    asset: Asset, *, redirect_uri: str | None = None
) -> OAuthConfig:
    """Build the per-server Mattermost OAuth configuration."""
    server_url = asset.server_url.rstrip("/")
    authorization_endpoint = MATTERMOST_AUTHORIZE_URL.split("?")[0].format(
        server_url=server_url
    )
    token_endpoint = MATTERMOST_ACCESS_TOKEN_URL.format(server_url=server_url)
    return OAuthConfig(
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        redirect_uri=redirect_uri,
    )


def _oauth_http_client(verify: bool) -> httpx.Client:
    """Create the HTTP client used by the SDK OAuth token exchange."""
    return httpx.Client(
        headers={"Accept": "application/json"}, timeout=30.0, verify=verify
    )


def build_oauth_client(
    asset: Asset, *, redirect_uri: str | None = None
) -> SOARAssetOAuthClient:
    """Build an OAuth client backed by the asset's persisted auth state."""
    return SOARAssetOAuthClient(
        _build_oauth_config(asset, redirect_uri=redirect_uri),
        asset.auth_state,
        http_client=_oauth_http_client(asset.verify_server_cert),
    )


def build_oauth_auth(asset: Asset) -> OAuthBearerAuth:
    """Build bearer authentication backed by a stored OAuth token."""
    return OAuthBearerAuth(build_oauth_client(asset), auto_refresh=True)


def probe_current_user(asset: Asset, auth: httpx.Auth) -> httpx.Response:
    """Call Mattermost's current-user endpoint with explicit auth."""
    url = (
        MATTERMOST_API_BASE_URL.format(server_url=asset.server_url.rstrip("/"))
        + MATTERMOST_CURRENT_USER_ENDPOINT
    )
    try:
        with httpx.Client(timeout=30.0, verify=asset.verify_server_cert) as client:
            return client.get(url, auth=auth, headers={"Accept": "application/json"})
    except httpx.RequestError as exc:
        raise ActionFailure(f"Error connecting to Mattermost API: {exc}") from exc


def complete_oauth_authorization(
    asset: Asset,
    *,
    asset_id: str,
    redirect_uri: str,
    announce_url: Callable[[str], None],
    poll_timeout: int = OAUTH_POLL_TIMEOUT,
    poll_interval: int = MATTERMOST_TC_STATUS_SLEEP,
) -> OAuthToken:
    """Run the browser-based Mattermost OAuth authorization flow."""
    client = build_oauth_client(asset, redirect_uri=redirect_uri)
    try:
        if client.get_stored_token() is not None:
            return client.get_valid_token(auto_refresh=True)
    except ConfigurationChangedError:
        pass

    auth_url, _ = client.create_authorization_url(asset_id, use_pkce=False)
    announce_url(auth_url)

    deadline = time.time() + poll_timeout
    while time.time() < deadline:
        time.sleep(poll_interval)
        code = client.get_authorization_code(force_reload=True)
        if not code:
            continue
        token = client.fetch_token_with_authorization_code(code)
        # The SDK token exchange returns the token but older SDK releases can
        # reload stale auth state while clearing the authorization code.
        client._store_token(token)
        return token

    raise ActionFailure(
        f"OAuth authorization failed: timed out after {poll_timeout}s "
        "waiting for user authorization."
    )


def resolve_mattermost_auth(asset: Asset) -> httpx.Auth:
    """Return the preferred configured Mattermost authentication method."""
    if asset.personal_token:
        return build_pat_auth(asset)
    if asset.client_id and asset.client_secret:
        return build_oauth_auth(asset)
    raise ActionFailure(MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG)
