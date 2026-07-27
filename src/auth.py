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
# Authentication for the Mattermost app, built entirely on soar_sdk.auth.
#
# Mattermost supports two credential styles (see legacy
# mattermost_connector.py _handle_update_request / _handle_test_connectivity /
# _handle_interactive_login):
#   1. Personal Access Token (PAT, asset.personal_token) — a static bearer
#      token, sent as `Authorization: Bearer <personal_token>`.
#   2. OAuth App (asset.client_id / asset.client_secret) — the 3-legged
#      authorization code flow against the Mattermost server's own
#      /oauth/authorize and /oauth/access_token endpoints, with the resulting
#      access_token also sent as `Authorization: Bearer <access_token>`.
#
# Legacy's own precedence (see _handle_update_request / _handle_test_connectivity):
# try personal_token first: if it works, use it; only fall through to the
# OAuth-derived access_token if personal_token is absent, or is present but
# fails with a 401 *and* client_id/client_secret are also configured.
# resolve_mattermost_auth() below implements the simple "PAT if configured,
# else OAuth" half of that precedence — the 401-triggered fallback-to-OAuth
# behavior lives in test_connectivity's/client.py's retry logic in a later
# per-action port pass (call_mattermost() only resolves auth once per call).

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

from .consts import (
    MATTERMOST_ACCESS_TOKEN_URL,
    MATTERMOST_AUTHORIZE_URL,
    MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG,
    MATTERMOST_TC_STATUS_SLEEP,
)

if TYPE_CHECKING:
    # Asset lives in app.py for this app (no standalone asset.py) — see
    # target_structure in the design doc: app.py owns Asset + App(...) + the
    # test_connectivity decorator wiring only.
    from .app import Asset

# How long test_connectivity waits (in seconds) for the user to complete the
# browser authorization step before giving up. Legacy waited a fixed 15s
# (MATTERMOST_AUTHORIZE_WAIT_TIME) plus up to 105s via self._wait(); this uses
# the SDK-idiomatic poll loop shape from the github reference app instead —
# TODO(per-action port pass): reconcile the exact poll_timeout with legacy's
# combined ~120s wait budget if operators report the default is too short/long.
_OAUTH_POLL_TIMEOUT = 300


def build_pat_auth(asset: Asset) -> StaticTokenAuth:
    """Return SDK bearer auth for a Mattermost Personal Access Token.

    Matches legacy's ``headers = {"Authorization": f"Bearer {self._personal_token}"}``
    in ``_handle_update_request`` / ``_handle_test_connectivity`` exactly.
    """
    return StaticTokenAuth(asset.personal_token)


def _build_oauth_config(
    asset: Asset, *, redirect_uri: str | None = None
) -> OAuthConfig:
    """Build the OAuth config shared by the flow and the bearer auth.

    Mattermost's authorize/token endpoints are per-server (``asset.server_url``),
    unlike GitHub's fixed endpoints — so these are formatted from the
    already-seeded consts.py templates using the asset's configured server_url,
    not re-typed literals. ``MATTERMOST_AUTHORIZE_URL`` bakes response_type/
    client_id/redirect_uri/state directly into its template (legacy built the
    full authorize URL itself rather than relying on the OAuth client to append
    those params); splitting off everything before "?" here recovers just the
    bare authorization endpoint that OAuthConfig/SOARAssetOAuthClient expect,
    since the SDK client builds those same query params itself in
    ``create_authorization_url``.
    """
    base_url = asset.server_url.rstrip("/")
    authorization_endpoint = MATTERMOST_AUTHORIZE_URL.split("?")[0].format(
        server_url=base_url
    )
    token_endpoint = MATTERMOST_ACCESS_TOKEN_URL.format(server_url=base_url)
    return OAuthConfig(
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        redirect_uri=redirect_uri,
        # Legacy's OAuth App flow never sent a `scope` param (see
        # _handle_interactive_login's request_data / MATTERMOST_AUTHORIZE_URL) —
        # intentionally omitted here rather than inventing one.
    )


def _mattermost_oauth_http_client() -> httpx.Client:
    """HTTP client for the OAuth token endpoint.

    Mirrors legacy's _make_rest_call default behavior for the access-token
    POST (no special Accept header was required there since Mattermost's
    /oauth/access_token already returns JSON), but SDK OAuth clients still
    expect JSON responses, so Accept is pinned here defensively.
    """
    return httpx.Client(headers={"Accept": "application/json"}, timeout=30.0)


def build_oauth_client(
    asset: Asset, *, redirect_uri: str | None = None
) -> SOARAssetOAuthClient:
    """Return the SDK OAuth client bound to the asset's persisted auth_state."""
    return SOARAssetOAuthClient(
        _build_oauth_config(asset, redirect_uri=redirect_uri),
        asset.auth_state,
        http_client=_mattermost_oauth_http_client(),
    )


def build_oauth_auth(asset: Asset) -> OAuthBearerAuth:
    """Return SDK bearer auth that reads/refreshes the OAuth token from auth_state."""
    return OAuthBearerAuth(build_oauth_client(asset), auto_refresh=True)


def complete_oauth_authorization(
    asset: Asset,
    *,
    asset_id: str,
    redirect_uri: str,
    announce_url: Callable[[str], None],
    poll_timeout: int = _OAUTH_POLL_TIMEOUT,
    poll_interval: int = MATTERMOST_TC_STATUS_SLEEP,
) -> OAuthToken:
    """Drive the authorization code flow to obtain and persist an OAuth token.

    Replaces legacy's ``_handle_interactive_login`` (state-file-based code
    exchange + ``self._wait``). If a valid token is already stored for the
    current credentials it is reused. Otherwise an authorization URL is
    generated and handed to ``announce_url`` (so the caller can surface it to
    the user), then this polls ``auth_state`` until the webhook callback lands
    the authorization code, exchanges it for a token, and returns it. Raises
    ActionFailure if the user does not authorize within ``poll_timeout``
    seconds.

    TODO(per-action port pass): this function's body mirrors the
    already-working `github` reference app's `complete_oauth_authorization`
    verbatim (its SOARAssetOAuthClient call shapes were confirmed against the
    installed soar_sdk package for this build tree). It has not yet been
    exercised end-to-end against a live Mattermost server from this app, so
    the per-action port pass for test_connectivity should verify the flow
    against a real asset before relying on it.
    """
    client = build_oauth_client(asset, redirect_uri=redirect_uri)

    # Reuse an existing token when the stored credentials still match.
    try:
        if client.get_stored_token() is not None:
            return client.get_valid_token(auto_refresh=True)
    except ConfigurationChangedError:
        # client_id changed → stored token was cleared, fall through to re-auth.
        pass

    auth_url, _ = client.create_authorization_url(asset_id, use_pkce=False)
    announce_url(auth_url)

    deadline = time.time() + poll_timeout
    while time.time() < deadline:
        time.sleep(poll_interval)
        code = client.get_authorization_code(force_reload=True)
        if code:
            token = client.fetch_token_with_authorization_code(code)
            # SDK bug workaround (also present in the github reference app):
            # fetch_token_with_authorization_code() stores the token, then
            # clears the session by re-saving a state object it loaded
            # *before* the token existed — which wipes the token from
            # auth_state. It still returns a valid token, so re-persist it
            # here; otherwise the subsequent connectivity probe reads an
            # empty auth_state.
            client._store_token(token)
            return token

    raise ActionFailure(
        f"OAuth authorization failed: timed out after {poll_timeout}s waiting for user authorization."
    )


def resolve_mattermost_auth(asset: Asset) -> httpx.Auth:
    """Return the correct httpx.Auth for the configured asset credentials.

    Priority order (matches legacy's own precedence in
    ``_handle_update_request``/``_handle_test_connectivity`` — try
    personal_token first, fall through to the OAuth-derived access_token):
      1. personal_token (PAT)                  → StaticTokenAuth
      2. client_id / client_secret (OAuth App)  → OAuthBearerAuth (auth_state)

    Raises ActionFailure when neither credential set is present.
    """
    if asset.personal_token:
        return build_pat_auth(asset)

    if asset.client_id and asset.client_secret:
        return build_oauth_auth(asset)

    raise ActionFailure(MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG)
