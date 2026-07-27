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
# Single HTTP call function for the Mattermost app, replacing legacy's
# `_make_rest_call` / `_handle_update_request`. All auth resolution is
# delegated to auth.py's resolve_mattermost_auth() — no action or helper in
# this app should build an Authorization header directly.

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from soar_sdk.exceptions import ActionFailure

from .auth import resolve_mattermost_auth
from .consts import MATTERMOST_API_BASE_URL

if TYPE_CHECKING:
    from .app import Asset

MATTERMOST_DEFAULT_HEADERS: dict[str, str] = {
    "Accept": "application/json",
}


def call_mattermost(
    method: str,
    endpoint: str,
    asset: Asset,
    *,
    params: dict[str, Any] | None = None,
    json: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    files: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 30.0,
    verify: bool | None = None,
) -> httpx.Response:
    """Make an authenticated request against the asset's Mattermost server.

    ``verify`` defaults to ``asset.verify_server_cert`` (legacy's
    ``self._verify_server_cert``, defaulting to False) when not explicitly
    overridden by the caller.
    """
    base_url = MATTERMOST_API_BASE_URL.format(server_url=asset.server_url.rstrip("/"))
    url = f"{base_url}{endpoint}"
    headers = {**MATTERMOST_DEFAULT_HEADERS, **(extra_headers or {})}
    auth = resolve_mattermost_auth(asset)  # raises ActionFailure when unconfigured
    should_verify = asset.verify_server_cert if verify is None else verify

    try:
        with httpx.Client(timeout=timeout, verify=bool(should_verify)) as client:
            return client.request(
                method=method,
                url=url,
                auth=auth,
                headers=headers,
                params=params,
                json=json,
                data=data,
                files=files,
            )
    except httpx.RequestError as exc:
        raise ActionFailure(f"Error connecting to Mattermost API: {exc}") from exc
    except Exception as exc:
        raise ActionFailure(f"Unexpected error during request: {exc}") from exc
