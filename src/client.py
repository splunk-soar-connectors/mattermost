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

from typing import TYPE_CHECKING, Any

import httpx
from soar_sdk.exceptions import ActionFailure

from .auth import build_oauth_auth, build_pat_auth
from .consts import MATTERMOST_API_BASE_URL


if TYPE_CHECKING:
    from .asset import Asset


DEFAULT_HEADERS = {"Accept": "application/json"}


def _request_with_auth(
    method: str,
    url: str,
    asset: Asset,
    *,
    auth: httpx.Auth,
    params: dict[str, Any] | None,
    json: dict[str, Any] | None,
    data: dict[str, Any] | None,
    files: dict[str, Any] | None,
    headers: dict[str, str],
    timeout: float,
) -> httpx.Response:
    try:
        with httpx.Client(
            timeout=timeout,
            verify=asset.verify_server_cert,
        ) as client:
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
) -> httpx.Response:
    """Send one authenticated request, preserving legacy auth fallback."""
    base_url = MATTERMOST_API_BASE_URL.format(server_url=asset.server_url.rstrip("/"))
    url = f"{base_url}{endpoint}"
    headers = {**DEFAULT_HEADERS, **(extra_headers or {})}

    auth_candidates: list[httpx.Auth] = []
    if asset.personal_token:
        auth_candidates.append(build_pat_auth(asset))
    if asset.client_id and asset.client_secret:
        auth_candidates.append(build_oauth_auth(asset))
    if not auth_candidates:
        raise ActionFailure(
            "Please provide 'personal_token' or run test connectivity with "
            "'client_id' and 'client_secret'"
        )

    response = _request_with_auth(
        method,
        url,
        asset,
        auth=auth_candidates[0],
        params=params,
        json=json,
        data=data,
        files=files,
        headers=headers,
        timeout=timeout,
    )
    if response.status_code != 401 or len(auth_candidates) == 1:
        return response

    return _request_with_auth(
        method,
        url,
        asset,
        auth=auth_candidates[1],
        params=params,
        json=json,
        data=data,
        files=files,
        headers=headers,
        timeout=timeout,
    )


def parse_json_response(response: httpx.Response) -> Any:
    """Validate an HTTP response and return its JSON body."""
    if not 200 <= response.status_code < 300:
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            message = payload.get("detailed_error") or payload.get("message")
        else:
            message = None
        message = message or response.text or "No response body"
        raise ActionFailure(f"Mattermost API error {response.status_code}: {message}")

    try:
        return response.json()
    except ValueError as exc:
        raise ActionFailure(
            f"Unable to parse Mattermost API JSON response: {exc}"
        ) from exc
