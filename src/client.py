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

from bs4 import BeautifulSoup
import httpx
from soar_sdk.exceptions import ActionFailure

from .auth import build_oauth_auth, build_pat_auth
from .consts import MATTERMOST_API_BASE_URL


if TYPE_CHECKING:
    from .asset import Asset


def _request_with_auth(
    method: str,
    url: str,
    *,
    auth: httpx.Auth,
    params: dict[str, Any] | None,
    json: Any | None,
    data: Any | None,
    files: dict[str, Any] | None,
    headers: dict[str, str],
    timeout: float | None,
    verify_ssl: bool,
) -> httpx.Response:
    try:
        raw_content = data if isinstance(data, str | bytes | bytearray) else None
        form_data = None if raw_content is not None else data
        with httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=True,
        ) as client:
            return client.request(
                method=method,
                url=url,
                auth=auth,
                headers=headers,
                params=params,
                json=json,
                data=form_data,
                content=raw_content,
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
    json: Any | None = None,
    data: Any | None = None,
    files: dict[str, Any] | None = None,
    timeout: float | None = None,
    headers: dict[str, str] | None = None,
    query_string: str | None = None,
    verify_ssl: bool | None = None,
) -> httpx.Response:
    """Send one authenticated request, preserving legacy auth fallback."""
    base_url = MATTERMOST_API_BASE_URL.format(server_url=asset.server_url.rstrip("/"))
    url = f"{base_url}{endpoint}"
    if query_string:
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}{query_string.lstrip('?')}"
    request_headers = headers or {}
    request_verify_ssl = asset.verify_server_cert if verify_ssl is None else verify_ssl
    request_timeout = timeout

    def request_with_auth(auth: httpx.Auth) -> httpx.Response:
        return _request_with_auth(
            method,
            url,
            auth=auth,
            params=params,
            json=json,
            data=data,
            files=files,
            headers=request_headers,
            timeout=request_timeout,
            verify_ssl=request_verify_ssl,
        )

    has_oauth_credentials = bool(asset.client_id and asset.client_secret)
    if asset.personal_token:
        response = request_with_auth(build_pat_auth(asset))
        if response.status_code != 401 or not has_oauth_credentials:
            return response
        return request_with_auth(build_oauth_auth(asset))

    if has_oauth_credentials:
        return request_with_auth(build_oauth_auth(asset))

    raise ActionFailure(
        "Please provide 'personal_token' or run test connectivity with "
        "'client_id' and 'client_secret'"
    )


def parse_json_response(response: httpx.Response) -> Any:
    """Process a response using the legacy connector's response semantics."""
    content_type = response.headers.get("Content-Type", "")
    if any(
        content_type_part in content_type
        for content_type_part in ("json", "text/javascript", "text/plain")
    ):
        try:
            payload = response.json()
        except ValueError as exc:
            raise ActionFailure(f"Unable to parse JSON response. Error: {exc}") from exc

        if 200 <= response.status_code < 399:
            return payload

        message = None
        if isinstance(payload, dict) and payload.get("detailed_error"):
            message = f"Error from server. Status Code: {response.status_code} Data from server: {payload['detailed_error']}"
        elif isinstance(payload, dict) and payload.get("message"):
            message = f"Error from server. Status Code: {response.status_code} Data from server: {payload['message']}"
        if not message:
            response_text = response.text.replace("{", "{{").replace("}", "}}")
            message = f"Error from server. Status Code: {response.status_code} Data from server: {response_text}"
        raise ActionFailure(message)

    if "html" in content_type:
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = "\n".join(
                line.strip() for line in soup.text.split("\n") if line.strip()
            )
        except Exception:
            error_text = "Cannot parse error details"

        message = (
            f"Status Code: {response.status_code}. Data from server:\n{error_text}\n"
        )
        if response.status_code in [200, 201, 204]:
            message = f"Status Code: {response.status_code}. Data from server:\nInvalid URL. Cannot parse response.\n"
        elif response.status_code == 403:
            message = f"Status Code: {response.status_code}. Data from server:\nForbidden. Please verify credentials.\n"
        raise ActionFailure(message.replace("{", "{{").replace("}", "}}"))

    if not response.text:
        if response.status_code in [200, 204]:
            return {}
        raise ActionFailure("Empty response and no information in the header")

    response_text = response.text.replace("{", "{{").replace("}", "}}")
    raise ActionFailure(
        f"Can't process response from server. Status Code: {response.status_code} Data from server: {response_text}"
    )
