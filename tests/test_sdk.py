# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

from unittest.mock import Mock, patch

import httpx
import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions._helpers import (
    _check_response,
    _get_posts,
    _process_posts,
    _validate_and_convert_time,
)
from src.actions.list_users import _normalize_user_output
from src.asset import Asset
from src.client import call_mattermost, parse_json_response


def _asset() -> Asset:
    return Asset(
        server_url="https://mattermost.example.com",
        verify_server_cert=True,
        personal_token="personal-token",
    )


def test_parse_json_response_returns_success_payload() -> None:
    response = httpx.Response(200, json={"id": "post-id"})

    assert parse_json_response(response) == {"id": "post-id"}


def test_parse_json_response_raises_action_failure_for_api_error() -> None:
    response = httpx.Response(401, json={"message": "Not authorized"})

    with pytest.raises(ActionFailure, match="Not authorized"):
        parse_json_response(response)


def test_parse_json_response_returns_none_for_no_content() -> None:
    response = httpx.Response(204)

    assert parse_json_response(response) is None


def test_parse_json_response_rejects_empty_success_body() -> None:
    response = httpx.Response(200, content=b"")

    with pytest.raises(ActionFailure, match="empty response body"):
        parse_json_response(response)


def test_parse_json_response_reports_non_json_response_details() -> None:
    response = httpx.Response(
        200,
        content=b"upstream failure",
        headers={"content-type": "text/html"},
    )

    with pytest.raises(ActionFailure, match=r"HTTP 200.*text/html.*upstream failure"):
        parse_json_response(response)


def test_check_response_rejects_unexpected_json_type() -> None:
    response = httpx.Response(200, json={"posts": []})

    with pytest.raises(ActionFailure, match="expected list, got dict"):
        _check_response(response, list)


def test_normalize_user_output_stringifies_nested_timezone_flag() -> None:
    user = {
        "timezone": {
            "automaticTimezone": "UTC",
            "manualTimezone": "",
            "useAutomaticTimezone": True,
        }
    }

    normalized = _normalize_user_output(user)

    assert normalized["timezone"]["useAutomaticTimezone"] == "true"


def test_call_mattermost_falls_back_to_oauth_after_pat_401() -> None:
    asset = Asset(
        server_url="https://mattermost.example.com",
        personal_token="expired-token",
        client_id="client-id",
        client_secret="client-secret",
    )
    pat_response = httpx.Response(401)
    oauth_response = httpx.Response(200, json={"id": "user-id"})

    with (
        patch(
            "src.client._request_with_auth", side_effect=[pat_response, oauth_response]
        ) as request,
        patch("src.client.build_oauth_auth", return_value=Mock()),
    ):
        response = call_mattermost("GET", "/users/me", asset)

    assert response is oauth_response
    assert request.call_count == 2
    assert (
        request.call_args_list[0].kwargs["auth"].__class__.__name__ == "StaticTokenAuth"
    )


def test_validate_and_convert_time_accepts_date_and_iso_timestamp() -> None:
    assert _validate_and_convert_time("1970-01-01") == 0
    assert _validate_and_convert_time("1970-01-01T00:00:01Z") == 1000


def test_validate_and_convert_time_rejects_invalid_timestamp() -> None:
    with pytest.raises(ActionFailure):
        _validate_and_convert_time("not-a-timestamp")


def test_get_posts_rejects_a_repeated_page() -> None:
    response = httpx.Response(
        200,
        json={"order": ["post-1"], "posts": {"post-1": {"id": "post-1"}}},
    )

    with (
        patch("src.actions._helpers.call_mattermost", return_value=response),
        pytest.raises(ActionFailure, match="stopped making progress"),
    ):
        _get_posts("/channels/channel-id/posts", _asset())


def test_process_posts_stops_at_end_time() -> None:
    posts = [
        {"id": "new", "create_at": 300},
        {"id": "old", "create_at": 100},
    ]

    with patch("src.actions._helpers._get_posts", return_value=posts):
        result = _process_posts("/posts", _asset(), 50, 200)

    assert result == [{"id": "old", "create_at": 100}]
