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
    _get_posts,
    _process_posts,
    _resolve_team_id,
    _validate_and_convert_time,
)
from src.actions.list_channels import ListChannelsParams, list_channels
from src.actions.list_posts import ListPostsOutput, ListPostsParams, list_posts
from src.actions.list_teams import ListTeamsOutput, _normalize_team_output, list_teams
from src.actions.list_users import ListUsersParams, _normalize_user_output, list_users
from src.actions.make_request import MattermostMakeRequestParams, make_request
from src.app import app
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


def test_normalize_user_output_preserves_nested_timezone_flag() -> None:
    user = {
        "timezone": {
            "automaticTimezone": "UTC",
            "manualTimezone": "",
            "useAutomaticTimezone": True,
        }
    }

    normalized = _normalize_user_output(user)

    assert normalized["timezone"]["useAutomaticTimezone"] is True


def test_list_teams_output_preserves_legacy_fields_and_extra_values() -> None:
    team = {
        "id": "team-id",
        "name": "team-name",
        "allowed_domains": "example.com",
        "group_constrained": False,
        "legacy_extra": {"key": "value"},
    }

    output = ListTeamsOutput(**_normalize_team_output(team))

    assert output.model_dump()["allowed_domains"] == "example.com"
    assert output.model_dump()["group_constrained"] is False
    assert output.model_dump()["legacy_extra"] == {"key": "value"}


def test_output_model_preserves_structured_post_values() -> None:
    output = ListPostsOutput(file_ids=["file-id"], participants=["user-id"])

    assert output.model_dump()["file_ids"] == ["file-id"]
    assert output.model_dump()["participants"] == ["user-id"]


def test_call_mattermost_falls_back_to_oauth_after_pat_401() -> None:
    asset = Asset(
        server_url="https://mattermost.example.com",
        personal_token="expired-token",
        client_id="client-id",
        client_secret="client-secret",  # pragma: allowlist secret
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


def test_make_request_is_registered_and_passes_request_parameters() -> None:
    response = httpx.Response(200, text='{"id":"user-id"}')
    with patch(
        "src.actions.make_request.call_mattermost", return_value=response
    ) as call:
        output = make_request(
            MattermostMakeRequestParams(
                http_method="GET",
                endpoint="users/me",
                headers='{"X-Test":"value"}',
                query_parameters="?per_page=1",
                timeout=10,
                verify_ssl=True,
            ),
            _asset(),
        )

    assert "make_request" in app.get_actions()
    assert output.status_code == 200
    assert output.response_body == '{"id":"user-id"}'
    assert call.call_args.args[:2] == ("GET", "/users/me")
    assert call.call_args.kwargs["headers"] == {"X-Test": "value"}
    assert call.call_args.kwargs["query_string"] == "per_page=1"
    assert call.call_args.kwargs["verify_ssl"] is True


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


def test_get_posts_reports_the_post_length_limit() -> None:
    response = httpx.Response(
        200,
        json={"order": ["post-1"], "posts": {"post-1": {"id": "post-1"}}},
    )

    with (
        patch("src.actions._helpers.call_mattermost", return_value=response),
        patch("src.actions._helpers.MATTERMOST_MAX_POSTS", 1),
        pytest.raises(ActionFailure, match="safe post length limit"),
    ):
        _get_posts("/channels/channel-id/posts", _asset())


def test_get_posts_reports_the_page_limit() -> None:
    response = httpx.Response(
        200,
        json={"order": ["post-1"], "posts": {"post-1": {"id": "post-1"}}},
    )

    with (
        patch("src.actions._helpers.call_mattermost", return_value=response),
        patch("src.actions._helpers.MATTERMOST_MAX_POST_PAGES", 1),
        pytest.raises(ActionFailure, match="safe page limit"),
    ):
        _get_posts("/channels/channel-id/posts", _asset())


def test_resolve_team_id_stops_after_matching_page() -> None:
    response = httpx.Response(
        200,
        json=[{"id": "team-id", "name": "target-team"}],
    )

    with patch("src.actions._helpers.call_mattermost", return_value=response) as call:
        assert _resolve_team_id("target-team", _asset()) == "team-id"

    call.assert_called_once_with("GET", "/teams", _asset(), params={"page": 0})


def test_process_posts_stops_at_end_time() -> None:
    posts = [
        {"id": "new", "create_at": 300},
        {"id": "old", "create_at": 100},
    ]

    with patch("src.actions._helpers._get_posts", return_value=posts):
        result = _process_posts("/posts", _asset(), 50, 200)

    assert result == [{"id": "old", "create_at": 100}]


def test_process_posts_preserves_legacy_end_time_fallback() -> None:
    older_posts = [{"id": "old", "create_at": 100}]

    with patch(
        "src.actions._helpers._get_posts", side_effect=[[], older_posts]
    ) as get_posts:
        result = _process_posts("/posts", _asset(), None, 200)

    assert result == older_posts
    assert get_posts.call_args_list[0].args[2] == {"since": 200}
    assert get_posts.call_args_list[1].args[2] == {}


def test_registered_list_posts_action_preserves_empty_result_message() -> None:
    soar = Mock()
    action = app.get_actions()["list_posts"]

    with (
        patch("src.actions.list_posts._resolve_team_id", return_value="team-id"),
        patch("src.actions.list_posts._resolve_channel_id", return_value="channel-id"),
        patch("src.actions.list_posts._process_posts", return_value=[]),
    ):
        result = action(
            ListPostsParams(team="team", channel="channel"),
            soar=soar,
            asset=_asset(),
        )

    assert action.meta.render_as == "table"
    assert result is True
    soar.set_message.assert_called_once_with("No posts found")


def test_list_actions_preserve_legacy_count_messages() -> None:
    soar = Mock()
    asset = _asset()

    with patch(
        "src.actions.list_users._paginate_all",
        return_value=[{"id": "user-id"}],
    ):
        list_users(ListUsersParams(), soar, asset)
    soar.set_message.assert_called_with("Total users: 1")

    with (
        patch("src.actions.list_channels._resolve_team_id", return_value="team-id"),
        patch(
            "src.actions.list_channels._list_all_channels",
            return_value=[{"id": "channel-id"}],
        ),
    ):
        list_channels(ListChannelsParams(team="team"), soar, asset)
    soar.set_message.assert_called_with("Total channels: 1")

    with patch(
        "src.actions.list_teams._list_all_teams",
        return_value=[{"id": "team-id"}],
    ):
        list_teams(None, soar, asset)
    soar.set_message.assert_called_with("Total teams: 1")

    with (
        patch("src.actions.list_posts._resolve_team_id", return_value="team-id"),
        patch("src.actions.list_posts._resolve_channel_id", return_value="channel-id"),
        patch(
            "src.actions.list_posts._process_posts",
            return_value=[{"id": "post-id"}],
        ),
    ):
        list_posts(ListPostsParams(team="team", channel="channel"), soar, asset)
    soar.set_message.assert_called_with("Total posts: 1")
