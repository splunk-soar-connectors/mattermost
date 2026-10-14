# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import httpx
import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions._helpers import (
    _create_post,
    _get_posts,
    _list_all_teams,
    _paginate_all,
    _process_posts,
    _resolve_team_id,
    _validate_and_convert_time,
)
from src.actions.list_channels import ListChannelsParams, list_channels
from src.actions.list_posts import ListPostsOutput, ListPostsParams, list_posts
from src.actions.list_teams import ListTeamsOutput, list_teams
from src.actions.list_users import (
    ListUsersOutput,
    ListUsersParams,
    list_users,
)
from src.actions.make_request import MattermostMakeRequestParams, make_request
from src.actions.upload_file import UploadFileParams, upload_file
from src.app import app
from src.auth import build_oauth_client, migrate_legacy_oauth_state
from src.asset import Asset
from src.client import call_mattermost, parse_json_response


def _asset() -> Asset:
    return Asset(
        server_url="https://mattermost.example.com",
        verify_server_cert=True,
        personal_token="personal-token",
    )


def _auth_state(*, current: dict, legacy: dict) -> MagicMock:
    state = MagicMock()
    state.get_all.return_value = current
    state.backend.load_state.return_value = legacy
    state.asset_id = "asset-id"
    return state


def _migration_asset(auth_state: MagicMock) -> SimpleNamespace:
    return SimpleNamespace(client_id="client-id", auth_state=auth_state)


def test_migrate_legacy_oauth_state_preserves_plaintext_token() -> None:
    auth_state = _auth_state(
        current={"session": {"session_id": "session-id"}},
        legacy={
            "token": {
                "access_token": "legacy-access-token",
                "refresh_token": "legacy-refresh-token",
                "scope": "read",
            }
        },
    )
    asset = _migration_asset(auth_state)

    migrate_legacy_oauth_state(asset)

    saved_state = auth_state.put_all.call_args.args[0]
    assert saved_state["session"] == {"session_id": "session-id"}
    assert saved_state["oauth"] == {
        "token": {
            "access_token": "legacy-access-token",
            "token_type": "Bearer",
            "refresh_token": "legacy-refresh-token",
            "scope": "read",
        },
        "client_id": "client-id",
    }


def test_migrate_legacy_oauth_state_decrypts_token_values() -> None:
    auth_state = _auth_state(
        current={},
        legacy={
            "token": {
                "access_token": "encrypted-access-token",
                "refresh_token": "legacy-refresh-token",
                "is_encrypted": True,
            }
        },
    )
    asset = _migration_asset(auth_state)

    with patch(
        "src.auth.encryption_helper.decrypt",
        return_value="access-token",
    ) as decrypt:
        migrate_legacy_oauth_state(asset)

    decrypt.assert_called_once_with("encrypted-access-token", "asset-id")
    assert auth_state.put_all.call_args.args[0]["oauth"]["token"]["access_token"] == (
        "access-token"
    )
    assert auth_state.put_all.call_args.args[0]["oauth"]["token"]["refresh_token"] == (
        "legacy-refresh-token"
    )


def test_migrate_legacy_oauth_state_does_not_overwrite_sdk_token() -> None:
    auth_state = _auth_state(
        current={
            "oauth": {
                "token": {"access_token": "sdk-access-token"},
                "client_id": "client-id",
            }
        },
        legacy={
            "token": {"access_token": "legacy-access-token"},
        },
    )
    asset = _migration_asset(auth_state)

    migrate_legacy_oauth_state(asset)

    auth_state.put_all.assert_not_called()


def test_migrate_legacy_oauth_state_ignores_invalid_legacy_token() -> None:
    auth_state = _auth_state(
        current={},
        legacy={
            "token": {
                "access_token": "encrypted-access-token",
                "is_encrypted": True,
            }
        },
    )
    asset = _migration_asset(auth_state)

    with patch(
        "src.auth.encryption_helper.decrypt",
        side_effect=ValueError("invalid token"),
    ):
        migrate_legacy_oauth_state(asset)

    auth_state.put_all.assert_not_called()


def test_build_oauth_client_migrates_legacy_state_before_use() -> None:
    asset = SimpleNamespace(
        server_url="https://mattermost.example.com",
        client_id="client-id",
        client_secret="client-secret",  # pragma: allowlist secret
        verify_server_cert=True,
        auth_state=MagicMock(),
    )

    with (
        patch("src.auth.migrate_legacy_oauth_state") as migrate,
        patch("src.auth.SOARAssetOAuthClient") as oauth_client,
    ):
        result = build_oauth_client(asset)

    migrate.assert_called_once_with(asset)
    assert result is oauth_client.return_value


def test_parse_json_response_returns_success_payload() -> None:
    response = httpx.Response(200, json={"id": "post-id"})

    assert parse_json_response(response) == {"id": "post-id"}


def test_parse_json_response_raises_action_failure_for_api_error() -> None:
    response = httpx.Response(401, json={"message": "Not authorized"})

    with pytest.raises(ActionFailure, match="Not authorized"):
        parse_json_response(response)


def test_parse_json_response_accepts_legacy_success_status_range() -> None:
    response = httpx.Response(398, json={"id": "post-id"})

    assert parse_json_response(response) == {"id": "post-id"}


def test_parse_json_response_preserves_legacy_empty_success_behavior() -> None:
    assert parse_json_response(httpx.Response(204)) == {}


def test_parse_json_response_processes_legacy_html_errors() -> None:
    response = httpx.Response(
        403,
        text="<html><script>ignored</script><h1>Forbidden</h1></html>",
        headers={"Content-Type": "text/html"},
    )

    with pytest.raises(ActionFailure, match=r"Forbidden\. Please verify credentials"):
        parse_json_response(response)


def test_list_users_output_preserves_nested_timezone_flag() -> None:
    user = {
        "timezone": {
            "automaticTimezone": "UTC",
            "manualTimezone": "",
            "useAutomaticTimezone": True,
        }
    }

    output = ListUsersOutput(**user)

    assert output.model_dump()["timezone"]["useAutomaticTimezone"] is True


def test_list_users_output_preserves_typed_notify_props_and_raw_props() -> None:
    output = ListUsersOutput(
        notify_props={"email": "true", "desktop": "mention"},
        props={"future_property": {"enabled": True}},
    )

    dumped = output.model_dump()
    assert dumped["notify_props"]["email"] == "true"
    assert dumped["notify_props"]["desktop"] == "mention"
    assert dumped["props"] == {"future_property": {"enabled": True}}


def test_list_teams_output_preserves_legacy_fields_and_extra_values() -> None:
    team = {
        "id": "team-id",
        "name": "team-name",
        "allowed_domains": "example.com",
        "group_constrained": False,
        "legacy_extra": {"key": "value"},
    }

    output = ListTeamsOutput(**team)

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


def test_call_mattermost_preserves_legacy_request_defaults() -> None:
    response = httpx.Response(200, json={"id": "user-id"})

    with patch("src.client._request_with_auth", return_value=response) as request:
        call_mattermost("GET", "/users/me", _asset())

    assert request.call_args.kwargs["headers"] == {}
    assert request.call_args.kwargs["timeout"] is None


def test_create_post_sends_legacy_serialized_body() -> None:
    response = httpx.Response(200, json={"id": "post-id"})

    with patch("src.actions._helpers.call_mattermost", return_value=response) as call:
        _create_post({"channel_id": "channel-id", "message": "hello"}, _asset())

    assert call.call_args.kwargs["data"] == (
        '{"channel_id": "channel-id", "message": "hello"}'
    )


@pytest.mark.parametrize(
    ("message", "expected_message"),
    [(None, "Phantom file upload"), ("", "")],
)
def test_upload_file_preserves_legacy_empty_message_behavior(
    message: str | None, expected_message: str
) -> None:
    soar = Mock()
    attachment = MagicMock(container_id="container-id", name="test.txt")
    attachment.open.return_value.__enter__.return_value.read.return_value = b"content"
    soar.vault.get_attachment.return_value = [attachment]
    soar.get_executing_container_id.return_value = "container-id"

    with (
        patch("src.actions.upload_file._resolve_team_id", return_value="team-id"),
        patch("src.actions.upload_file._resolve_channel_id", return_value="channel-id"),
        patch(
            "src.actions.upload_file.call_mattermost",
            return_value=httpx.Response(200, json={"file_infos": [{"id": "file-id"}]}),
        ),
        patch(
            "src.actions.upload_file._create_post",
            return_value={"id": "post-id"},
        ) as create_post,
    ):
        upload_file(
            UploadFileParams(
                team="team",
                channel="channel",
                vault_id="vault-id",
                message=message,
            ),
            soar,
            _asset(),
        )

    assert create_post.call_args.args[0]["message"] == expected_message


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
        pytest.raises(ActionFailure, match="exceeded the safety limit"),
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
        pytest.raises(ActionFailure, match="exceeded the safety limit"),
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


def test_generic_user_pagination_reports_page_limit() -> None:
    response = httpx.Response(200, json=[{"id": "user-id"}])

    with (
        patch("src.actions._helpers.call_mattermost", return_value=response),
        patch("src.actions._helpers.MATTERMOST_MAX_GENERIC_PAGES", 1),
        pytest.raises(ActionFailure, match=r"safe generic page limit \(1\)"),
    ):
        _paginate_all("/users", _asset())


def test_team_resolution_reports_page_limit() -> None:
    response = httpx.Response(200, json=[{"id": "other-team"}])

    with (
        patch("src.actions._helpers.call_mattermost", return_value=response),
        patch("src.actions._helpers.MATTERMOST_MAX_GENERIC_PAGES", 1),
        pytest.raises(ActionFailure, match=r"safe generic page limit \(1\)"),
    ):
        _resolve_team_id("target-team", _asset())


def test_list_teams_reports_page_limit() -> None:
    response = httpx.Response(
        200,
        json=[{"id": "team-id", "name": "team-name"}],
    )

    with (
        patch("src.actions._helpers.call_mattermost", return_value=response),
        patch("src.actions._helpers.MATTERMOST_MAX_GENERIC_PAGES", 1),
        pytest.raises(ActionFailure, match=r"safe generic page limit \(1\)"),
    ):
        _list_all_teams(_asset())


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
