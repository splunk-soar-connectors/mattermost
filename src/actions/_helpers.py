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

import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from soar_sdk.exceptions import ActionFailure

from ..client import call_mattermost, parse_json_response
from ..consts import (
    MATTERMOST_CHANNEL_NOT_FOUND_MSG,
    MATTERMOST_LIST_CHANNELS_ENDPOINT,
    MATTERMOST_MAX_GENERIC_PAGES,
    MATTERMOST_MAX_POST_PAGES,
    MATTERMOST_MAX_POSTS,
    MATTERMOST_NEGATIVE_TIME,
    MATTERMOST_SEND_MSG_ENDPOINT,
    MATTERMOST_TEAM_NOT_FOUND_MSG,
    MATTERMOST_TEAMS_ENDPOINT,
    MATTERMOST_TIMESTAMP_CONVERSION_FAILED_MSG,
    MATTERMOST_TIMESTAMP_VALIDATION_FAILED_MSG,
)


if TYPE_CHECKING:
    from ..asset import Asset


ISO8601_RE = re.compile(
    r"^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T"
    r"(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?"
    r"(Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])?$"
)


def _check_response(
    response, expected_type: type | tuple[type, ...] | None = None
) -> Any:
    """Decode a response and optionally validate its top-level JSON type."""
    payload = parse_json_response(response)
    if expected_type is not None and not isinstance(payload, expected_type):
        expected_name = (
            ", ".join(item.__name__ for item in expected_type)
            if isinstance(expected_type, tuple)
            else expected_type.__name__
        )
        actual_name = type(payload).__name__
        raise ActionFailure(
            f"Mattermost returned an unexpected response type: "
            f"expected {expected_name}, got {actual_name}"
        )
    return payload


def _item_key(item: Any) -> str:
    """Create a stable key for pagination progress detection."""
    return json.dumps(item, sort_keys=True, default=str)


def _stringify_legacy_fields(
    payload: dict[str, Any], field_names: set[str]
) -> dict[str, Any]:
    """Preserve legacy string output fields for structured API values."""
    output = dict(payload)
    for field_name in field_names:
        value = output.get(field_name)
        if value is not None and not isinstance(value, str):
            output[field_name] = json.dumps(value, sort_keys=True, default=str)
    return output


def _paginate_all(
    endpoint: str,
    asset: Asset,
    extra_params: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Fetch all pages while preventing unbounded or non-progressing loops."""
    page = 0
    results: list[dict[str, Any]] = []
    seen_items: set[str] = set()

    while page < MATTERMOST_MAX_GENERIC_PAGES:
        query = {"page": page, **(extra_params or {})}
        payload = _check_response(
            call_mattermost("GET", endpoint, asset, params=query), list
        )
        if not payload:
            return results
        if not isinstance(payload, list):
            raise ActionFailure("Mattermost returned an unexpected paginated response")

        new_items = [item for item in payload if _item_key(item) not in seen_items]
        if not new_items:
            raise ActionFailure("Mattermost pagination stopped making progress")
        results.extend(new_items)
        seen_items.update(_item_key(item) for item in new_items)
        page += 1

    raise ActionFailure("Mattermost pagination exceeded the safety limit")


def _resolve_team_id(team: str, asset: Asset) -> str:
    """Resolve a Mattermost team name or ID to its ID."""
    team_value = team.strip().lower()
    for each_team in _paginate_all(MATTERMOST_TEAMS_ENDPOINT, asset):
        if team_value in (
            str(each_team.get("id", "")).lower(),
            str(each_team.get("name", "")).lower(),
        ):
            return each_team["id"]
    raise ActionFailure(MATTERMOST_TEAM_NOT_FOUND_MSG)


def _list_all_teams(asset: Asset) -> list[dict[str, Any]]:
    """Return all Mattermost teams with duplicate-page protection."""
    return _paginate_all(MATTERMOST_TEAMS_ENDPOINT, asset)


def _resolve_channel_id(team_id: str, channel: str, asset: Asset) -> str:
    """Resolve a Mattermost channel name or ID to its ID."""
    endpoint = MATTERMOST_LIST_CHANNELS_ENDPOINT.format(team=team_id)
    channels = _check_response(call_mattermost("GET", endpoint, asset), list)
    channel_value = channel.strip().lower()
    for each_channel in channels:
        if channel_value in (
            str(each_channel.get("id", "")).lower(),
            str(each_channel.get("name", "")).lower(),
        ):
            return each_channel["id"]
    raise ActionFailure(MATTERMOST_CHANNEL_NOT_FOUND_MSG)


def _list_all_channels(team_id: str, asset: Asset) -> list[dict[str, Any]]:
    """Return public and private channels visible to the current user."""
    endpoint = MATTERMOST_LIST_CHANNELS_ENDPOINT.format(team=team_id)
    channels = _check_response(call_mattermost("GET", endpoint, asset), list)
    return [
        channel
        for channel in channels
        if str(channel.get("type", "")).lower() in {"o", "p"}
    ]


def _create_post(request_data: dict[str, Any], asset: Asset) -> dict[str, Any]:
    """Create a Mattermost post."""
    response = call_mattermost(
        "POST", MATTERMOST_SEND_MSG_ENDPOINT, asset, json=request_data
    )
    payload = _check_response(response, dict)
    return payload


def _validate_and_convert_time(time_stamp: str) -> int:
    """Validate an ISO timestamp or date and convert it to epoch milliseconds."""
    if ISO8601_RE.match(time_stamp) is None:
        try:
            datetime.strptime(time_stamp, "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            raise ActionFailure(MATTERMOST_TIMESTAMP_VALIDATION_FAILED_MSG) from None

    try:
        parsed = datetime.fromisoformat(time_stamp)
    except ValueError as exc:
        raise ActionFailure(
            f"{MATTERMOST_TIMESTAMP_CONVERSION_FAILED_MSG}. Error Details: {exc}"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    epoch_time = int(parsed.timestamp() * 1000)
    if epoch_time < 0:
        raise ActionFailure(MATTERMOST_NEGATIVE_TIME)
    return epoch_time


def _get_posts(
    endpoint: str,
    asset: Asset,
    extra_params: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Fetch posts with the legacy page and count safety limits preserved."""
    page = 0
    params = dict(extra_params or {})
    results: list[dict[str, Any]] = []
    seen_post_ids: set[str] = set()

    while page < MATTERMOST_MAX_POST_PAGES and len(results) < MATTERMOST_MAX_POSTS:
        params["page"] = page
        payload = _check_response(
            call_mattermost("GET", endpoint, asset, params=params)
        )
        if not isinstance(payload, dict) or not payload.get("posts"):
            return results

        order = payload.get("order", [])
        page_post_ids = [post_id for post_id in order if post_id not in seen_post_ids]
        if not page_post_ids:
            raise ActionFailure("Mattermost post pagination stopped making progress")

        posts = payload["posts"]
        for post_id in page_post_ids:
            if post_id not in posts:
                raise ActionFailure(
                    f"Mattermost response did not contain post {post_id}"
                )
            seen_post_ids.add(post_id)
            results.append(posts[post_id])
            if len(results) >= MATTERMOST_MAX_POSTS:
                break

        if params.get("since"):
            return results
        page += 1

    raise ActionFailure("Mattermost post pagination exceeded the safety limit")


def _process_posts(
    endpoint: str,
    asset: Asset,
    start_time: int | None,
    end_time: int | None,
) -> list[dict[str, Any]]:
    """Fetch posts for the requested time range."""
    if not end_time:
        return _get_posts(
            endpoint, asset, {"since": start_time} if start_time else None
        )

    if not start_time:
        posts = _get_posts(endpoint, asset, {"since": end_time})
        if not posts:
            return []
        return _get_posts(endpoint, asset, {"before": posts[-1]["id"]})

    posts = _get_posts(endpoint, asset, {"since": start_time})
    result = []
    for post in reversed(posts):
        if post["create_at"] <= end_time:
            result.append(post)
        else:
            break
    return result


__all__ = [
    "_check_response",
    "_create_post",
    "_get_posts",
    "_list_all_channels",
    "_list_all_teams",
    "_paginate_all",
    "_process_posts",
    "_resolve_channel_id",
    "_resolve_team_id",
    "_stringify_legacy_fields",
    "_validate_and_convert_time",
]
