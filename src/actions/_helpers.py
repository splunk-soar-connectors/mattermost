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
# Shared helpers for Mattermost actions. Mirrors legacy's shared pagination
# (`page`-param while-loop used by _handle_list_users / _verify_team / etc.)
# and team-resolution (_verify_team) logic used by more than one action.

from __future__ import annotations

import re
from datetime import datetime, UTC
from typing import TYPE_CHECKING, Any

from soar_sdk.exceptions import ActionFailure

from ..client import call_mattermost
from ..consts import (
    MATTERMOST_CHANNEL_NOT_FOUND_MSG,
    MATTERMOST_LIST_CHANNELS_ENDPOINT,
    MATTERMOST_NEGATIVE_TIME,
    MATTERMOST_SEND_MSG_ENDPOINT,
    MATTERMOST_TEAMS_ENDPOINT,
    MATTERMOST_TEAM_NOT_FOUND_MSG,
    MATTERMOST_TIMESTAMP_CONVERSION_FAILED_MSG,
    MATTERMOST_TIMESTAMP_VALIDATION_FAILED_MSG,
)

_ISO8601_RE = re.compile(
    r"^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T"
    r"(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?"
    r"(Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])?$"
)

if TYPE_CHECKING:
    from ..app import Asset


def _check_response(response) -> None:
    """Raise ActionFailure for any non-2xx Mattermost API response."""
    if not response.is_success:
        raise ActionFailure(
            f"Mattermost API error {response.status_code}: {response.text}"
        )


def _paginate_all(
    endpoint: str,
    asset: Asset,
    extra_params: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Exhaust all pages of a Mattermost list endpoint and return every item.

    Mirrors legacy's page-number while-loop (increment `page`, stop on an
    empty page) used by _handle_list_users / _verify_team.
    """
    page, results = 0, []
    while True:
        query = {"page": page, **(extra_params or {})}
        response = call_mattermost("GET", endpoint, asset, params=query)
        _check_response(response)
        page_items = response.json()
        if not page_items:
            break
        results.extend(page_items)
        page += 1
    return results


def _resolve_team_id(team: str, asset: Asset) -> str:
    """Return a team ID from either a numeric/opaque team ID or a team name.

    Mirrors legacy _verify_team's non-list_teams branch: paginate GET /teams
    and match either id or name (case-insensitive). Raises ActionFailure with
    MATTERMOST_TEAM_NOT_FOUND_MSG when no page yields a match.
    """
    teams = _paginate_all(MATTERMOST_TEAMS_ENDPOINT, asset)
    for each_team in teams:
        if team.lower() in (
            each_team.get("id", "").lower(),
            each_team.get("name", "").lower(),
        ):
            return each_team["id"]

    raise ActionFailure(MATTERMOST_TEAM_NOT_FOUND_MSG)


def _list_all_teams(asset: Asset) -> list[dict[str, Any]]:
    """Return every team, mirroring legacy _verify_team's list_teams branch.

    Legacy paginates /teams and de-duplicates entries that reappear across
    page boundaries: it diffs each page against the previous page, only
    appends genuinely-new entries, and skips forward by `1 + duplicate_entry`
    pages to avoid re-fetching a page whose items were already consumed.
    Page 0 is always appended in full since there is no previous page yet.
    """
    teams: list[dict[str, Any]] = []
    page = 0
    duplicate_entry = 0
    previous_teams: list[dict[str, Any]] = []
    while True:
        response = call_mattermost(
            "GET", MATTERMOST_TEAMS_ENDPOINT, asset, params={"page": page}
        )
        _check_response(response)
        page_teams = response.json()
        if not page_teams:
            break

        new_teams: list[dict[str, Any]] = []
        if previous_teams:
            duplicate_entry = len([t for t in page_teams if t in previous_teams])
            new_teams = [t for t in page_teams if t not in previous_teams]
        previous_teams = page_teams

        if not new_teams and page == 0:
            teams.extend(page_teams)
        else:
            teams.extend(new_teams)

        page += 1 + duplicate_entry
    return teams


def _resolve_channel_id(team_id: str, channel: str, asset: Asset) -> str:
    """Return a channel ID from either a channel ID or a channel name.

    Mirrors legacy _verify_channel's non-list_channels branch: fetch the
    team's channels (a single, non-paginated GET) and match either id or
    name (case-insensitive).
    """
    response = call_mattermost(
        "GET", MATTERMOST_LIST_CHANNELS_ENDPOINT.format(team=team_id), asset
    )
    _check_response(response)
    for each_channel in response.json():
        if channel.lower() in (
            each_channel.get("id", "").lower(),
            each_channel.get("name", "").lower(),
        ):
            return each_channel["id"]

    raise ActionFailure(MATTERMOST_CHANNEL_NOT_FOUND_MSG)


def _list_all_channels(team_id: str, asset: Asset) -> list[dict[str, Any]]:
    """Return every public/private channel for a team.

    Mirrors legacy _verify_channel's list_channels branch: a single GET of
    the team's channels, filtered to types "O" (public) and "P" (private).
    """
    response = call_mattermost(
        "GET", MATTERMOST_LIST_CHANNELS_ENDPOINT.format(team=team_id), asset
    )
    _check_response(response)
    return [
        each_channel
        for each_channel in response.json()
        if each_channel.get("type", "").lower() in ("o", "p")
    ]


def _create_post(request_data: dict[str, Any], asset: Asset) -> dict[str, Any]:
    """POST a new post (message, optionally with file_ids) to a channel."""
    response = call_mattermost(
        "POST", MATTERMOST_SEND_MSG_ENDPOINT, asset, json=request_data
    )
    _check_response(response)
    return response.json()


def _validate_and_convert_time(time_stamp: str) -> int:
    """Validate a start_time/end_time string and convert it to epoch ms.

    Mirrors legacy's _validate_date + _convert_time + _verify_time chain:
    the string must be either a valid ISO 8601 timestamp or a "%Y-%m-%d"
    date; it's then converted to a millisecond epoch (naive input is
    treated as UTC, matching legacy's dateutil-based conversion), and the
    result must be a non-negative integer.
    """
    if _ISO8601_RE.match(time_stamp) is None:
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
    endpoint: str, asset: Asset, extra_params: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Paginated GET of a channel's posts.

    Mirrors legacy _get_posts: increments `page` and stops on an empty
    `posts` payload, UNLESS `since` is set in params, in which case it
    fetches exactly one page (legacy breaks immediately after the first
    request when `since` is present).
    """
    page, results = 0, []
    params = dict(extra_params or {})
    while True:
        params["page"] = page
        response = call_mattermost("GET", endpoint, asset, params=params)
        _check_response(response)
        payload = response.json()
        if not payload.get("posts"):
            break
        results.extend(payload["posts"][post_id] for post_id in payload["order"])
        if params.get("since"):
            break
        page += 1
    return results


def _process_posts(
    endpoint: str,
    asset: Asset,
    start_time: int | None,
    end_time: int | None,
) -> list[dict[str, Any]]:
    """Fetch a channel's posts for the given time window.

    Mirrors legacy _process_posts' three branches: no end_time (optionally
    filtered by since=start_time); end_time only (fetch since=end_time, then
    re-fetch with before=<last post id> to get everything strictly before
    end_time); both times (fetch since=start_time, then walk backwards and
    stop once a post's create_at exceeds end_time).
    """
    if not end_time:
        params = {"since": start_time} if start_time else {}
        return _get_posts(endpoint, asset, params)

    if not start_time:
        posts = _get_posts(endpoint, asset, {"since": end_time})
        if not posts:
            return []
        return _get_posts(endpoint, asset, {"before": posts[-1]["id"]})

    posts = _get_posts(endpoint, asset, {"since": start_time})
    result = []
    for each_post in reversed(posts):
        if each_post["create_at"] <= end_time:
            result.append(each_post)
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
    "_validate_and_convert_time",
]
