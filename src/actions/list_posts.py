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


from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import MATTERMOST_INVALID_TIME_RANGE, MATTERMOST_LIST_POSTS_ENDPOINT
from ._helpers import (
    _process_posts,
    _resolve_channel_id,
    _resolve_team_id,
    _stringify_legacy_fields,
    _validate_and_convert_time,
)


class ListPostsParams(Params):
    """Parameters for listing posts from a Mattermost channel."""

    team: str = Param(
        required=True,
        description="ID or name of the team",
        primary=True,
        cef_types=["mattermost team"],
    )
    channel: str = Param(
        required=True,
        description="ID or name of the channel",
        primary=True,
        cef_types=["mattermost channel"],
    )
    start_time: str | None = Param(
        required=False, description="Start time in formatted timestamp"
    )
    end_time: str | None = Param(
        required=False, description="End time in formatted timestamp"
    )


class PropsOutput(ActionOutput):
    """Post properties returned by Mattermost."""

    addedUsername: str | None = OutputField(cef_types=["user name"])
    username: str | None = OutputField(cef_types=["user name"])


class FilesOutput(ActionOutput):
    """File metadata embedded in a Mattermost post."""

    id: str | None = None
    name: str | None = None
    size: float | None = None
    width: float | None = None
    height: float | None = None
    post_id: str | None = None
    user_id: str | None = None
    create_at: float | None = None
    delete_at: float | None = None
    extension: str | None = None
    mime_type: str | None = None
    update_at: float | None = None
    channel_id: str | None = None
    mini_preview: str | None = None
    has_preview_image: bool | None = None
    remote_id: str | None = None


class MetadataOutput(ActionOutput):
    """Metadata attached to a Mattermost post."""

    files: list[FilesOutput] | None = None


class ListPostsOutput(ActionOutput):
    """A Mattermost post."""

    channel_id: str | None = OutputField(cef_types=["mattermost channel"])
    create_at: float | None = None
    delete_at: float | None = None
    edit_at: float | None = None
    file_ids: str | None = None
    hashtags: str | None = None
    id: str | None = None
    is_pinned: bool | None = None
    message: str | None = None
    original_id: str | None = None
    parent_id: str | None = None
    pending_post_id: str | None = None
    props: PropsOutput | None = None
    root_id: str | None = None
    type: str | None = None
    update_at: float | None = None
    user_id: str | None = None
    reply_count: float | None = None
    last_reply_at: float | None = None
    metadata: MetadataOutput | None = None
    participants: str | None = None


class ListPostsSummary(ActionOutput):
    """Summary for the list posts action."""

    total_posts: int


def list_posts(
    params: ListPostsParams, soar: SOARClient, asset: Asset
) -> list[ListPostsOutput]:
    """List posts from a channel, optionally constrained by timestamps."""
    start_time = (
        _validate_and_convert_time(params.start_time) if params.start_time else None
    )
    end_time = _validate_and_convert_time(params.end_time) if params.end_time else None
    if start_time is not None and end_time is not None and start_time >= end_time:
        raise ActionFailure(MATTERMOST_INVALID_TIME_RANGE)

    team_id = _resolve_team_id(params.team, asset)
    channel_id = _resolve_channel_id(team_id, params.channel, asset)
    endpoint = MATTERMOST_LIST_POSTS_ENDPOINT.format(channel=channel_id)
    posts = _process_posts(endpoint, asset, start_time, end_time)
    output = [
        ListPostsOutput(
            **_stringify_legacy_fields(post, {"file_ids", "participants"})
        )
        for post in posts
    ]
    soar.set_summary(ListPostsSummary(total_posts=len(output)))
    return output
