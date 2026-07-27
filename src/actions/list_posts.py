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
# Ported from legacy _handle_list_posts (mattermost_connector.py): validate
# and convert start_time/end_time, resolve team+channel, then fetch posts for
# the resulting time window via _process_posts.
# Note: original app.py had two classes both named `FilesOutput`/`MetadataOutput`
# (one for upload_file, one for list_posts) — module-scoping them here (as
# upload_file.FilesOutput vs list_posts.FilesOutput) resolves that collision
# for free without renaming anything the SDK schema depends on.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset
from ..consts import (
    MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG,
    MATTERMOST_INVALID_TIME_RANGE,
    MATTERMOST_LIST_POSTS_ENDPOINT,
)
from ._helpers import (
    _process_posts,
    _resolve_channel_id,
    _resolve_team_id,
    _validate_and_convert_time,
)


class ListPostsParams(Params):
    team: str = Param(
        description="ID or name of the team",
        primary=True,
        cef_types=["mattermost team"],
    )
    channel: str = Param(
        description="ID or name of the channel",
        primary=True,
        cef_types=["mattermost channel"],
    )
    start_time: str | None = Param(description="Start time in formatted timestamp")
    end_time: str | None = Param(description="End time in formatted timestamp")


class PropsOutput(ActionOutput):
    addedUsername: str = OutputField(
        cef_types=["user name"], example_values=["test-name"]
    )
    username: str = OutputField(cef_types=["user name"], example_values=["admin"])


class FilesOutput(ActionOutput):
    id: str = OutputField(example_values=["1nrp7izie7gdz81mwb99azed4w"])
    name: str = OutputField(example_values=["test.png"])
    size: float = OutputField(example_values=[211962])
    width: float = OutputField(example_values=[2230])
    height: float = OutputField(example_values=[1220])
    post_id: str = OutputField(example_values=["zn6cs7a4b7y6bmxy4yk4j1dz3y"])
    user_id: str = OutputField(example_values=["8bfk4fj8gpyofq7qx85tsz97rh"])
    create_at: float = OutputField(example_values=[1637228792269])
    delete_at: float = OutputField(example_values=[0])
    extension: str = OutputField(example_values=["png"])
    mime_type: str = OutputField(example_values=["image/png"])
    update_at: float = OutputField(example_values=[1637228792269])
    channel_id: str = OutputField(example_values=["aopx3i38utrfxqyg86tq9xx3wy"])
    mini_preview: str = OutputField(
        example_values=[
            "/9j/2wCEAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRQBAwQEBQQFCQUFCRQNCw0UFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFP/AABEIABAAEAMBIgACEQEDEQH/xAGiAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgsQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+gEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoLEQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T19vf4+fr/2gAMAwEAAhEDEQA/APgKe+e6YM7DhMDCA+2Kg8krAJs4GcD5hnI68V1NjfQxWlmiMI5UhRi2DkH1B+uKi1O6ie1uQZd0jITyDkk89fxrqsc1z//Z"  # pragma: allowlist secret
        ]
    )
    has_preview_image: bool = OutputField(example_values=[True])
    remote_id: str


class MetadataOutput(ActionOutput):
    files: list[FilesOutput]


class ListPostsOutput(ActionOutput):
    channel_id: str = OutputField(
        cef_types=["mattermost channel"], example_values=["ectpw8kdeir4589wu61ijp77tc"]
    )
    create_at: float = OutputField(example_values=[1541079654322])
    delete_at: float = OutputField(example_values=[0])
    edit_at: float = OutputField(example_values=[1535007704567])
    file_ids: str = OutputField(example_values=["e4yq14jxd3ra5pmcsjeqjw3j7o"])
    hashtags: str
    id: str = OutputField(example_values=["rb19t6ggfj81bk1txxtcw13kir"])
    is_pinned: bool
    message: str = OutputField(example_values=["Test"])
    original_id: str = OutputField(example_values=["uinosfs9a3r9dgay15epdn39qy"])
    parent_id: str = OutputField(example_values=["fsn1bn4nwjdwpmbuqch5fp9xnh"])
    pending_post_id: str = OutputField(example_values=["g9rit1zsx3ngzbs1srtx8tu5fe"])
    props: PropsOutput
    root_id: str = OutputField(example_values=["fsn1bn4nwjdwpmbuqch5fp9xnh"])
    type: str = OutputField(example_values=["system_join_channel"])
    update_at: float = OutputField(example_values=[1541079654322])
    user_id: str = OutputField(example_values=["zxutg6e6ibgyxjmpee7wjsmc5a"])
    reply_count: float = OutputField(example_values=[0])
    last_reply_at: float = OutputField(example_values=[0])
    metadata: MetadataOutput
    participants: str


class ListPostsSummary(ActionOutput):
    total_posts: int = OutputField(example_values=[10])


def list_posts(
    params: ListPostsParams, soar: SOARClient, asset: Asset
) -> list[ListPostsOutput]:
    if not asset.personal_token and not (asset.client_id and asset.client_secret):
        raise ActionFailure(MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG)

    start_time = (
        _validate_and_convert_time(params.start_time) if params.start_time else None
    )
    end_time = _validate_and_convert_time(params.end_time) if params.end_time else None
    if start_time is not None and end_time is not None and start_time >= end_time:
        raise ActionFailure(MATTERMOST_INVALID_TIME_RANGE)

    team_id = _resolve_team_id(params.team, asset)
    channel_id = _resolve_channel_id(team_id, params.channel, asset)

    posts = _process_posts(
        MATTERMOST_LIST_POSTS_ENDPOINT.format(channel=channel_id),
        asset,
        start_time,
        end_time,
    )
    output = [ListPostsOutput(**post) for post in posts]
    soar.set_summary(ListPostsSummary(total_posts=len(output)))
    return output
