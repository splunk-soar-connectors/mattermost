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
from soar_sdk.params import Param, Params

from ..asset import Asset
from ._helpers import _create_post, _resolve_channel_id, _resolve_team_id


class SendMessageParams(Params):
    """Parameters for sending a Mattermost message."""

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
    message: str = Param(required=True, description="Message to send")


class SendMessageOutput(ActionOutput):
    """Mattermost post created by the send message action."""

    channel_id: str | None = OutputField(cef_types=["mattermost channel"])
    create_at: float | None = None
    delete_at: float | None = None
    edit_at: float | None = None
    hashtags: str | None = None
    id: str | None = None
    is_pinned: bool | None = None
    message: str | None = None
    original_id: str | None = None
    parent_id: str | None = None
    pending_post_id: str | None = None
    root_id: str | None = None
    type: str | None = None
    update_at: float | None = None
    user_id: str | None = None
    reply_count: float | None = None
    last_reply_at: float | None = None


def send_message(
    params: SendMessageParams, soar: SOARClient, asset: Asset
) -> SendMessageOutput:
    """Send a message to a Mattermost channel."""
    team_id = _resolve_team_id(params.team, asset)
    channel_id = _resolve_channel_id(team_id, params.channel, asset)
    return SendMessageOutput(
        **_create_post({"channel_id": channel_id, "message": params.message}, asset)
    )
