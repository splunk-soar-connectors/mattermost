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
from soar_sdk.action_results import OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import MATTERMOST_SEND_MSG_SUCCESS
from ._helpers import (
    LegacyCompatibleOutput,
    _create_post,
    _resolve_channel_id,
    _resolve_team_id,
    _stringify_legacy_fields,
)


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


class SendMessageOutput(LegacyCompatibleOutput):
    """Mattermost post created by the send message action."""

    id: str | None = OutputField(column_name="Message ID")
    message: str | None = OutputField(column_name="Message")
    user_id: str | None = OutputField(column_name="User ID")
    channel_id: str | None = OutputField(
        column_name="Channel ID", cef_types=["mattermost channel"]
    )
    create_at: float | None = OutputField(column_name="Created At")
    update_at: float | None = OutputField(column_name="Updated At")
    delete_at: float | None = None
    edit_at: float | None = None
    hashtags: str | None = None
    is_pinned: bool | None = None
    original_id: str | None = None
    parent_id: str | None = None
    pending_post_id: str | None = None
    root_id: str | None = None
    type: str | None = None
    reply_count: float | None = OutputField(example_values=[0])
    last_reply_at: float | None = OutputField(example_values=[0])
    participants: list[str] | None = None


def send_message(
    params: SendMessageParams, soar: SOARClient, asset: Asset
) -> SendMessageOutput:
    """Send a message to a Mattermost channel."""
    team_id = _resolve_team_id(params.team, asset)
    channel_id = _resolve_channel_id(team_id, params.channel, asset)
    output = SendMessageOutput(
        **_stringify_legacy_fields(
            _create_post({"channel_id": channel_id, "message": params.message}, asset),
            {
                "channel_id",
                "hashtags",
                "id",
                "message",
                "original_id",
                "parent_id",
                "pending_post_id",
                "root_id",
                "type",
                "user_id",
                "participants",
            },
        )
    )
    soar.set_message(MATTERMOST_SEND_MSG_SUCCESS)
    return output
