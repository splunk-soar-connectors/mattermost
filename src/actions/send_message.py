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
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import MATTERMOST_SEND_MSG_SUCCESS
from ._helpers import _create_post, _resolve_channel_id, _resolve_team_id
from .list_users import UserOutput


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


class SendMessageOutput(PermissiveActionOutput):
    """Mattermost post created by the send message action."""

    id: str | None = OutputField(
        column_name="Message ID", example_values=["g9rit1zsx3ngzbs1srtx8tu5fe"]
    )
    message: str | None = OutputField(
        column_name="Message", example_values=["Hey, guys how r u?"]
    )
    user_id: str | None = OutputField(
        column_name="User ID", example_values=["hrfxwdb7gtdjzbzqscix7edyeh"]
    )
    channel_id: str | None = OutputField(
        column_name="Channel ID",
        cef_types=["mattermost channel"],
        example_values=["9fm7epgq9b8x3ekb3frhid5kaw"],
    )
    create_at: float | None = OutputField(
        column_name="Created At", example_values=[1535458197064]
    )
    update_at: float | None = OutputField(
        column_name="Updated At", example_values=[1535458197064]
    )
    delete_at: float | None = OutputField(example_values=[0])
    edit_at: float | None = OutputField(example_values=[1535458199241])
    hashtags: str | None = None
    is_pinned: bool | None = None
    original_id: str | None = OutputField(example_values=["uinosfs9a3r9dgay15epdn39qy"])
    parent_id: str | None = OutputField(example_values=["g9rit1zsx3ngzbs1srtx8tu5fe"])
    pending_post_id: str | None = OutputField(
        example_values=["uinosfs9a3r9dgay15epdn39qy"]
    )
    root_id: str | None = OutputField(example_values=["g9rit1zsx3ngzbs1srtx8tu5fe"])
    type: str | None = None
    reply_count: float | None = OutputField(example_values=[0])
    last_reply_at: float | None = OutputField(example_values=[0])
    participants: list[UserOutput] | None = None


def send_message(
    params: SendMessageParams, soar: SOARClient, asset: Asset
) -> SendMessageOutput:
    """Send a message to a Mattermost channel."""
    team_id = _resolve_team_id(params.team, asset)
    channel_id = _resolve_channel_id(team_id, params.channel, asset)
    output = SendMessageOutput(
        **_create_post({"channel_id": channel_id, "message": params.message}, asset)
    )
    soar.set_message(MATTERMOST_SEND_MSG_SUCCESS)
    return output
