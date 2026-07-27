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
# Ported from legacy _handle_send_message (mattermost_connector.py): resolve
# team+channel to IDs, then POST the message via _create_post.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset
from ..consts import MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG
from ._helpers import _create_post, _resolve_channel_id, _resolve_team_id


class SendMessageParams(Params):
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
    message: str = Param(description="Message to send")


class SendMessageOutput(ActionOutput):
    channel_id: str = OutputField(
        cef_types=["mattermost channel"], example_values=["9fm7epgq9b8x3ekb3frhid5kaw"]
    )
    create_at: float = OutputField(example_values=[1535458197064])
    delete_at: float = OutputField(example_values=[0])
    edit_at: float = OutputField(example_values=[1535458199241])
    hashtags: str
    id: str = OutputField(example_values=["g9rit1zsx3ngzbs1srtx8tu5fe"])
    is_pinned: bool
    message: str = OutputField(example_values=["Hey, guys how r u?"])
    original_id: str = OutputField(example_values=["uinosfs9a3r9dgay15epdn39qy"])
    parent_id: str = OutputField(example_values=["g9rit1zsx3ngzbs1srtx8tu5fe"])
    pending_post_id: str = OutputField(example_values=["uinosfs9a3r9dgay15epdn39qy"])
    root_id: str = OutputField(example_values=["g9rit1zsx3ngzbs1srtx8tu5fe"])
    type: str
    update_at: float = OutputField(example_values=[1535458197064])
    user_id: str = OutputField(example_values=["hrfxwdb7gtdjzbzqscix7edyeh"])
    reply_count: float = OutputField(example_values=[0])
    last_reply_at: float = OutputField(example_values=[0])
    participants: str


def send_message(
    params: SendMessageParams, soar: SOARClient, asset: Asset
) -> SendMessageOutput:
    if not asset.personal_token and not (asset.client_id and asset.client_secret):
        raise ActionFailure(MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG)

    team_id = _resolve_team_id(params.team, asset)
    channel_id = _resolve_channel_id(team_id, params.channel, asset)

    response = _create_post(
        {"channel_id": channel_id, "message": params.message}, asset
    )
    return SendMessageOutput(**response)
