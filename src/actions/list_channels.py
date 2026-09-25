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
from ._helpers import (
    _list_all_channels,
    _resolve_team_id,
    _stringify_legacy_fields,
)


class ListChannelsParams(Params):
    """Parameters for listing a team's channels."""

    team: str = Param(
        required=True,
        description="ID or name of the team",
        primary=True,
        cef_types=["mattermost team"],
    )


class ListChannelsOutput(ActionOutput):
    """A Mattermost public or private channel."""

    create_at: float | None = OutputField(example_values=[1535370158299])
    creator_id: str | None = None
    delete_at: float | None = OutputField(example_values=[0])
    display_name: str | None = OutputField(example_values=["Off-Topic"])
    extra_update_at: float | None = OutputField(example_values=[0])
    header: str | None = None
    id: str | None = OutputField(
        cef_types=["mattermost channel"],
        example_values=["bm5dwbhditgxxxd5z4qkawgxha"],
    )
    last_post_at: float | None = OutputField(example_values=[1535370232524])
    name: str | None = OutputField(
        cef_types=["mattermost channel"],
        example_values=["off-topic"],
    )
    props: str | None = None
    purpose: str | None = None
    scheme_id: str | None = None
    team_id: str | None = OutputField(
        cef_types=["mattermost team"],
        example_values=["suico8q897yyiraqdekxspfjma"],
    )
    total_msg_count: float | None = OutputField(example_values=[0])
    type: str | None = OutputField(example_values=["O"])
    update_at: float | None = OutputField(example_values=[1535370158299])
    total_msg_count_root: float | None = OutputField(example_values=[0])
    team_name: str | None = OutputField(example_values=["test-005"])
    team_update_at: float | None = OutputField(example_values=[1637228653671])
    team_display_name: str | None = OutputField(example_values=["test-005"])
    shared: str | None = None
    policy_id: str | None = None
    group_constrained: str | None = None


class ListChannelsSummary(ActionOutput):
    """Summary for the list channels action."""

    total_channels: int


def list_channels(
    params: ListChannelsParams, soar: SOARClient, asset: Asset
) -> list[ListChannelsOutput]:
    """List public and private channels for a Mattermost team."""
    team_id = _resolve_team_id(params.team, asset)
    channels = _list_all_channels(team_id, asset)
    output = [
        ListChannelsOutput(
            **_stringify_legacy_fields(
                channel, {"props", "shared", "policy_id", "group_constrained"}
            )
        )
        for channel in channels
    ]
    soar.set_summary(ListChannelsSummary(total_channels=len(output)))
    return output
