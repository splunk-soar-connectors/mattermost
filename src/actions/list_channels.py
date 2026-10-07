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
    LegacyCompatibleOutput,
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
        column_name="Team",
    )


class ListChannelsOutput(LegacyCompatibleOutput):
    """A Mattermost public or private channel."""

    @classmethod
    def _to_json_schema(
        cls, parent_datapath="action_result.data.*", column_order_counter=None
    ):
        """Keep the legacy string contract for the unstructured props field."""
        yield from super()._to_json_schema(parent_datapath, column_order_counter)
        yield {
            "data_path": f"{parent_datapath}.props",
            "data_type": "string",
        }

    id: str | None = OutputField(
        column_name="Channel ID",
        cef_types=["mattermost channel"],
        example_values=["bm5dwbhditgxxxd5z4qkawgxha"],
    )
    name: str | None = OutputField(
        column_name="Channel Name",
        cef_types=["mattermost channel"],
        example_values=["off-topic"],
    )
    display_name: str | None = OutputField(
        column_name="Display Name", example_values=["Off-Topic"]
    )
    type: str | None = OutputField(column_name="Type", example_values=["O"])
    total_msg_count: float | None = OutputField(
        column_name="Total Message Count", example_values=[0]
    )
    create_at: float | None = OutputField(example_values=[1535370158299])
    creator_id: str | None = None
    delete_at: float | None = OutputField(example_values=[0])
    extra_update_at: float | None = OutputField(example_values=[0])
    header: str | None = None
    last_post_at: float | None = OutputField(example_values=[1535370232524])
    props: LegacyCompatibleOutput | None = None
    purpose: str | None = None
    scheme_id: str | None = None
    team_id: str | None = OutputField(
        cef_types=["mattermost team"],
        example_values=["suico8q897yyiraqdekxspfjma"],
    )
    update_at: float | None = OutputField(example_values=[1535370158299])
    total_msg_count_root: float | None = OutputField(example_values=[0])
    team_name: str | None = OutputField(example_values=["test-005"])
    team_update_at: float | None = OutputField(example_values=[1637228653671])
    team_display_name: str | None = OutputField(example_values=["test-005"])
    shared: bool | None = None
    policy_id: str | None = None
    group_constrained: bool | None = None


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
                channel,
                {
                    "creator_id",
                    "display_name",
                    "header",
                    "id",
                    "name",
                    "props",
                    "purpose",
                    "scheme_id",
                    "team_id",
                    "type",
                    "team_name",
                    "team_display_name",
                    "shared",
                    "policy_id",
                    "group_constrained",
                },
            )
        )
        for channel in channels
    ]
    soar.set_message(f"Total channels: {len(output)}")
    soar.set_summary(ListChannelsSummary(total_channels=len(output)))
    return output
