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
# Ported from legacy _handle_list_channels (mattermost_connector.py):
# resolve team, then list every public/private channel of that team.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset
from ..consts import MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG
from ._helpers import _list_all_channels, _resolve_team_id


class ListChannelsParams(Params):
    team: str = Param(
        description="ID or name of the team",
        primary=True,
        cef_types=["mattermost team"],
    )


class ListChannelsOutput(ActionOutput):
    create_at: float = OutputField(example_values=[1535370158299])
    creator_id: str
    delete_at: float = OutputField(example_values=[0])
    display_name: str = OutputField(example_values=["Off-Topic"])
    extra_update_at: float = OutputField(example_values=[0])
    header: str
    id: str = OutputField(
        cef_types=["mattermost channel"], example_values=["bm5dwbhditgxxxd5z4qkawgxha"]
    )
    last_post_at: float = OutputField(example_values=[1535370232524])
    name: str = OutputField(
        cef_types=["mattermost channel"], example_values=["off-topic"]
    )
    props: str
    purpose: str
    scheme_id: str
    team_id: str = OutputField(
        cef_types=["mattermost team"], example_values=["suico8q897yyiraqdekxspfjma"]
    )
    total_msg_count: float = OutputField(example_values=[0])
    type: str = OutputField(example_values=["O"])
    update_at: float = OutputField(example_values=[1535370158299])
    total_msg_count_root: float = OutputField(example_values=[0])
    team_name: str = OutputField(example_values=["test-005"])
    team_update_at: float = OutputField(example_values=[1637228653671])
    team_display_name: str = OutputField(example_values=["test-005"])
    shared: str
    policy_id: str
    group_constrained: str


class ListChannelsSummary(ActionOutput):
    total_channels: int = OutputField(example_values=[10])


def list_channels(
    params: ListChannelsParams, soar: SOARClient, asset: Asset
) -> list[ListChannelsOutput]:
    if not asset.personal_token and not (asset.client_id and asset.client_secret):
        raise ActionFailure(MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG)

    team_id = _resolve_team_id(params.team, asset)
    channels = _list_all_channels(team_id, asset)
    output = [ListChannelsOutput(**channel) for channel in channels]
    soar.set_summary(ListChannelsSummary(total_channels=len(output)))
    return output
