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
# Ported from legacy _handle_list_teams (mattermost_connector.py): list every
# team via the same paginated/dedup logic as _verify_team's list_teams branch.
# list_teams has no input params in the original manifest — it kept the bare
# `Params` base class rather than defining a subclass, so that is preserved
# here rather than inventing an empty ListTeamsParams subclass.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Params

from ..app import Asset
from ..consts import MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG
from ._helpers import _list_all_teams


class ListTeamsOutput(ActionOutput):
    allow_open_invite: bool
    allowed_domains: str = OutputField(
        cef_types=["domain"], example_values=["example.com"]
    )
    company_name: str
    create_at: float = OutputField(example_values=[1534856540543])
    delete_at: float = OutputField(example_values=[0])
    description: str
    display_name: str = OutputField(example_values=["test2 sample"])
    email: str = OutputField(
        cef_types=["email"], example_values=["sampleteam@mattermost.com"]
    )
    id: str = OutputField(
        cef_types=["mattermost team"], example_values=["396afxwqzbgruxdkft7d8wo5qw"]
    )
    invite_id: str = OutputField(example_values=["xo3gnntbfbg5bnirx7zi1uqujc"])
    name: str = OutputField(
        cef_types=["mattermost team"], example_values=["test2-sample"]
    )
    scheme_id: str
    type: str = OutputField(example_values=["O"])
    update_at: float = OutputField(example_values=[1534918716675])
    policy_id: str
    group_constrained: str


class ListTeamsSummary(ActionOutput):
    total_teams: int = OutputField(example_values=[10])


def list_teams(params: Params, soar: SOARClient, asset: Asset) -> list[ListTeamsOutput]:
    if not asset.personal_token and not (asset.client_id and asset.client_secret):
        raise ActionFailure(MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG)

    teams = _list_all_teams(asset)
    output = [ListTeamsOutput(**team) for team in teams]
    soar.set_summary(ListTeamsSummary(total_teams=len(output)))
    return output
