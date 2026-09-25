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
from soar_sdk.params import Params

from ..asset import Asset
from ._helpers import _list_all_teams, _stringify_legacy_fields


class ListTeamsOutput(ActionOutput):
    """A Mattermost team returned by the API."""

    allow_open_invite: bool | None = None
    allowed_domains: str | None = OutputField(example_values=["example.com"])
    company_name: str | None = None
    create_at: float | None = OutputField(example_values=[1534856540543])
    delete_at: float | None = OutputField(example_values=[0])
    description: str | None = None
    display_name: str | None = OutputField(example_values=["test2 sample"])
    email: str | None = OutputField(example_values=["sampleteam@mattermost.com"])
    id: str | None = OutputField(
        cef_types=["mattermost team"],
        example_values=["396afxwqzbgruxdkft7d8wo5qw"],
    )
    invite_id: str | None = OutputField(example_values=["xo3gnntbfbg5bnirx7i1uqujc"])
    name: str | None = OutputField(
        cef_types=["mattermost team"],
        example_values=["test2-sample"],
    )
    scheme_id: str | None = None
    type: str | None = OutputField(example_values=["O"])
    update_at: float | None = OutputField(example_values=[1534918716675])
    policy_id: str | None = None
    group_constrained: str | None = None


class ListTeamsSummary(ActionOutput):
    """Summary for the list teams action."""

    total_teams: int


def list_teams(params: Params, soar: SOARClient, asset: Asset) -> list[ListTeamsOutput]:
    """List all Mattermost teams visible to the current user."""
    teams = _list_all_teams(asset)
    output = [
        ListTeamsOutput(**_stringify_legacy_fields(team, {"group_constrained"}))
        for team in teams
    ]
    soar.set_summary(ListTeamsSummary(total_teams=len(output)))
    return output
