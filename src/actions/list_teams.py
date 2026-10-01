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


from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Params

from ..asset import Asset
from ._helpers import (
    LegacyCompatibleOutput,
    _list_all_teams,
    _stringify_legacy_fields,
)


class ListTeamsOutput(LegacyCompatibleOutput):
    """A Mattermost team returned by the API."""

    id: str | None = OutputField(
        column_name="Team ID",
        cef_types=["mattermost team"],
        example_values=["396afxwqzbgruxdkft7d8wo5qw"],
    )
    name: str | None = OutputField(
        column_name="Team Name",
        cef_types=["mattermost team"],
        example_values=["test2-sample"],
    )
    display_name: str | None = OutputField(
        column_name="Display Name", example_values=["test2 sample"]
    )
    email: str | None = OutputField(
        column_name="Email",
        cef_types=["email"],
        example_values=["sampleteam@mattermost.com"],
    )
    type: str | None = OutputField(column_name="Type", example_values=["O"])
    invite_id: str | None = OutputField(
        column_name="Invite ID", example_values=["xo3gnntbfbg5bnirx7i1uqujc"]
    )
    allow_open_invite: bool | None = OutputField(column_name="Allow Open Invite")
    allowed_domains: str | None = OutputField(
        cef_types=["domain"], example_values=["example.com"]
    )
    company_name: str | None = None
    create_at: float | None = OutputField(example_values=[1534856540543])
    delete_at: float | None = OutputField(example_values=[0])
    description: str | None = None
    scheme_id: str | None = None
    update_at: float | None = OutputField(example_values=[1534918716675])
    policy_id: str | None = None
    group_constrained: bool | None = None


class ListTeamsSummary(ActionOutput):
    """Summary for the list teams action."""

    total_teams: int


def _normalize_team_output(team: dict[str, Any]) -> dict[str, Any]:
    """Normalize all legacy string fields without dropping API fields."""
    return _stringify_legacy_fields(
        team,
        {
            "allowed_domains",
            "company_name",
            "description",
            "display_name",
            "email",
            "id",
            "invite_id",
            "name",
            "scheme_id",
            "type",
            "policy_id",
            "group_constrained",
        },
    )


def list_teams(params: Params, soar: SOARClient, asset: Asset) -> list[ListTeamsOutput]:
    """List all Mattermost teams visible to the current user."""
    teams = _list_all_teams(asset)
    output = [ListTeamsOutput(**_normalize_team_output(team)) for team in teams]
    soar.set_summary(ListTeamsSummary(total_teams=len(output)))
    return output
