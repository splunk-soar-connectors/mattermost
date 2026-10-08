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
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import MATTERMOST_USERS_ENDPOINT
from ._helpers import (
    LegacyCompatibleOutput,
    _legacy_string_fields,
    _paginate_all,
    _resolve_team_id,
)


def _normalize_user_output(user: dict[str, Any]) -> dict[str, Any]:
    """Copy user output without changing the API response value types."""
    output = dict(user)
    timezone = output.get("timezone")
    if isinstance(timezone, dict):
        output["timezone"] = dict(timezone)
    return output


class ListUsersParams(Params):
    """Parameters for listing Mattermost users."""

    team: str | None = Param(
        required=False,
        default=None,
        description="ID or name of the team",
        primary=True,
        cef_types=["mattermost team"],
        column_name="Team",
    )


class TimezoneOutput(LegacyCompatibleOutput):
    """Mattermost user timezone settings."""

    automaticTimezone: str | None = None
    manualTimezone: str | None = None
    useAutomaticTimezone: bool | None = OutputField(example_values=[True, False])


class ListUsersOutput(LegacyCompatibleOutput):
    """A Mattermost user returned by the API."""

    @classmethod
    def _to_json_schema(
        cls, parent_datapath="action_result.data.*", column_order_counter=None
    ):
        """Keep legacy string datapaths for raw Mattermost property objects."""
        yield from super()._to_json_schema(parent_datapath, column_order_counter)
        yield from _legacy_string_fields(parent_datapath, ("notify_props", "props"))

    id: str | None = OutputField(
        column_name="User ID",
        example_values=["pyx8sqe7zfn1dpmtd1s3qzqhfr"],
    )
    username: str | None = OutputField(
        column_name="User Name",
        cef_types=["user name"],
        example_values=["test.user"],
    )
    email: str | None = OutputField(
        column_name="Email",
        cef_types=["email"],
        example_values=["test.user@mattermost.com"],
    )
    first_name: str | None = OutputField(
        column_name="First Name", example_values=["test"]
    )
    last_name: str | None = OutputField(
        column_name="Last Name", example_values=["user"]
    )
    roles: str | None = OutputField(
        column_name="Roles",
        example_values=["system_user system_user_access_token system_post_all"],
    )
    auth_data: str | None = None
    auth_service: str | None = None
    create_at: float | None = OutputField(example_values=[1535004134292])
    delete_at: float | None = OutputField(example_values=[0])
    email_verified: bool | None = None
    failed_attempts: float | None = OutputField(example_values=[0])
    last_password_update: float | None = OutputField(example_values=[0])
    last_picture_update: float | None = OutputField(example_values=[0])
    locale: str | None = OutputField(example_values=["en"])
    mfa_active: bool | None = None
    nickname: str | None = OutputField(example_values=["test"])
    notify_props: LegacyCompatibleOutput | None = None
    position: str | None = None
    props: LegacyCompatibleOutput | None = None
    timezone: TimezoneOutput | None = None
    update_at: float | None = OutputField(example_values=[1535105717458])
    disable_welcome_email: bool | None = OutputField(example_values=[False])


class ListUsersSummary(ActionOutput):
    """Summary for the list users action."""

    total_users: int


def list_users(
    params: ListUsersParams, soar: SOARClient, asset: Asset
) -> list[ListUsersOutput]:
    """List users, optionally restricted to one Mattermost team."""
    extra_params = {}
    if params.team:
        extra_params["in_team"] = _resolve_team_id(params.team, asset)
    users = _paginate_all(MATTERMOST_USERS_ENDPOINT, asset, extra_params)
    output = [ListUsersOutput(**_normalize_user_output(user)) for user in users]
    soar.set_message(f"Total users: {len(output)}")
    soar.set_summary(ListUsersSummary(total_users=len(output)))
    return output
