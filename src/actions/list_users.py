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
from ..consts import MATTERMOST_USERS_ENDPOINT
from ._helpers import _paginate_all, _resolve_team_id, _stringify_legacy_fields


class ListUsersParams(Params):
    """Parameters for listing Mattermost users."""

    team: str | None = Param(
        required=False,
        default=None,
        description="ID or name of the team",
        primary=True,
        cef_types=["mattermost team"],
    )


class TimezoneOutput(ActionOutput):
    """Mattermost user timezone settings."""

    automaticTimezone: str | None = None
    manualTimezone: str | None = None
    useAutomaticTimezone: str | None = OutputField(example_values=["true"])


class ListUsersOutput(ActionOutput):
    """A Mattermost user returned by the API."""

    auth_data: str | None = None
    auth_service: str | None = None
    create_at: float | None = OutputField(example_values=[1535004134292])
    delete_at: float | None = OutputField(example_values=[0])
    email: str | None = OutputField(
        cef_types=["email"],
        example_values=["test.user@mattermost.com"],
    )
    email_verified: bool | None = None
    failed_attempts: float | None = OutputField(example_values=[0])
    first_name: str | None = OutputField(example_values=["test"])
    id: str | None = OutputField(
        example_values=["pyx8sqe7zfn1dpmtd1s3qzqhfr"],
    )
    last_name: str | None = OutputField(example_values=["user"])
    last_password_update: float | None = OutputField(example_values=[0])
    last_picture_update: float | None = OutputField(example_values=[0])
    locale: str | None = OutputField(example_values=["en"])
    mfa_active: bool | None = None
    nickname: str | None = OutputField(example_values=["test"])
    notify_props: str | None = None
    position: str | None = None
    props: str | None = None
    roles: str | None = OutputField(
        example_values=["system_user system_user_access_token system_post_all"],
    )
    timezone: TimezoneOutput | None = None
    update_at: float | None = OutputField(example_values=[1535105717458])
    username: str | None = OutputField(
        cef_types=["user name"],
        example_values=["test.user"],
    )
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
    output = [
        ListUsersOutput(
            **_stringify_legacy_fields(
                user, {"auth_data", "notify_props", "props"}
            )
        )
        for user in users
    ]
    soar.set_summary(ListUsersSummary(total_users=len(output)))
    return output
