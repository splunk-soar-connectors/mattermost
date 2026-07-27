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
# Ported from legacy _handle_list_users (mattermost_connector.py). Legacy
# requires personal_token or an already-obtained access_token; resolves an
# optional team filter via _verify_team; paginates GET /users; and sets
# summary["total_users"] via action_result.update_summary(). The SDK
# equivalent of that summary write is soar.set_summary(ListUsersSummary(...))
# below, paired with summary_type=ListUsersSummary at registration time
# (see actions/__init__.py) — both are required for the
# action_result.summary.total_users manifest datapath to appear.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset
from ..consts import MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG, MATTERMOST_USERS_ENDPOINT
from ._helpers import _paginate_all, _resolve_team_id


class ListUsersParams(Params):
    team: str | None = Param(
        description="ID or name of the team",
        primary=True,
        cef_types=["mattermost team"],
    )


class TimezoneOutput(ActionOutput):
    automaticTimezone: str
    manualTimezone: str
    useAutomaticTimezone: str = OutputField(example_values=["true"])


class ListUsersOutput(ActionOutput):
    auth_data: str
    auth_service: str
    create_at: float = OutputField(example_values=[1535004134292])
    delete_at: float = OutputField(example_values=[0])
    email: str = OutputField(
        cef_types=["email"], example_values=["test.user@mattermost.com"]
    )
    email_verified: bool
    failed_attempts: float = OutputField(example_values=[0])
    first_name: str = OutputField(example_values=["test"])
    id: str = OutputField(example_values=["pyx8sqe7zfn1dpmtd1s3qzqhfr"])
    last_name: str = OutputField(example_values=["user"])
    last_password_update: float = OutputField(example_values=[0])
    last_picture_update: float = OutputField(example_values=[0])
    locale: str = OutputField(example_values=["en"])
    mfa_active: bool
    nickname: str = OutputField(example_values=["test"])
    notify_props: str
    position: str
    props: str
    roles: str = OutputField(
        example_values=["system_user system_user_access_token system_post_all"]
    )
    timezone: TimezoneOutput
    update_at: float = OutputField(example_values=[1535105717458])
    username: str = OutputField(cef_types=["user name"], example_values=["test.user"])
    disable_welcome_email: bool = OutputField(example_values=[False])


class ListUsersSummary(ActionOutput):
    total_users: int = OutputField(example_values=[10])


def list_users(
    params: ListUsersParams, soar: SOARClient, asset: Asset
) -> list[ListUsersOutput]:
    if not asset.personal_token and not (asset.client_id and asset.client_secret):
        raise ActionFailure(MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG)

    extra_params: dict[str, str] = {}
    if params.team:
        extra_params["in_team"] = _resolve_team_id(params.team, asset)

    users = _paginate_all(MATTERMOST_USERS_ENDPOINT, asset, extra_params)
    output = [ListUsersOutput(**user) for user in users]
    soar.set_summary(ListUsersSummary(total_users=len(output)))
    return output
