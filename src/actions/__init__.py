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
from soar_sdk.app import App

from ..views import display_view
from .list_channels import ListChannelsSummary, list_channels
from .list_posts import ListPostsSummary, list_posts
from .list_teams import ListTeamsSummary, list_teams
from .list_users import ListUsersSummary, list_users
from .send_message import send_message
from .upload_file import upload_file

__all__ = ["register_actions"]


def register_actions(app: App) -> App:
    """Register every Mattermost action on the given App instance.

    Actions are declared as plain functions in their own modules; this is the
    single place they are wired onto the app, mirroring the Jira reference
    app's register_actions idiom. test_connectivity is registered separately
    by the app factory via its dedicated decorator (see app.py), not here.

    Descriptions/action_type/read_only/verbose are ported verbatim from what
    `soarapps convert` produced in the original flat app.py (itself sourced
    from mattermost.json). view_handler wiring for the 5 custom-view actions
    (list_users, upload_file, send_message, list_posts, list_channels) mirrors
    mattermost.json's render.type="custom" entries; list_teams instead uses
    render_as="table" (render.type="table" in the manifest) and has no
    view_handler.
    """
    # --- list users ---
    app.register_action(
        action=list_users,
        description="List users of a team",
        action_type="investigate",
        verbose="While listing users from a specific team, the user should have created the team or be a member of that team.",
        view_handler=display_view,
        summary_type=ListUsersSummary,
    )

    # --- upload file ---
    app.register_action(
        action=upload_file,
        description="Upload file to a channel",
        action_type="generic",
        read_only=False,
        verbose="User can upload files to only those channels which user has created or is a member of.<br><br>The default value for the <b>message</b> parameter is <b>Phantom file upload</b>.",
        view_handler=display_view,
    )

    # --- send message ---
    app.register_action(
        action=send_message,
        description="Send a message to a channel",
        action_type="generic",
        read_only=False,
        verbose="User can send message to only those channels which user has created or is a member of the team.",
        view_handler=display_view,
    )

    # --- list posts ---
    app.register_action(
        action=list_posts,
        description="List posts of a channel",
        action_type="investigate",
        verbose="Users can only list the posts of channels they have created or are members of.<br> If &quotstart_time&quot or &quotend_time&quot is specified, the action will also list the deleted post(s) within the specified time.<br>If only &quotstart_time&quot is given then the current time would be taken as &quotend_time&quot.<br>If only &quotend_time&quot is given then all the posts before that time would be displayed.<br>The timestamp should be entered in <b>YYYY-MM-DD</b> or a valid &quotISO 8601 timestamp&quot format.<br>Some examples of valid time formats are:<ul><li>2018-09-24</li><li>2018-09-23T14:40:44Z</li><li>2018-09-23T14:40:44+05:30</li><li>2020-08-30T01:45:36.123Z</li><li>2021-12-13T21:20:37.593194+05:30</li></ul>",
        view_handler=display_view,
        summary_type=ListPostsSummary,
    )

    # --- list channels ---
    app.register_action(
        action=list_channels,
        description="List public and private channels of a team",
        action_type="investigate",
        verbose="A user can view only those channels of a team which he is a member of.",
        view_handler=display_view,
        summary_type=ListChannelsSummary,
    )

    # --- list teams ---
    app.register_action(
        action=list_teams,
        description="List teams",
        action_type="investigate",
        render_as="table",
        verbose="While creating a team, the user should have set &quotAllow any user with an account on this server to join this team&quot under <b>Team Settings</b> to <b>YES</b> to allow the team to be displayed for all users.",
        summary_type=ListTeamsSummary,
    )

    return app
