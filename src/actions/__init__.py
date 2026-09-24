# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

from soar_sdk.app import App

from ..views import display_view
from .list_channels import ListChannelsSummary, list_channels
from .list_posts import ListPostsSummary, list_posts
from .list_teams import ListTeamsSummary, list_teams
from .list_users import ListUsersSummary, list_users
from .send_message import send_message
from .upload_file import upload_file


def register_actions(app: App) -> App:
    """Register Mattermost actions with the SOAR application."""
    app.register_action(
        list_users,
        description="List Mattermost users.",
        verbose="Lists all users, optionally limited to a Mattermost team.",
        action_type="investigate",
        read_only=True,
        view_handler=display_view,
        summary_type=ListUsersSummary,
    )
    app.register_action(
        upload_file,
        description="Upload a vault file to a Mattermost channel.",
        verbose="Uploads a SOAR vault file and creates a Mattermost post containing it.",
        read_only=False,
        view_handler=display_view,
    )
    app.register_action(
        send_message,
        description="Send a message to a Mattermost channel.",
        verbose="Creates a new post in a Mattermost channel.",
        read_only=False,
        view_handler=display_view,
    )
    app.register_action(
        list_posts,
        description="List posts from a Mattermost channel.",
        verbose="Lists channel posts, optionally constrained by a timestamp range.",
        action_type="investigate",
        read_only=True,
        view_handler=display_view,
        summary_type=ListPostsSummary,
    )
    app.register_action(
        list_channels,
        description="List public and private Mattermost channels for a team.",
        verbose="Lists channels visible to the configured Mattermost user.",
        action_type="investigate",
        read_only=True,
        view_handler=display_view,
        summary_type=ListChannelsSummary,
    )
    app.register_action(
        list_teams,
        description="List Mattermost teams.",
        verbose="Lists all teams visible to the configured Mattermost user.",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ListTeamsSummary,
    )
    return app


__all__ = ["register_actions"]
