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

from __future__ import annotations

from typing import TYPE_CHECKING

from soar_sdk.auth import create_oauth_callback_handler

from .auth import build_oauth_client
from .consts import MATTERMOST_OAUTH_CALLBACK_ROUTE, MATTERMOST_OAUTH_SUCCESS_MSG


if TYPE_CHECKING:
    from soar_sdk.app import App


def register_oauth_webhook(app: App) -> App:
    """Register the unauthenticated callback used by Mattermost OAuth."""
    app.enable_webhooks(default_requires_auth=False)
    oauth_callback = create_oauth_callback_handler(
        build_oauth_client,
        success_message=MATTERMOST_OAUTH_SUCCESS_MSG,
    )

    @app.webhook(MATTERMOST_OAUTH_CALLBACK_ROUTE, allowed_methods=["GET"])
    def mattermost_oauth_callback(request):
        return oauth_callback(request)

    return app
