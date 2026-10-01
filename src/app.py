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
from soar_sdk.app import App
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .actions import register_actions
from .asset import Asset
from .auth import (
    build_oauth_auth,
    build_pat_auth,
    complete_oauth_authorization,
    probe_current_user,
)
from .client import parse_json_response
from .consts import (
    MATTERMOST_MAKING_CONNECTION_MSG,
    MATTERMOST_OAUTH_CALLBACK_ROUTE,
    MATTERMOST_TEST_CONNECTIVITY_FAILED_MSG,
    MATTERMOST_TEST_CONNECTIVITY_PASSED_MSG,
)
from .webhooks import register_oauth_webhook


logger = getLogger()


def create_mattermost_app() -> App:
    """Create and configure the Mattermost SOAR application."""
    app = App(
        name="Mattermost",
        app_type="information",
        logo="logo_mattermost.svg",
        logo_dark="logo_mattermost_dark.svg",
        product_vendor="Mattermost",
        product_name="Mattermost",
        publisher="Splunk",
        appid="b303c16b-8b45-404d-b573-dd5f4b0082e0",
        fips_compliant=True,
        asset_cls=Asset,
    )

    register_oauth_webhook(app)

    @app.test_connectivity()
    def test_connectivity(soar: SOARClient, asset: Asset) -> None:
        """Validate Mattermost credentials with the current-user endpoint."""
        if not asset.personal_token and not (asset.client_id and asset.client_secret):
            raise ActionFailure(
                "Either 'personal_token' or 'client_id' and 'client_secret' "
                "are required for test connectivity"
            )

        logger.progress(MATTERMOST_MAKING_CONNECTION_MSG)
        if asset.personal_token:
            response = probe_current_user(asset, build_pat_auth(asset))
            if response.is_success:
                logger.progress(MATTERMOST_TEST_CONNECTIVITY_PASSED_MSG)
                return
            if response.status_code != 401 or not (
                asset.client_id and asset.client_secret
            ):
                parse_json_response(response)

        redirect_uri = app.get_webhook_url(MATTERMOST_OAUTH_CALLBACK_ROUTE)
        complete_oauth_authorization(
            asset,
            asset_id=str(soar.get_asset_id()),
            redirect_uri=redirect_uri,
            announce_url=logger.progress,
        )
        response = probe_current_user(asset, build_oauth_auth(asset))
        try:
            parse_json_response(response)
        except ActionFailure:
            logger.progress(MATTERMOST_TEST_CONNECTIVITY_FAILED_MSG)
            raise
        logger.progress(MATTERMOST_TEST_CONNECTIVITY_PASSED_MSG)

    return register_actions(app)


app: App = create_mattermost_app()


if __name__ == "__main__":
    app.cli()
