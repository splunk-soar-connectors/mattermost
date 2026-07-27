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
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.logging import getLogger

logger = getLogger()


class Asset(BaseAsset):
    server_url: str = AssetField(
        description="Server URL (e.g. http://10.10.10.10:8080)"
    )
    verify_server_cert: bool | None = AssetField(
        description="Verify server certificate", default=False
    )
    personal_token: str | None = AssetField(
        description="Personal token", sensitive=True
    )
    client_id: str | None = AssetField(description="Client ID")
    client_secret: str | None = AssetField(description="Client secret", sensitive=True)


# Deliberately imported after Asset is defined above (not at the top of the
# file with the other imports): actions/__init__.py and every actions/*.py
# module do `from ..app import Asset`, which would otherwise be a circular
# import (app -> actions -> app) since this app keeps Asset in app.py rather
# than a standalone asset.py. Defining Asset first lets that lookup resolve
# against this partially-initialized module.
from .actions import register_actions
from .actions.test_connectivity import run_test_connectivity
from .webhooks import register_oauth_webhook


def create_mattermost_app() -> App:
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
        run_test_connectivity(soar, asset, app=app)

    return register_actions(app)


app: App = create_mattermost_app()


if __name__ == "__main__":
    app.cli()
