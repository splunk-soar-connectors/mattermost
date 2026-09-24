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

from soar_sdk.asset import AssetField, BaseAsset


class Asset(BaseAsset):
    """Mattermost server and authentication configuration."""

    server_url: str = AssetField(
        description="Server URL (e.g. http://10.10.10.10:8080)"
    )
    verify_server_cert: bool = AssetField(
        description="Verify server certificate", required=False, default=True
    )
    personal_token: str | None = AssetField(
        description="Personal token", sensitive=True, required=False
    )
    client_id: str | None = AssetField(description="Client ID", required=False)
    client_secret: str | None = AssetField(
        description="Client secret", sensitive=True, required=False
    )
