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
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..client import call_mattermost, parse_json_response
from ..consts import (
    MATTERMOST_FILE_UPLOAD_FAILED,
    MATTERMOST_FILE_UPLOAD_MSG,
    MATTERMOST_FILES_ENDPOINT,
    MATTERMOST_VAULT_ID_NOT_FOUND,
)
from ._helpers import _create_post, _resolve_channel_id, _resolve_team_id


class UploadFileParams(Params):
    """Parameters for uploading a vault file to a Mattermost channel."""

    team: str = Param(
        required=True,
        description="ID or name of the team",
        primary=True,
        cef_types=["mattermost team"],
    )
    channel: str = Param(
        required=True,
        description="ID or name of the channel",
        primary=True,
        cef_types=["mattermost channel"],
    )
    vault_id: str = Param(
        required=True, description="Vault ID", cef_types=["vault id", "sha1"]
    )
    message: str | None = Param(
        required=False,
        default=None,
        description="Message to send",
    )


class FilesOutput(ActionOutput):
    """File metadata returned by Mattermost."""

    id: str | None = None
    name: str | None = None
    size: float | None = None
    width: float | None = None
    height: float | None = None
    post_id: str | None = None
    user_id: str | None = None
    create_at: float | None = None
    delete_at: float | None = None
    extension: str | None = None
    mime_type: str | None = None
    update_at: float | None = None
    channel_id: str | None = None
    mini_preview: str | None = None
    has_preview_image: bool | None = None
    remote_id: str | None = None


class MetadataOutput(ActionOutput):
    """File metadata embedded in the created post."""

    files: list[FilesOutput] | None = None


class UploadFileOutput(ActionOutput):
    """Mattermost post created after the file upload."""

    channel_id: str | None = OutputField(cef_types=["mattermost channel"])
    create_at: float | None = None
    delete_at: float | None = None
    edit_at: float | None = None
    file_ids: list[str] | None = None
    hashtags: str | None = None
    id: str | None = None
    is_pinned: bool | None = None
    message: str | None = None
    original_id: str | None = None
    parent_id: str | None = None
    pending_post_id: str | None = None
    root_id: str | None = None
    type: str | None = None
    update_at: float | None = None
    user_id: str | None = None
    metadata: MetadataOutput | None = None
    reply_count: float | None = None
    last_reply_at: float | None = None


def upload_file(
    params: UploadFileParams, soar: SOARClient, asset: Asset
) -> UploadFileOutput:
    """Upload a SOAR vault file and create a Mattermost post for it."""
    attachments = soar.vault.get_attachment(vault_id=params.vault_id)
    if not attachments:
        raise ActionFailure(MATTERMOST_VAULT_ID_NOT_FOUND)

    container_id = soar.get_executing_container_id()
    attachment = next(
        (item for item in attachments if item.container_id == container_id),
        attachments[0],
    )
    team_id = _resolve_team_id(params.team, asset)
    channel_id = _resolve_channel_id(team_id, params.channel, asset)

    with attachment.open("rb") as file_handle:
        content = file_handle.read()

    response = call_mattermost(
        "POST",
        MATTERMOST_FILES_ENDPOINT,
        asset,
        data={"channel_id": channel_id},
        files={"files": (attachment.name, content)},
    )
    upload_response = parse_json_response(response)
    file_infos = upload_response.get("file_infos", [])
    if not file_infos:
        raise ActionFailure(MATTERMOST_FILE_UPLOAD_FAILED)

    post = _create_post(
        {
            "channel_id": channel_id,
            "message": params.message or MATTERMOST_FILE_UPLOAD_MSG,
            "file_ids": [file_info["id"] for file_info in file_infos],
        },
        asset,
    )
    return UploadFileOutput(**post)
