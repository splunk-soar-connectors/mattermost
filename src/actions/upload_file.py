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
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..client import call_mattermost, parse_json_response
from ..consts import (
    MATTERMOST_FILE_UPLOAD_FAILED,
    MATTERMOST_FILE_UPLOAD_MSG,
    MATTERMOST_FILE_UPLOAD_SUCCESS,
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
        required=True,
        description="Vault ID",
        primary=True,
        cef_types=["vault id", "sha1"],
    )
    message: str | None = Param(
        required=False,
        default=None,
        description="Message to send",
    )


class FilesOutput(PermissiveActionOutput):
    """File metadata returned by Mattermost."""

    id: str | None = OutputField(example_values=["8fgytaxpojn15dchqonjb15enw"])
    name: str | None = OutputField(example_values=["test.png"])
    size: float | None = OutputField(example_values=[211962])
    width: float | None = OutputField(example_values=[2230])
    height: float | None = OutputField(example_values=[1220])
    post_id: str | None = OutputField(example_values=["k44mtz9ippru7eipruqnthsc9o"])
    user_id: str | None = OutputField(example_values=["8bfk4fj8gpyofq7qx85tsz97rh"])
    create_at: float | None = OutputField(example_values=[1636961337700])
    delete_at: float | None = OutputField(example_values=[0])
    extension: str | None = OutputField(example_values=["png"])
    mime_type: str | None = OutputField(example_values=["image/png"])
    update_at: float | None = OutputField(example_values=[1636961337700])
    channel_id: str | None = OutputField(example_values=["aopx3i38utrfxqyg86tq9xx3qw"])
    mini_preview: str | None = OutputField(
        example_values=[
            "/9j/2wCEAAMCAgMCBgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRQBAwQEBQQFCQUFCRQNCw0UFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFP/AABEIABAAEAMBIgACEQEDEQH/xAGiAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgsQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+gEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoLEQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T19vf4+fr/2gAMAwEAAhEDEQA/APgKe+e6YM7DhMDCA+2Kg8krAJs4GcD5hnI68V1NjfQxWlmiMI5UhRi2DkH1B+uKi1O6ie1uQZd0jITyDkk89fxrqsc1z//Z"  # pragma: allowlist secret
        ]
    )
    has_preview_image: bool | None = OutputField(example_values=[True])
    remote_id: str | None = None


class MetadataOutput(PermissiveActionOutput):
    """File metadata embedded in the created post."""

    files: list[FilesOutput] | None = None


class UploadFileOutput(PermissiveActionOutput):
    """Mattermost post created after the file upload."""

    id: str | None = OutputField(
        column_name="Message ID", example_values=["uinosfs9a3r9dgay15epdn39qy"]
    )
    message: str | None = OutputField(
        column_name="Message", example_values=["Upload file"]
    )
    user_id: str | None = OutputField(
        column_name="User ID", example_values=["nj9wemswb7f4zykdetw9egbwuo"]
    )
    channel_id: str | None = OutputField(
        column_name="Channel ID",
        cef_types=["mattermost channel"],
        example_values=["ofond1t88jbr8e6cbwb7ogk98h"],
    )
    file_ids: list[str] | None = OutputField(
        column_name="File ID", example_values=["1ioo54wdtpnq7eddp9yc5jikhy"]
    )
    create_at: float | None = OutputField(
        column_name="Created At", example_values=[1535533720541]
    )
    update_at: float | None = OutputField(
        column_name="Updated At", example_values=[1535533720541]
    )
    delete_at: float | None = OutputField(example_values=[0])
    edit_at: float | None = OutputField(example_values=[1535533798521])
    hashtags: str | None = None
    is_pinned: bool | None = None
    original_id: str | None = OutputField(example_values=["g9rit1zsx3ngzbs1srtx8tu5fe"])
    parent_id: str | None = OutputField(example_values=["uinosfs9a3r9dgay15epdn39qy"])
    pending_post_id: str | None = OutputField(
        example_values=["g9rit1zsx3ngzbs1srtx8tu5fe"]
    )
    root_id: str | None = OutputField(example_values=["uinosfs9a3r9dgay15epdn39qy"])
    type: str | None = None
    metadata: MetadataOutput | None = None
    reply_count: float | None = OutputField(example_values=[0])
    last_reply_at: float | None = OutputField(example_values=[0])
    participants: list[str] | None = None


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
            "message": (
                MATTERMOST_FILE_UPLOAD_MSG if params.message is None else params.message
            ),
            "file_ids": [file_info["id"] for file_info in file_infos],
        },
        asset,
    )
    output = UploadFileOutput(**post)
    soar.set_message(MATTERMOST_FILE_UPLOAD_SUCCESS)
    return output
