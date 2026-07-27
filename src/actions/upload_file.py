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
# Ported from legacy _handle_upload_file / _get_vault_info
# (mattermost_connector.py): resolve the vault file for this container
# (falling back to the first vault entry on ambiguity, matching legacy),
# resolve team+channel, multipart-upload the file's bytes to /files, then
# create a post referencing the returned file_ids.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset
from ..client import call_mattermost
from ..consts import (
    MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG,
    MATTERMOST_FILE_UPLOAD_FAILED,
    MATTERMOST_FILE_UPLOAD_MSG,
    MATTERMOST_FILES_ENDPOINT,
    MATTERMOST_VAULT_ID_NOT_FOUND,
)
from ._helpers import (
    _check_response,
    _create_post,
    _resolve_channel_id,
    _resolve_team_id,
)


class UploadFileParams(Params):
    team: str = Param(
        description="ID or name of the team",
        primary=True,
        cef_types=["mattermost team"],
    )
    channel: str = Param(
        description="ID or name of the channel",
        primary=True,
        cef_types=["mattermost channel"],
    )
    vault_id: str = Param(
        description="Vault ID", primary=True, cef_types=["vault id", "sha1"]
    )
    message: str | None = Param(description="Message to send")


class FilesOutput(ActionOutput):
    id: str = OutputField(example_values=["8fgytaxpojn15dchqonjb15enw"])
    name: str = OutputField(example_values=["test.png"])
    size: float = OutputField(example_values=[211962])
    width: float = OutputField(example_values=[2230])
    height: float = OutputField(example_values=[1220])
    post_id: str = OutputField(example_values=["k44mtz9ippru7eipruqnthsc9o"])
    user_id: str = OutputField(example_values=["8bfk4fj8gpyofq7qx85tsz97rh"])
    create_at: float = OutputField(example_values=[1636961337700])
    delete_at: float = OutputField(example_values=[0])
    extension: str = OutputField(example_values=["png"])
    mime_type: str = OutputField(example_values=["image/png"])
    update_at: float = OutputField(example_values=[1636961337700])
    channel_id: str = OutputField(example_values=["aopx3i38utrfxqyg86tq9xx3qw"])
    mini_preview: str = OutputField(
        example_values=[
            "/9j/2wCEAAMCAgMCBgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRQBAwQEBQQFCQUFCRQNCw0UFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFP/AABEIABAAEAMBIgACEQEDEQH/xAGiAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgsQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+gEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoLEQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T19vf4+fr/2gAMAwEAAhEDEQA/APgKe+e6YM7DhMDCA+2Kg8krAJs4GcD5hnI68V1NjfQxWlmiMI5UhRi2DkH1B+uKi1O6ie1uQZd0jITyDkk89fxrqsc1z//Z"  # pragma: allowlist secret
        ]
    )
    has_preview_image: bool = OutputField(example_values=[True])
    remote_id: str


class MetadataOutput(ActionOutput):
    files: list[FilesOutput]


class UploadFileOutput(ActionOutput):
    channel_id: str = OutputField(
        cef_types=["mattermost channel"], example_values=["ofond1t88jbr8e6cbwb7ogk98h"]
    )
    create_at: float = OutputField(example_values=[1535533720541])
    delete_at: float = OutputField(example_values=[0])
    edit_at: float = OutputField(example_values=[1535533798521])
    file_ids: str = OutputField(example_values=["1ioo54wdtpnq7eddp9yc5jikhy"])
    hashtags: str
    id: str = OutputField(example_values=["uinosfs9a3r9dgay15epdn39qy"])
    is_pinned: bool
    message: str = OutputField(example_values=["Upload file"])
    original_id: str = OutputField(example_values=["g9rit1zsx3ngzbs1srtx8tu5fe"])
    parent_id: str = OutputField(example_values=["uinosfs9a3r9dgay15epdn39qy"])
    pending_post_id: str = OutputField(example_values=["g9rit1zsx3ngzbs1srtx8tu5fe"])
    root_id: str = OutputField(example_values=["uinosfs9a3r9dgay15epdn39qy"])
    type: str
    update_at: float = OutputField(example_values=[1535533720541])
    user_id: str = OutputField(example_values=["nj9wemswb7f4zykdetw9egbwuo"])
    metadata: MetadataOutput
    reply_count: float = OutputField(example_values=[0])
    last_reply_at: float = OutputField(example_values=[0])
    participants: str


def upload_file(
    params: UploadFileParams, soar: SOARClient, asset: Asset
) -> UploadFileOutput:
    if not asset.personal_token and not (asset.client_id and asset.client_secret):
        raise ActionFailure(MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG)

    attachments = soar.vault.get_attachment(vault_id=params.vault_id)
    if not attachments:
        raise ActionFailure(MATTERMOST_VAULT_ID_NOT_FOUND)

    container_id = soar.get_executing_container_id()
    attachment = next(
        (a for a in attachments if a.container_id == container_id), attachments[0]
    )

    team_id = _resolve_team_id(params.team, asset)
    channel_id = _resolve_channel_id(team_id, params.channel, asset)

    with attachment.open("rb") as fin:
        content = fin.read()

    response = call_mattermost(
        "POST",
        MATTERMOST_FILES_ENDPOINT,
        asset,
        data={"channel_id": channel_id},
        files={"files": (attachment.name, content)},
    )
    _check_response(response)
    file_infos = response.json().get("file_infos", [])
    if not file_infos:
        raise ActionFailure(MATTERMOST_FILE_UPLOAD_FAILED)

    file_ids = [each_file["id"] for each_file in file_infos]
    message = params.message or MATTERMOST_FILE_UPLOAD_MSG
    post = _create_post(
        {"channel_id": channel_id, "message": message, "file_ids": file_ids}, asset
    )
    return UploadFileOutput(**post)
