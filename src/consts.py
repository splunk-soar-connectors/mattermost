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

MATTERMOST_API_BASE_URL = "{server_url}/api/v4"
MATTERMOST_CURRENT_USER_ENDPOINT = "/users/me"
MATTERMOST_USERS_ENDPOINT = "/users"
MATTERMOST_TEAMS_ENDPOINT = "/teams"
MATTERMOST_LIST_CHANNELS_ENDPOINT = "/users/me/teams/{team}/channels"
MATTERMOST_LIST_POSTS_ENDPOINT = "/channels/{channel}/posts"
MATTERMOST_SEND_MSG_ENDPOINT = "/posts"
MATTERMOST_FILES_ENDPOINT = "/files"

MATTERMOST_AUTHORIZE_URL = (
    "{server_url}/oauth/authorize?response_type=code&client_id={client_id}"
    "&redirect_uri={redirect_uri}&state={state}"
)
MATTERMOST_ACCESS_TOKEN_URL = "{server_url}/oauth/access_token"  # noqa: S105
MATTERMOST_OAUTH_CALLBACK_ROUTE = "oauth_callback"
MATTERMOST_OAUTH_SUCCESS_MSG = "Code received. Please close this window, the action will continue to get new token."

MATTERMOST_CONFIG_PARAMS_REQUIRED_CONNECTIVITY = (
    "Either 'personal_token' or 'client_id' and 'client_secret' are required "
    "for test connectivity"
)
MATTERMOST_CONFIG_PARAMS_REQUIRED_MSG = (
    "Please provide 'personal_token' or run test connectivity with "
    "'client_id' and 'client_secret'"
)
MATTERMOST_TEAM_NOT_FOUND_MSG = "Team with given name or ID not found"
MATTERMOST_CHANNEL_NOT_FOUND_MSG = "Channel with given name or ID not found"
MATTERMOST_NO_POSTS_FOUND = "No posts found"
MATTERMOST_SEND_MSG_SUCCESS = "Message sent successfully"
MATTERMOST_FILE_UPLOAD_MSG = "Phantom file upload"
MATTERMOST_FILE_UPLOAD_SUCCESS = "File uploaded successfully"
MATTERMOST_VAULT_ID_NOT_FOUND = "Vault ID not found"
MATTERMOST_FILE_UPLOAD_FAILED = "Cannot upload file to the given channel"
MATTERMOST_INVALID_TIME = "Parameter 'start_time' or 'end_time' failed validation"
MATTERMOST_INVALID_TIME_RANGE = (
    "Invalid time range. 'end_time' should be greater than 'start_time'."
)
MATTERMOST_NEGATIVE_TIME = "Invalid time. Time cannot be negative."
MATTERMOST_TIMESTAMP_VALIDATION_FAILED_MSG = "Incorrect timestamp format, please enter in YYYY-MM-DD or valid ISO 8601 timestamp format."
MATTERMOST_TIMESTAMP_CONVERSION_FAILED_MSG = (
    "Cannot convert given timestamp into valid millisecond epoch"
)
MATTERMOST_MAKING_CONNECTION_MSG = "Connecting to an endpoint"
MATTERMOST_OAUTH_URL_MSG = "Using OAuth URL:"
MATTERMOST_TEST_CONNECTIVITY_FAILED_MSG = "Test connectivity failed"
MATTERMOST_TEST_CONNECTIVITY_PASSED_MSG = "Test connectivity passed"
MATTERMOST_WAITING_FOR_AUTHORIZATION_MSG = (
    "Waiting for user to complete authorization..."
)
MATTERMOST_TC_STATUS_SLEEP = 3

# These limits are part of the legacy connector's safety contract.
MATTERMOST_MAX_POST_PAGES = 1000
MATTERMOST_MAX_POSTS = 10000
MATTERMOST_MAX_GENERIC_PAGES = 1000
