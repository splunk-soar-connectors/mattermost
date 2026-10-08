# Mattermost

Publisher: Splunk <br>
Connector Version: 3.0.1 <br>
Product Vendor: Mattermost <br>
Product Name: Mattermost <br>
Minimum Product Version: 7.0.0

This app integrates with Mattermost to support various investigative actions

### Configuration variables

This table lists the configuration variables required to operate Mattermost. These variables are specified when configuring a Mattermost asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server_url** | required | string | Server URL (e.g. http://10.10.10.10:8080) |
**verify_server_cert** | optional | boolean | Verify server certificate |
**personal_token** | optional | password | Personal token |
**client_id** | optional | string | Client ID |
**client_secret** | optional | password | Client secret |

### OAuth configuration

When using OAuth authentication, configure the Mattermost OAuth application with the client ID and client secret. Copy the callback URL shown under the Mattermost asset's Webhook Settings into the OAuth application's Callback URLs, then enable webhooks for the asset in SOAR. Leave **Webhooks require SOAR authentication** disabled for the OAuth callback. A personal-token configuration does not require webhook setup.

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate Mattermost credentials with the current-user endpoint. <br>
[list users](#action-list-users) - List Mattermost users. <br>
[upload file](#action-upload-file) - Upload a vault file to a Mattermost channel. <br>
[send message](#action-send-message) - Send a message to a Mattermost channel. <br>
[list posts](#action-list-posts) - List posts from a Mattermost channel. <br>
[list channels](#action-list-channels) - List public and private Mattermost channels for a team. <br>
[list teams](#action-list-teams) - List Mattermost teams. <br>
[make request](#action-make-request) - Send an arbitrary authenticated request to a Mattermost API endpoint.

## action: 'test connectivity'

Validate Mattermost credentials with the current-user endpoint.

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list users'

List Mattermost users.

Type: **investigate** <br>
Read only: **True**

Lists all users, optionally limited to a Mattermost team.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**team** | optional | ID or name of the team | string | `mattermost team` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.team | string | `mattermost team` | |
action_result.data.\*.id | string | | pyx8sqe7zfn1dpmtd1s3qzqhfr |
action_result.data.\*.username | string | `user name` | test.user |
action_result.data.\*.email | string | `email` | test.user@mattermost.com |
action_result.data.\*.first_name | string | | test |
action_result.data.\*.last_name | string | | user |
action_result.data.\*.roles | string | | system_user system_user_access_token system_post_all |
action_result.data.\*.auth_data | string | | |
action_result.data.\*.auth_service | string | | |
action_result.data.\*.create_at | numeric | | 1535004134292 |
action_result.data.\*.delete_at | numeric | | 0 |
action_result.data.\*.email_verified | boolean | | True False |
action_result.data.\*.failed_attempts | numeric | | 0 |
action_result.data.\*.last_password_update | numeric | | 0 |
action_result.data.\*.last_picture_update | numeric | | 0 |
action_result.data.\*.locale | string | | en |
action_result.data.\*.mfa_active | boolean | | True False |
action_result.data.\*.nickname | string | | test |
action_result.data.\*.position | string | | |
action_result.data.\*.timezone.automaticTimezone | string | | |
action_result.data.\*.timezone.manualTimezone | string | | |
action_result.data.\*.timezone.useAutomaticTimezone | boolean | | True False |
action_result.data.\*.update_at | numeric | | 1535105717458 |
action_result.data.\*.disable_welcome_email | boolean | | True False |
action_result.data.\*.notify_props | string | | |
action_result.data.\*.props | string | | |
action_result.summary.total_users | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'upload file'

Upload a vault file to a Mattermost channel.

Type: **generic** <br>
Read only: **False**

Uploads a SOAR vault file and creates a Mattermost post containing it.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**team** | required | ID or name of the team | string | `mattermost team` |
**channel** | required | ID or name of the channel | string | `mattermost channel` |
**vault_id** | required | Vault ID | string | `vault id` `sha1` |
**message** | optional | Message to send | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.team | string | `mattermost team` | |
action_result.parameter.channel | string | `mattermost channel` | |
action_result.parameter.vault_id | string | `vault id` `sha1` | |
action_result.parameter.message | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.message | string | | |
action_result.data.\*.user_id | string | | |
action_result.data.\*.channel_id | string | `mattermost channel` | |
action_result.data.\*.file_ids.\* | string | | |
action_result.data.\*.create_at | numeric | | |
action_result.data.\*.update_at | numeric | | |
action_result.data.\*.delete_at | numeric | | |
action_result.data.\*.edit_at | numeric | | |
action_result.data.\*.hashtags | string | | |
action_result.data.\*.is_pinned | boolean | | True False |
action_result.data.\*.original_id | string | | |
action_result.data.\*.parent_id | string | | |
action_result.data.\*.pending_post_id | string | | |
action_result.data.\*.root_id | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.metadata.files.\*.id | string | | 8fgytaxpojn15dchqonjb15enw |
action_result.data.\*.metadata.files.\*.name | string | | test.png |
action_result.data.\*.metadata.files.\*.size | numeric | | 211962 |
action_result.data.\*.metadata.files.\*.width | numeric | | 2230 |
action_result.data.\*.metadata.files.\*.height | numeric | | 1220 |
action_result.data.\*.metadata.files.\*.post_id | string | | k44mtz9ippru7eipruqnthsc9o |
action_result.data.\*.metadata.files.\*.user_id | string | | 8bfk4fj8gpyofq7qx85tsz97rh |
action_result.data.\*.metadata.files.\*.create_at | numeric | | 1636961337700 |
action_result.data.\*.metadata.files.\*.delete_at | numeric | | 0 |
action_result.data.\*.metadata.files.\*.extension | string | | png |
action_result.data.\*.metadata.files.\*.mime_type | string | | image/png |
action_result.data.\*.metadata.files.\*.update_at | numeric | | 1636961337700 |
action_result.data.\*.metadata.files.\*.channel_id | string | | aopx3i38utrfxqyg86tq9xx3qw |
action_result.data.\*.metadata.files.\*.mini_preview | string | | |
action_result.data.\*.metadata.files.\*.has_preview_image | boolean | | True False |
action_result.data.\*.metadata.files.\*.remote_id | string | | |
action_result.data.\*.reply_count | numeric | | 0 |
action_result.data.\*.last_reply_at | numeric | | 0 |
action_result.data.\*.participants.\* | string | | |
action_result.summary | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'send message'

Send a message to a Mattermost channel.

Type: **generic** <br>
Read only: **False**

Creates a new post in a Mattermost channel.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**team** | required | ID or name of the team | string | `mattermost team` |
**channel** | required | ID or name of the channel | string | `mattermost channel` |
**message** | required | Message to send | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.team | string | `mattermost team` | |
action_result.parameter.channel | string | `mattermost channel` | |
action_result.parameter.message | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.message | string | | |
action_result.data.\*.user_id | string | | |
action_result.data.\*.channel_id | string | `mattermost channel` | |
action_result.data.\*.create_at | numeric | | |
action_result.data.\*.update_at | numeric | | |
action_result.data.\*.delete_at | numeric | | |
action_result.data.\*.edit_at | numeric | | |
action_result.data.\*.hashtags | string | | |
action_result.data.\*.is_pinned | boolean | | True False |
action_result.data.\*.original_id | string | | |
action_result.data.\*.parent_id | string | | |
action_result.data.\*.pending_post_id | string | | |
action_result.data.\*.root_id | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.reply_count | numeric | | 0 |
action_result.data.\*.last_reply_at | numeric | | 0 |
action_result.data.\*.participants.\* | string | | |
action_result.summary | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list posts'

List posts from a Mattermost channel.

Type: **investigate** <br>
Read only: **True**

Lists channel posts, optionally constrained by a timestamp range.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**team** | required | ID or name of the team | string | `mattermost team` |
**channel** | required | ID or name of the channel | string | `mattermost channel` |
**start_time** | optional | Start time in formatted timestamp | string | |
**end_time** | optional | End time in formatted timestamp | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.team | string | `mattermost team` | |
action_result.parameter.channel | string | `mattermost channel` | |
action_result.parameter.start_time | string | | |
action_result.parameter.end_time | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.message | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.user_id | string | | |
action_result.data.\*.props.addedUsername | string | `user name` | |
action_result.data.\*.props.username | string | `user name` | |
action_result.data.\*.channel_id | string | `mattermost channel` | |
action_result.data.\*.file_ids.\* | string | | |
action_result.data.\*.create_at | numeric | | |
action_result.data.\*.edit_at | numeric | | |
action_result.data.\*.update_at | numeric | | |
action_result.data.\*.delete_at | numeric | | |
action_result.data.\*.hashtags | string | | |
action_result.data.\*.is_pinned | boolean | | True False |
action_result.data.\*.original_id | string | | |
action_result.data.\*.parent_id | string | | |
action_result.data.\*.pending_post_id | string | | |
action_result.data.\*.root_id | string | | |
action_result.data.\*.reply_count | numeric | | 0 |
action_result.data.\*.last_reply_at | numeric | | 0 |
action_result.data.\*.metadata.files.\*.id | string | | 1nrp7izie7gdz81mwb99azed4w |
action_result.data.\*.metadata.files.\*.name | string | | test.png |
action_result.data.\*.metadata.files.\*.size | numeric | | 211962 |
action_result.data.\*.metadata.files.\*.width | numeric | | 2230 |
action_result.data.\*.metadata.files.\*.height | numeric | | 1220 |
action_result.data.\*.metadata.files.\*.post_id | string | | zn6cs7a4b7y6bmxy4yk4j1dz3y |
action_result.data.\*.metadata.files.\*.user_id | string | | 8bfk4fj8gpyofq7qx85tsz97rh |
action_result.data.\*.metadata.files.\*.create_at | numeric | | 1637228792269 |
action_result.data.\*.metadata.files.\*.delete_at | numeric | | 0 |
action_result.data.\*.metadata.files.\*.extension | string | | png |
action_result.data.\*.metadata.files.\*.mime_type | string | | image/png |
action_result.data.\*.metadata.files.\*.update_at | numeric | | 1637228792269 |
action_result.data.\*.metadata.files.\*.channel_id | string | | aopx3i38utrfxqyg86tq9xx3wy |
action_result.data.\*.metadata.files.\*.mini_preview | string | | |
action_result.data.\*.metadata.files.\*.has_preview_image | boolean | | True False |
action_result.data.\*.metadata.files.\*.remote_id | string | | |
action_result.data.\*.participants.\* | string | | |
action_result.summary.total_posts | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list channels'

List public and private Mattermost channels for a team.

Type: **investigate** <br>
Read only: **True**

Lists channels visible to the configured Mattermost user.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**team** | required | ID or name of the team | string | `mattermost team` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.team | string | `mattermost team` | |
action_result.data.\*.id | string | `mattermost channel` | bm5dwbhditgxxxd5z4qkawgxha |
action_result.data.\*.name | string | `mattermost channel` | off-topic |
action_result.data.\*.display_name | string | | Off-Topic |
action_result.data.\*.type | string | | O |
action_result.data.\*.total_msg_count | numeric | | 0 |
action_result.data.\*.create_at | numeric | | 1535370158299 |
action_result.data.\*.creator_id | string | | |
action_result.data.\*.delete_at | numeric | | 0 |
action_result.data.\*.extra_update_at | numeric | | 0 |
action_result.data.\*.header | string | | |
action_result.data.\*.last_post_at | numeric | | 1535370232524 |
action_result.data.\*.purpose | string | | |
action_result.data.\*.scheme_id | string | | |
action_result.data.\*.team_id | string | `mattermost team` | suico8q897yyiraqdekxspfjma |
action_result.data.\*.update_at | numeric | | 1535370158299 |
action_result.data.\*.total_msg_count_root | numeric | | 0 |
action_result.data.\*.team_name | string | | test-005 |
action_result.data.\*.team_update_at | numeric | | 1637228653671 |
action_result.data.\*.team_display_name | string | | test-005 |
action_result.data.\*.shared | boolean | | True False |
action_result.data.\*.policy_id | string | | |
action_result.data.\*.group_constrained | boolean | | True False |
action_result.data.\*.props | string | | |
action_result.summary.total_channels | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list teams'

List Mattermost teams.

Type: **investigate** <br>
Read only: **True**

Lists all teams visible to the configured Mattermost user.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.data.\*.id | string | `mattermost team` | 396afxwqzbgruxdkft7d8wo5qw |
action_result.data.\*.name | string | `mattermost team` | test2-sample |
action_result.data.\*.display_name | string | | test2 sample |
action_result.data.\*.email | string | `email` | sampleteam@mattermost.com |
action_result.data.\*.type | string | | O |
action_result.data.\*.invite_id | string | | xo3gnntbfbg5bnirx7i1uqujc |
action_result.data.\*.allow_open_invite | boolean | | True False |
action_result.data.\*.allowed_domains | string | `domain` | example.com |
action_result.data.\*.company_name | string | | |
action_result.data.\*.create_at | numeric | | 1534856540543 |
action_result.data.\*.delete_at | numeric | | 0 |
action_result.data.\*.description | string | | |
action_result.data.\*.scheme_id | string | | |
action_result.data.\*.update_at | numeric | | 1534918716675 |
action_result.data.\*.policy_id | string | | |
action_result.data.\*.group_constrained | boolean | | True False |
action_result.summary.total_teams | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

Send an arbitrary authenticated request to a Mattermost API endpoint.

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | Mattermost API endpoint relative to /api/v4. For example, 'users/me' or 'teams'. Do not include the server URL. | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Default true. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 404 500 |
action_result.data.\*.response_body | string | | {"key": "value"} |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
