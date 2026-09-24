**Unreleased**

* Migrated the Mattermost connector to the Splunk SOAR SDK. Existing action names, parameters, Mattermost endpoints, and personal-token authentication remain available.
* Raised the minimum supported Splunk SOAR version from 6.3.0 to 7.0.0.
* Added the SDK `make_request` action for authenticated Mattermost API requests.
* OAuth callbacks now use the SDK webhook route ending in `/oauth_callback` instead of the legacy `/rest/handler/.../result` route. Existing OAuth applications must register the asset-specific SDK callback URL, and OAuth assets must have both `client_id` and `client_secret` configured.
* A usable legacy OAuth token is migrated automatically. If no token exists, or a stored token cannot be refreshed or accepted, the connector requires one authorization through the browser.
* Added nested participant datapath support for `list_posts`, `send_message`, and `upload_file`. playbooks can use nested fields such as `participants.*.id` or `participants.*.username`.
* Added individual file-ID datapath support for `list_posts` and `upload_file`. Playbooks can use `action_result.data.*.file_ids.*` to pass each returned file ID separately to downstream actions.
* User and team pagination now stops with an explicit error after 1,000 pages. This prevents an unavailable or non-terminating endpoint from running indefinitely; normal result sets are unchanged. Existing post safety limits and repeated-page progress checks remain in place.
