**Unreleased**

* Migrated the Mattermost connector to the Splunk SOAR SDK. Existing action names,
  parameters, Mattermost endpoints, and personal-token authentication remain
  available.
* Raised the minimum supported Splunk SOAR version from 6.3.0 to 7.0.0.
* Added the SDK `make_request` action for authenticated Mattermost API requests.

### Compatibility and migration notes

* OAuth callbacks now use the SDK webhook route ending in `/oauth_callback`
  instead of the legacy `/rest/handler/.../result` route. Existing OAuth
  applications must register the asset-specific SDK callback URL. OAuth assets
  must have both `client_id` and `client_secret` configured. A usable legacy
  token is migrated automatically. If no token exists, or a stored token cannot
  be refreshed or accepted, the connector requires one authorization through
  the browser.
* SDK output models now describe Mattermost response types instead of exposing
  several legacy manifest fields as generic strings:
  * `participants` is a list of user objects in `list_posts`,
    `send_message`, and `upload_file`. Playbooks that consumed the old
    `participants` string datapath should use nested fields such as
    `participants.*.id` or `participants.*.username`.
  * `file_ids` is represented as a list of string IDs. Playbooks that need an
    individual ID should use `file_ids.*` rather than the old `file_ids`
    field.
  * `notify_props` and post `props` retain structured Mattermost values,
    including additional keys returned by the server, instead of being modeled
    as one string value.
  * `timezone.useAutomaticTimezone` is represented as a boolean
    (`true`/`false`) rather than the legacy string (`"true"`/`"false"`).
    Playbooks comparing this value as text must update their comparisons.
* User and team pagination now stops with an explicit error after 1,000 pages.
  This prevents an unavailable or non-terminating endpoint from running
  indefinitely; normal result sets are unchanged. The existing post safety
  limits remain in place, and repeated post pages still fail explicitly when
  they make no progress.
