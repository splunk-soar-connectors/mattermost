### OAuth authentication

Mattermost supports authentication with either a personal access token or an
OAuth 2.0 application. Configure `server_url` for every asset. For OAuth,
configure both `client_id` and `client_secret`; the two fields are used
together for authorization and token exchange. `personal_token` is optional.

#### Configure the Mattermost OAuth application

1. In Mattermost, open **System Console > Integrations > OAuth 2.0
   Applications** and select the OAuth application used by the SOAR asset.
1. In the SOAR asset, open **Webhook Settings** and copy the route ending in
   `/oauth_callback`.
1. Add that complete URL to the Mattermost OAuth application's **Callback
   URLs**, including the SOAR host, application identifier, and asset ID. The
   URL is asset-specific, so use the URL displayed for each asset. Do not use
   the legacy `/rest/handler/.../result` callback for the SDK app.
1. Save the OAuth application and verify that the client ID and client secret
   in the SOAR asset belong to that application.

#### Authorize an asset

1. Configure the Mattermost asset with `server_url`, `client_id`, and
   `client_secret`.
1. Select **Test Connectivity** in SOAR.
1. If authorization is required, open the OAuth URL displayed in the test
   progress message, sign in to Mattermost, and select **Allow**.
1. Return to the SOAR test and wait for the OAuth callback and connectivity
   result.

If a valid `personal_token` is configured, the connector tries it first. When
that token is absent or rejected and both OAuth fields are configured, the
connector uses the OAuth flow instead.

#### Upgrade from the legacy connector

The SDK app uses the webhook callback ending in `/oauth_callback` instead of
the legacy `/rest/handler/.../result` callback. Before upgrading an existing
OAuth asset, add the new SDK callback URL to the Mattermost OAuth application
for that asset. Keep the legacy callback while an older connector version is
still in use, then remove it after the upgrade is complete.

The connector migrates a usable legacy OAuth token into SDK-managed OAuth
state when `client_id` is configured. Existing assets must still have both
`client_id` and `client_secret` configured so the connector can authorize or
refresh OAuth credentials. Run **Test Connectivity** after the upgrade. If the
legacy token cannot be used or no token is available, SOAR displays a new
authorization URL and the asset must be authorized once through the browser.
