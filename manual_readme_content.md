### OAuth authorization and one-time reauthorization

OAuth tokens from an existing legacy Mattermost asset are not migrated into the
SDK-managed `auth_state`. Therefore, each existing legacy OAuth asset requires
one authorization after upgrading to this SDK-based app. Personal-token assets
do not require this OAuth reauthorization step.

After this one-time authorization, the SDK stores the OAuth token in the
asset's `auth_state`. Later actions reuse the stored token and refresh it
automatically when Mattermost provides a refresh token.
