# flask-oauth-gmail
Example OAuth Gmail Flow


## Overview of Quickstart
See:

    https://developers.google.com/identity/protocols/OAuth2WebServer

1. Set Authorization Request to define which permissions the User will be asked to grant

2. [CLIENT => SERVER] Redirect to Google's OAuth Server to intiate the authentication and authorization process (when app needs access to user data)

3. [SERVER => CLIENT => SERVER] Google Prompts for consent

4. [SERVER => CLIENT] Google's OAuth server responds to your app's access request. Client gets the `authorization_code` from the response.

5. [CLIENT => SERVER] Exchange authorization code for refresh and access tokens

6. [CLIENT => SERVER] Call the relevant API with the refresh and access tokens

## Credentials

Drive Client ID


    1024059571436-isphathb93das31s6hr2j74f03011aqb.apps.googleusercontent.com

Drive Client Secret

    SQ7G3EuNxHfcs1bvgejZ54tU

---

Gmail Client ID

    83509637420-51coovqfcjcc98bh14ak0lpvbnprirum.apps.googleusercontent.com

Client Secret

    v5x4NNa4osiyqS35SB0WOigU

