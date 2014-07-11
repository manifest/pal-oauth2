# Pragmatic Authentication Library: OAuth2 workflows

collection of OAuth2 workflows for PAL according to [RFC 6749][rfc6749]

### Authorization Code Grant workflow

#### Options

You can configure several options, which you pass into `pal:new/2` or `pal:init/1` functions via map:

- `client_id` (required) -
		The client identifier, a unique string representing the registration information provided by the client
- `client_secret` (required) -
		The client secret.
- `authorization_uri` (required) -
		The endpoint for retrieving the authorization code.
- `access_token_uri` (required) -
		The endpoint for retrieving the access token.
- `redirect_uri` (optional) -
		The client redirection endpoint.
		After completing its interaction with the resource owner,
		the authorization server directs the resource owner's user-agent to this uri.
- `scope` (optional) -
		The scope of the access request.
- `session` (recommended) -
		A session module which implements the `pt_session` behavior. For instanse, `pt_cowboy_session`.
		Used for holding a state between the request and callback.
- `request_options` (optional) -
		Request options for [hackney][hackney] HTTP client.
- `includes` (optional) -
		Parts of authentication map to be processed by the workflow.
		All by default, `[credentials, info, extra, rules]`.

#### Auth Map

Here's an example of an authentication map available in the HTTP handler
after success execution of `pal:authenticate/2` function.
Keys have been named according to [RFC 6749][rfc6749-credentials].

```erlang
#{credentials =>
  #{access_token  => <<"token-value">>,
    token_type    => <<"Bearer">>,
    expires_in    => 3600,
    refresh_token => <<"another-token-value">>}}
```

### How to use

See [example][pal-example].

### Documentation

See [pal][pal] and [pt-cowboy-session][pt-cowboy-session] projects for more information.

### License

Provided under the terms of [the MIT license][license].

[license]:http://www.opensource.org/licenses/MIT
[rfc6749]:https://tools.ietf.org/html/rfc6749
[rfc6749-credentials]:http://tools.ietf.org/html/rfc6749#section-4.2.2
[hackney]:https://github.com/benoitc/hackney
[pt-cowboy-session]:https://github.com/manifest/pt-cowboy-session
[pal]:https://github.com/manifest/pal
[pal-example]:https://github.com/manifest/pal-example

