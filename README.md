# Pragmatic Authentication Library: OAuth2 workflows

The collection of OAuth2 workflows for [PAL][pal].

### The Authorization Code Grant workflow

#### Options

You can configure the workflow, passing the options into `pal:new/2` or `pal:group/2` functions:

- `client_id` (required) -
		The client identifier, a unique string representing the registration information provided by the client.
- `client_secret` (required) -
		The client secret.
- `authorization_uri` (required) -
		The authorization code endpoint.
- `access_token_uri` (required) -
		The endpoint for retrieving the access token.
- `redirect_uri` (optional) -
		The client redirection endpoint.
		After completing its interaction with the resource owner,
		the authorization server directs the resource owner's user-agent to this uri.
- `scope` (optional) -
		The scope of the access request.
- `request_options` (optional) -
		Request options, in the format of [hackney][hackney] HTTP client.
- `includes` (optional) -
		Parts of authentication schema to be processed by the workflow.
		All by default, `[uid, credentials, info, extra, rules]`.

#### Input Data

- `code` -
		The authorization code.
- `state` -
		The state was previously passed to the authentication provider.
- `error`
		If the request fails due to a missing, invalid, or mismatching
		redirection URI, or if the client identifier is missing or invalid.

#### Authentication Schema

If an execution of the `pal:authenticate/{2,3}` function were successful,
the authentication schema would be returned:

```erlang
#{access_token  => <<"...">>,
  token_type    => <<"Bearer">>,
  expires_in    => 3600,
  refresh_token => <<"...">>}
```

Keys were named according to [RFC 6749][rfc6749-credentials].

See the complete example using PAL and [Cowboy][cowboy] HTTP server [here][pal-example].

### License

The source code is provided under the terms of [the MIT license][license].

[license]:http://www.opensource.org/licenses/MIT
[cowboy]:https://github.com/extend/cowboy
[rfc6749]:https://tools.ietf.org/html/rfc6749
[rfc6749-credentials]:http://tools.ietf.org/html/rfc6749#section-4.2.2
[hackney]:https://github.com/benoitc/hackney
[pal]:https://github.com/manifest/pal
[pal-example]:https://github.com/manifest/pal-example

