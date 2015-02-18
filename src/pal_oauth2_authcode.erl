%% ----------------------------------------------------------------------------
%% The MIT License
%%
%% Copyright (c) 2014-2015 Andrei Nesterov <ae.nesterov@gmail.com>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a copy
%% of this software and associated documentation files (the "Software"), to
%% deal in the Software without restriction, including without limitation the
%% rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
%% sell copies of the Software, and to permit persons to whom the Software is
%% furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
%% IN THE SOFTWARE.
%% ----------------------------------------------------------------------------

-module(pal_oauth2_authcode).
-behaviour(pal_authentication).
-behaviour(pal_workflow).

%% API
-export([
	authorization_request/1,
	authorization_request/2,
	authorization_request_fields/1,
	access_token_request/1,
	access_token_request/2,
	access_token_request_fields/1
]).

%% Workflow callbacks
-export([
	decl/0
]).

%% Authentication workflow callbacks
-export([
	authenticate/4,
	credentials/2
]).

%% Definitions	
-define(CLIENT_ID, <<"client_id">>).
-define(CLIENT_SECRET, <<"client_secret">>).
-define(REDIRECT_URI, <<"redirect_uri">>).
-define(RESPONSE_TYPE, <<"response_type">>).
-define(GRANT_TYPE, <<"grant_type">>).
-define(AUTHORIZATION_CODE, <<"authorization_code">>).
-define(SCOPE, <<"scope">>).
-define(STATE, <<"state">>).
-define(CODE, <<"code">>).
-define(LOCATION, <<"location">>).

-define(ACCESS_TOKEN, <<"access_token">>).
-define(REFRESH_TOKEN, <<"refresh_token">>).
-define(TOKEN_TYPE, <<"token_type">>).
-define(EXPIRES_IN, <<"expires_in">>).

-define(CONTENT_TYPE, <<"content-type">>).

%% Types
-type fields() :: [{binary(), binary()}].

-export_type([fields/0]).

%% Callbacks

%% Optional.
%%
%%	-callback authorization_request(map()) -> pal_authentication:result().

%% Optional.
%%
%%	-callback authorization_request_fields(map()) -> fields().

%% Optional.
%%
%%	-callback access_token_request(map()) -> pal_authentication:result().

%% Optional.
%%
%%	-callback access_token_request_fields(map()) -> fields().

%% ============================================================================
%% API
%% ============================================================================

-spec authorization_request(list(module()), map()) -> pal_authentication:result().
authorization_request(Hs, State) ->
	Fields = pt_modlist:callr(Hs, authorization_request_fields, [State]),
	pt_modlist:callr(Hs, authorization_request, [State#{request_fields => Fields}]).

-spec authorization_request(map()) -> pal_authentication:result().
authorization_request(State) ->
	#{authorization_uri := Uri,
		request_fields := Fields} = State,
	
	Qs = cow_qs:qs(Fields),
	RedirectUri = <<Uri/binary, $?, Qs/binary>>,
	HttpResp = pal_http:response(303, [{?LOCATION, RedirectUri}]),

	{stop, HttpResp}.

-spec authorization_request_fields(map()) -> fields().
authorization_request_fields(State) ->
	#{scope := Scope,
		client_id := ClientID,
		redirect_uri := RedirectUri} = State,

	Fields =
		[	{?RESPONSE_TYPE, ?CODE},
			{?CLIENT_ID,     ClientID},
			{?REDIRECT_URI,  RedirectUri},
			{?SCOPE,         pt_binary:join(Scope, <<$\s>>)} ],

	case maps:find(state, State) of
		{ok, ReqState} -> [{?STATE, ReqState}|Fields];
		error          -> Fields
	end.

-spec access_token_request(list(module()), map()) -> pal_authentication:result().
access_token_request(Hs, State) ->
	Fields = pt_modlist:callr(Hs, access_token_request_fields, [State]),
	pt_modlist:callr(Hs, access_token_request, [State#{request_fields => Fields}]).

-spec access_token_request(map()) -> pal_authentication:result().
access_token_request(State) ->
	#{access_token_uri := Uri,
		request_fields := Fields,
		request_options := ReqOpts} = State,

	Payload = cow_qs:qs(Fields),
	Headers = [{?CONTENT_TYPE, <<"application/x-www-form-urlencoded">>}],

	case hackney:post(Uri, Headers, Payload, ReqOpts) of
		{ok, 200, _, Ref} ->
			{ok, Body} = hackney:body(Ref),
			{ok, jsx:decode(Body)};
		{ok, 400, _, Ref} ->
			{ok, Body} = hackney:body(Ref),
			Reason = pal_oauth2:parse_error(jsx:decode(Body)),
			{error, {oauth2, Reason}};
		{ok, Status, _, _} ->
			throw({bad_resp, Status});
		{error, Reason} ->
			throw({bad_req, Reason})
	end.

-spec access_token_request_fields(map()) -> fields().
access_token_request_fields(State) ->
	#{code := Code,
		client_id := ClientID,
		client_secret := ClientSecret,
		redirect_uri := RedirectUri} = State,

	[	{?CLIENT_ID,     ClientID},
		{?CLIENT_SECRET, ClientSecret},
		{?REDIRECT_URI,  RedirectUri},
		{?CODE,          Code},
		{?GRANT_TYPE,    ?AUTHORIZATION_CODE} ].

%% ============================================================================
%% Workflow callbacks
%% ============================================================================

-spec decl() -> pal_workflow:declaration().
decl() ->
	Opts =
		#{request_options => [{follow_redirect, true}]},

	{pal_authentication, ?MODULE, Opts}.

%% ============================================================================
%% Authentication workflow callbacks
%% ============================================================================

-spec authenticate(list(module()), map(), map(), map()) -> pal_authentication:result().
authenticate(Hs, #{code := Code}, _, State) ->
	access_token_request(Hs, State#{code => Code});
authenticate(_, #{error := Error}, _, _) ->
	{error, {oauth2, #{error => pal_oauth2:parse_error_code(Error)}}};
authenticate(Hs, Data, _, State) ->
	case maps:find(state, Data) of
		{ok, ReqState} -> authorization_request(Hs, State#{state => ReqState});
		error          -> authorization_request(Hs, State)
	end.

-spec credentials(pal_authentication:rawdata(), map()) -> map().
credentials([{?ACCESS_TOKEN, Val}|T], M)  -> credentials(T, M#{access_token => Val});
credentials([{?EXPIRES_IN, Val}|T], M)    -> credentials(T, M#{expires_in => Val});
credentials([{?TOKEN_TYPE, Val}|T], M)    -> credentials(T, M#{token_type => Val});
credentials([{?REFRESH_TOKEN, Val}|T], M) -> credentials(T, M#{refresh_token => Val});
credentials([_|T], M)                     -> credentials(T, M);
credentials([], M)                        -> M.

