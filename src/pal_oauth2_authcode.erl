%% ------------------------------------------------------------------
%% The MIT License
%%
%% Copyright (c) 2014 Andrei Nesterov <ae.nesterov@gmail.com>
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
%% ------------------------------------------------------------------

-module(pal_oauth2_authcode).
-behaviour(pal_authentication).

%% API
-export([
	authorization_request_uri/1,
	authorization_request_parameters/1,
	access_token_request_uri/1,
	access_token_request_parameters/1,
	access_token_request/1,
	client_id/1,
	client_secret/1,
	redirect_uri/1,
	scope/1,
	code/1,
	request_state/1,
	request_options/1,
	session/1,
	state/1,
	update_state/2,
	handler/1,
	handler_state/1,
	update_handler_state/2,
	raw_info/1
]).

%% Authentication workflow callbacks
-export([
	init/1,
	authenticate/3,
	credentials/1,
	uid/1,
	info/1,
	extra/1,
	rules/1
]).

%% Definitions	
-define(CLIENT_ID, <<"client_id">>).
-define(CLIENT_SECRET, <<"client_secret">>).
-define(REDIRECT_URI, <<"redirect_uri">>).
-define(RESPONSE_TYPE, <<"response_type">>).
-define(GRANT_TYPE, <<"grant_type">>).
-define(AUTHORIZATION_CODE, <<"authorization_code">>).
-define(STATE, <<"state">>).
-define(SCOPE, <<"scope">>).
-define(CODE, <<"code">>).
-define(LOCATION, <<"location">>).

-define(ACCESS_TOKEN, <<"access_token">>).
-define(REFRESH_TOKEN, <<"refresh_token">>).
-define(TOKEN_TYPE, <<"token_type">>).
-define(EXPIRES_IN, <<"expires_in">>).

-define(CONTENT_TYPE, <<"content-type">>).

%% Types
-type workflow()   :: pal_authentication:workflow().
-type response()   :: pal_workflow:response().
-type handler(W)   :: pal_workflow:handler(W).
-type options()    :: pal_workflow:options().
-type parameters() :: [{binary(), binary()}].

-record(state, {
	client_id       :: binary(),
	client_secret   :: binary(),
	redirect_uri    :: binary(),
	scope           :: [binary()],
	code            :: binary(),

	session         :: module(),
	req_state       :: binary(),
	req_opts        :: list(),

	auth_uri        :: binary(),
	auth_params     :: parameters(),
	token_uri       :: binary(),
	token_params    :: parameters(),
	token_resp_body :: map(),

	handler         :: handler(any())
}).

-type state() :: #state{}.

-export_type([parameters/0, workflow/0]).

%% Callbacks
-callback init(Initializer) -> Handler
	when
		Initializer :: pal_workflow:initializer(),
		Handler     :: pal_workflow:handler(workflow()).

%% Optional.
%%
%%	-callback authorization_request_parameters(workflow()) -> parameters().

%% Optional.
%%
%%	-callback access_token_request_parameters(workflow()) -> parameters().

%% Optional.
%%
%%	-callback access_token_request(workflow()) -> response().

%% Optional.
%%
%%	-callback credentials(workflow()) -> map().

%% Optional.
%%
%%	-callback uid(workflow()) -> binary().

%% Optional.
%%
%%	-callback info(workflow()) -> map().

%% Optional.
%%
%%	-callback extra(workflow()) -> map().

%% Optional.
%%
%%	-callback rules(workflow()) -> map().

%% ==================================================================
%% API
%% ==================================================================

-spec authorization_request_uri(workflow()) -> binary().
authorization_request_uri(W) ->
	(state(W))#state.auth_uri.

-spec authorization_request_parameters(workflow()) -> parameters().
authorization_request_parameters(W) ->
	State = state(W),
	case State#state.auth_params of
		undefined ->
			call(authorization_request_parameters, W, fun(_) ->
				Params =
					[	{?RESPONSE_TYPE,     ?CODE},
						{?CLIENT_ID,         State#state.client_id},
						{?REDIRECT_URI,      State#state.redirect_uri},
						{?SCOPE,             pt_binary:join(State#state.scope, <<$\s>>)} ],

				case State#state.req_state of
					undefined ->
						Params;
					ReqState ->
						[{?STATE, ReqState}|Params]
				end
			end);
		Params ->
			Params
	end.

-spec access_token_request_uri(workflow()) -> binary().
access_token_request_uri(W) ->
	(state(W))#state.token_uri.

-spec access_token_request_parameters(workflow()) -> parameters().
access_token_request_parameters(W) ->
	State = state(W),
	case State#state.token_params of
		undefined ->
			call(access_token_request_parameters, W, fun(_) ->
				[	{?CLIENT_ID,     State#state.client_id},
					{?CLIENT_SECRET, State#state.client_secret},
					{?REDIRECT_URI,  State#state.redirect_uri},
					{?CODE,          State#state.code},
					{?GRANT_TYPE,    ?AUTHORIZATION_CODE} ]
			end);
		Params ->
			Params
	end.

-spec access_token_request(workflow()) -> response().
access_token_request(W) ->
	call(access_token_request, W, fun(_) ->
		Uri = access_token_request_uri(W),
		Params = access_token_request_parameters(W),
		ReqOpts = request_options(W),
		Payload = cow_qs:qs(Params),
		Headers = [{?CONTENT_TYPE, <<"application/x-www-form-urlencoded">>}],

		case hackney:post(Uri, Headers, Payload, ReqOpts) of
			{ok, 200, _, Ref} ->
				pal_oauth2:from_json(Ref, fun(M) ->
					M
				end);
			{ok, 400, _, Ref} ->
				pal_oauth2:from_json(Ref, fun(M) ->
					{fail, M}
				end);
			{ok, Status, _, _} ->
				Message = <<"Unexpected status code received from an authorization server.">>,
				error_logger:error_report([{message, Message}, {status, Status}]),
				{fail, Message};
			{error, Reason} ->
				Message = <<"Access token request failed.">>,
				error_logger:error_report([{message, Message}, {reason, Reason}]),
				{fail, Message}
		end
	end).

-spec client_id(workflow()) -> binary().
client_id(W) ->
	(state(W))#state.client_id.

-spec client_secret(workflow()) -> binary().
client_secret(W) ->
	(state(W))#state.client_secret.

-spec redirect_uri(workflow()) -> binary().
redirect_uri(W) ->
	(state(W))#state.redirect_uri.

-spec scope(workflow()) -> [binary()].
scope(W) ->
	(state(W))#state.scope.
	
-spec code(workflow()) -> binary().
code(W) ->
	(state(W))#state.code.

-spec request_state(workflow()) -> binary().
request_state(W) ->
	(state(W))#state.req_state.

-spec request_options(workflow()) -> list().
request_options(W) ->
	(state(W))#state.req_opts.

-spec session(workflow()) -> module().
session(W) ->
	(state(W))#state.session.

-spec state(workflow()) -> state().
state(W) ->
	pal_authentication:handler_state(W).

-spec update_state(fun((state()) -> state()), W) -> W when W :: workflow().
update_state(Fun, W) ->
	pal_authentication:update_handler_state(Fun, W).

-spec handler(workflow()) -> pal_workflow:handler(any()).
handler(W) ->
	(state(W))#state.handler.

-spec handler_state(workflow()) -> any().
handler_state(W) ->
	{_, HS} = handler(W),
	HS.

-spec update_handler_state(fun((any()) -> any()), workflow()) -> workflow().
update_handler_state(Fun, W) ->
	update_state(
		fun(#state{handler = {HMod, HS}} = State) ->
			State#state{handler = {HMod, Fun(HS)}}
		end, W).

-spec raw_info(workflow()) -> map().
raw_info(W) ->
	pal_authentication:raw_info(W).

%% ==================================================================
%% Authentication workflow callbacks
%% ==================================================================

-spec init({handler(any()), options()} | options()) -> handler(workflow()).
init({Handler, Opts}) ->
	RequiredBinaryParam =
		fun(Name, Params) ->
			try pt_mlist:get(Name, Params) of
				Val ->
					pt_term:to_binary(Val)
			catch
				_:_ ->
					erlang:error("Required option '" ++ pt_term:to_list(Name) ++ "' not found.")
			end
		end,
	BinaryListParam =
		fun(Name, Params) ->
			L = pt_mlist:get(Name, Params, []),
			lists:map(fun pt_term:to_binary/1, L)
		end,

	Workflow =
		#state{
			client_id = RequiredBinaryParam(client_id, Opts),
			client_secret = RequiredBinaryParam(client_secret, Opts),
			redirect_uri = RequiredBinaryParam(redirect_uri, Opts),
			scope = BinaryListParam(scope, Opts),
			session = pt_mlist:find(session, Opts),
			req_opts = pt_mlist:get(request_options, Opts, [{follow_redirect, true}]),
			auth_uri = RequiredBinaryParam(authorization_uri, Opts),
			token_uri = RequiredBinaryParam(access_token_uri, Opts),
			handler = Handler},

	pal_authentication:init({{?MODULE, Workflow}, Opts});
init(Opts) ->
	init({{undefined, undefined}, Opts}).

-spec authenticate(map(), Req, workflow()) -> {response(), Req} when Req :: cowboy_req:req().
authenticate(_, Req, W) ->
	#{code := Code, error := Error, state := ReqState} =
		cowboy_req:match_qs(
			[	{code, nonempty, undefined},
				{error, nonempty, undefined},
				{state, nonempty, undefined} ],
			Req),

	case {Code, Error} of
		{undefined, undefined} ->
			prepare_authorization_request_state(Req, W);
		{Code, undefined} ->
			W2 = update_state(fun(State) -> State#state{code = Code} end, W),
			authorization_request_state_check(ReqState, Req, W2);
		{undefined, _} ->
			authorization_request_error(Req)
	end.

-spec credentials(workflow()) -> map().
credentials(W) ->
	call(credentials, W, fun(_) ->
		RawInfo = raw_info(W),
		#{access_token  => pt_map:find(?ACCESS_TOKEN, RawInfo),
			token_type    => pt_map:find(?TOKEN_TYPE, RawInfo),
			expires_in    => pt_map:find(?EXPIRES_IN, RawInfo),
			refresh_token => pt_map:find(?REFRESH_TOKEN, RawInfo)}
	end).

-spec uid(workflow()) -> undefined | binary().
uid(W) ->
	call(uid, W).

-spec info(workflow()) -> undefined | map().
info(W) ->
	call(info, W).

-spec extra(workflow()) -> undefined | map().
extra(W) ->
	call(extra, W).

-spec rules(workflow()) -> undefined | map().
rules(W) ->
	call(rules, W).

%% ==================================================================
%% Internal functions
%% ==================================================================

-spec prepare_authorization_request_state(Req, workflow()) -> {response(), Req} when Req :: cowboy_req:req().
prepare_authorization_request_state(Req, W) ->
	case session(W) of
		undefined ->
			prepare_authorization_request(Req, W);
		Session ->
			ReqState = uuid:uuid_to_string(uuid:get_v4(), binary_nodash),
			W2 = update_state(fun(State) -> State#state{req_state = ReqState} end, W),
			Req2 = Session:put(?STATE, ReqState, Req),
			prepare_authorization_request(Req2, W2)
	end.

-spec prepare_authorization_request(Req, workflow()) -> {response(), Req} when Req :: cowboy_req:req().
prepare_authorization_request(Req, W) ->
	Params = authorization_request_parameters(W),
	W2 = update_state(fun(State) -> State#state{auth_params = Params} end, W),
	authorization_request(Req, W2).

-spec authorization_request(Req, workflow()) -> {response(), Req} when Req :: cowboy_req:req().
authorization_request(Req, W) ->
	Uri = authorization_request_uri(W),
	Params = authorization_request_parameters(W),
	Qs = cow_qs:qs(Params),
	RedirectUri = <<Uri/binary, $?, Qs/binary>>,
	
	Req2 = pal_workflow:reply(303, [{?LOCATION, RedirectUri}], session(W), Req),
	{stop, Req2}.

-spec authorization_request_error(Req) -> {response(), Req} when Req :: cowboy_req:req().
authorization_request_error(Req) ->
	ErrorM = cowboy_req:parse_qs(Req),
	{{fail, ErrorM}, Req}.

-spec authorization_request_state_check(undefined | binary(), Req, workflow()) -> {response(), Req} when Req :: cowboy_req:req().
authorization_request_state_check(ReqState, Req, W) ->
	case session(W) of
		undefined ->
			Resp = prepare_access_token_request(W),
			{Resp, Req};
		Session ->
			{SesState, Req2} = Session:find(?STATE, Req),
			case ReqState =:= SesState of
				true ->
					Req3 = Session:remove(?STATE, Req2),
					Resp = prepare_access_token_request(W),
					{Resp, Req3};
				false ->
					{{fail, <<"CSRF or an obsolete state value.">>}, Req2}
			end
	end.

-spec prepare_access_token_request(workflow()) -> response().
prepare_access_token_request(W) ->
	Params = access_token_request_parameters(W),
	W2 = update_state(fun(State) -> State#state{token_params = Params} end, W),
	access_token_request(W2).

-spec call(atom(), workflow()) -> undefined | any().
call(Function, W) ->
	{HMod, _} = handler(W),
	case erlang:function_exported(HMod, Function, 1) of
		true ->
			HMod:Function(W);
		false ->
			undefined
	end.

-spec call(atom(), workflow(), fun((workflow()) -> any())) -> any().
call(Function, W, Default) ->
	case call(Function, W) of
		undefined ->
			Default(W);
		Result ->
			Result
	end.

