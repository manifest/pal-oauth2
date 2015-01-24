%% ------------------------------------------------------------------
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
%% ------------------------------------------------------------------

-module(pal_oauth2).

%% API
-export([
	parse_error/1,
	parse_error_code/1
]).

%% Definitions
-define(ERROR, <<"error">>).
-define(ERROR_DESCRIPTION, <<"error_description">>).
-define(ERROR_URI, <<"error_uri">>).
-define(STATE, <<"state">>).

%% ==================================================================
%% API
%% ==================================================================

-spec parse_error([{binary(), binary() | true}]) -> map().
parse_error(Data) ->
	parse_error(Data, #{}).

-spec parse_error([{binary(), binary() | true}], map()) -> map().
parse_error([{?ERROR, Val}|T], M)             -> parse_error(T, M#{error => parse_error_code(Val)});
parse_error([{?ERROR_DESCRIPTION, Val}|T], M) -> parse_error(T, M#{error_description => Val});
parse_error([{?ERROR_URI, Val}|T], M)         -> parse_error(T, M#{error_uri => Val});
parse_error([{?STATE, Val}|T], M)             -> parse_error(T, M#{state => Val});
parse_error([_|T], M)                         -> parse_error(T, M);
parse_error([], M)                            -> M.

-spec parse_error_code(binary()) -> atom().
parse_error_code(<<"invalid_request">>)           -> invalid_request;
parse_error_code(<<"invalid_client">>)            -> invalid_client;
parse_error_code(<<"invalid_grant">>)             -> invalid_grant;
parse_error_code(<<"invalid_scope">>)             -> invalid_scope;
parse_error_code(<<"unauthorized_client">>)       -> unauthorized_client;
parse_error_code(<<"unsupported_grant_type">>)    -> unsupported_grant_type;
parse_error_code(<<"unsupported_response_type">>) -> unsupported_response_type;
parse_error_code(<<"temporarily_unavailable">>)   -> temporarily_unavailable;
parse_error_code(<<"access_denied">>)             -> access_denied;
parse_error_code(<<"server_error">>)              -> server_error;
parse_error_code(_)                               -> other_oauth2_error.

