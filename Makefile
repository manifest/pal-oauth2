PROJECT = pal_oauth2

DEPS = pal jsx cowlib hackney
dep_pal = git git://github.com/manifest/pal.git develop
dep_jsx = git git://github.com/talentdeficit/jsx.git master
dep_cowlib = git git://github.com/ninenines/cowlib.git master
dep_hackney = git git://github.com/benoitc/hackney.git master

PLT_APPS = pt
SHELL_OPTS = \
	-eval 'application:ensure_all_started($(PROJECT), permanent)'

include erlang.mk
