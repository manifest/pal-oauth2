PROJECT = pal_oauth2

DEPS = pal jsx cowlib hackney
dep_pal = git git://github.com/manifest/pal.git v0.2.1
dep_jsx = git git://github.com/talentdeficit/jsx.git v2.4.0
dep_cowlib = git git://github.com/ninenines/cowlib.git 1.1.0
dep_hackney = git git://github.com/benoitc/hackney.git 1.0.6

PLT_APPS = pt
SHELL_OPTS = \
	-eval 'application:ensure_all_started($(PROJECT), permanent)'

include erlang.mk
