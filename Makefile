PROJECT = aws
PROJECT_DESCRIPTION = RabbitMQ - AWS integration plugin
PROJECT_MOD = aws_app
PROJECT_REGISTERED = aws_sup
PROJECT_VERSION = 0.3.0

define PROJECT_ENV
[]
endef

DEPS = rabbit_common rabbit rabbitmq_management gun jose
TEST_DEPS = meck proper rabbitmq_ct_helpers rabbitmq_ct_client_helpers rabbitmq_auth_backend_ldap rabbitmq_auth_backend_http rabbitmq_auth_backend_oauth2
LOCAL_DEPS = crypto inets ssl xmerl public_key eldap

PLT_APPS = rabbit

DEP_EARLY_PLUGINS = rabbit_common/mk/rabbitmq-early-plugin.mk
DEP_PLUGINS = rabbit_common/mk/rabbitmq-plugin.mk

include ../../rabbitmq-components.mk
include ../../erlang.mk

# The optional OAuth authz-evaluation layer (aws_auth_validate_oauth_authz)
# builds the broker's #resource_server{} record and so needs oauth2.hrl at
# compile time. rabbitmq_auth_backend_oauth2 is a RUNTIME soft dependency, and
# its header is absent on older broker series (e.g. 3.13.x). Define
# HAVE_OAUTH2_RESOURCE_SERVER only when the header actually exists in the
# resolved deps dir, so the plugin still compiles where it does not (the authz
# layer is then merely unavailable at runtime via available/0). This must come
# after erlang.mk so DEPS_DIR and ERLC_OPTS are set.
OAUTH2_HRL = $(DEPS_DIR)/rabbitmq_auth_backend_oauth2/include/oauth2.hrl
ifneq ($(wildcard $(OAUTH2_HRL)),)
ERLC_OPTS += -DHAVE_OAUTH2_RESOURCE_SERVER=1
TEST_ERLC_OPTS += -DHAVE_OAUTH2_RESOURCE_SERVER=1
endif
