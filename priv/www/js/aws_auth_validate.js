// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// vim:ft=javascript:
// -*- mode: javascript; -*-

// Management-console UI for the AWS auth-validation endpoint
//   PUT /api/aws/auth/validate/:method
//
// The endpoint returns a fixed, category-only result (never raw backend detail,
// per the endpoint's R4 invariant): 204 success, or 4xx/5xx with a JSON body
// {error: <category>, message: <fixed text>}. This UI submits a per-method form
// as a JSON body and renders that category as a friendly banner. Operators can
// also paste/edit the request in rabbitmq.conf dotted-key form (the same lines
// as the tutorials); the UI converts between that and the JSON wire body. It
// never puts secrets (password_arn, client_secret, ARNs) in the URL/hash or
// localStorage.

dispatcher_add(function(sammy) {
    sammy.get('#/auth-validate', function() {
        // Fresh page: no config has been validated yet in this view. render() is
        // async (it fetches + injects the template), so the actual preview
        // priming happens in aws_auth_validate_on_render, invoked by an inline
        // script at the bottom of the template once the DOM exists.
        AWS_AUTH_VALIDATE_LAST_VALID = null;
        render({}, 'aws_auth_validate', '#/auth-validate');
    });
});

// Invoked by the template's inline script after the console injects it. Sets the
// preview placeholder to the full field template for the initially-selected
// method so every possible field is visible up front as a hint.
function aws_auth_validate_on_render() {
    AWS_AUTH_VALIDATE_LAST_VALID = null;
    aws_auth_validate_config_status('', '');
    aws_auth_validate_show_template($('#aws-auth-validate-method').val());
}

// Admin-gated tab. The tag matches the endpoint's default required_user_tag
// (administrator). This is a client-side visibility hint only; the endpoint's
// is_authorized/2 remains the authoritative gate, and an operator who lowers
// aws.auth_validation.required_user_tag does not change this hint.
NAVIGATION['Admin'][0]['Auth Validation'] = ['#/auth-validate', "administrator"];

// The four methods and the request-body fields each accepts. Field names mirror
// the backend allowed_fields/0 exactly; the registry filters the body to these,
// so an unknown field is silently dropped rather than rejected.
var AWS_AUTH_VALIDATE_METHODS = ['ldap', 'http', 'oauth', 'tls'];

// Human-readable copy for each fixed response category the endpoint can return.
// Keyed by the `error` value in the JSON body (plus synthetic keys for the
// success and transport cases). Kept in one place so the .ejs and the banner
// stay in sync.
var AWS_AUTH_VALIDATE_CATEGORY = {
    success:            {cls: 'status-green',  text: 'Validation succeeded (204).'},
    input_invalid:      {cls: 'status-red',    text: 'Input invalid: the request failed pure validation before any connection.'},
    body_too_large:     {cls: 'status-red',    text: 'Request body too large: reduce the config size and retry.'},
    connection_failed:  {cls: 'status-red',    text: 'Connection failed: the target could not be reached.'},
    tls_failed:         {cls: 'status-red',    text: 'TLS failed: handshake or certificate verification did not succeed.'},
    query_invalid:      {cls: 'status-red',    text: 'Query invalid: an authorization query could not be parsed.'},
    auth_failed:        {cls: 'status-yellow', text: 'Auth failed: the server was reached but did not authenticate/respond as expected.'},
    token_invalid:      {cls: 'status-red',    text: 'Token invalid: the supplied access token failed signature verification, or no fetched JWKS key matched its key id -- the broker would also reject it.'},
    token_expired:      {cls: 'status-yellow', text: 'Token expired: the supplied access token is past its exp (transient -- re-mint the token and retry).'},
    config_conflict:    {cls: 'status-yellow', text: 'Config conflict: the supplied options are mutually inconsistent (for example an ARN is referenced with no assume_role configured, or an authorization check was requested but the oauth2 backend is not loaded on this broker).'},
    authz_unverified:   {cls: 'status-yellow', text: 'Authorization unverified: the token is authentic but the requested permission could not be confirmed on the vhost/resource. Check scope_prefix, resource_server_id, additional_scopes_key, and scope_aliases.'},
    method_disabled:    {cls: 'status-yellow', text: 'Method disabled: enable it with aws.auth_validation.enabled_methods.<method> = true (every method is opt-in).'},
    unknown_method:     {cls: 'status-red',    text: 'Unknown method.'},
    insufficient_user_tag: {cls: 'status-red', text: 'Your user lacks the tag required to call this endpoint.'},
    capacity_exhausted: {cls: 'status-yellow', text: 'Service at capacity or not ready. Try again shortly.'},
    internal_error:     {cls: 'status-red',    text: 'Internal error during validation.'},
    transport_error:    {cls: 'status-red',    text: 'Could not reach the management API.'}
};

// Read the visible method form into a JSON request body. Only non-empty fields
// are included so an omitted optional field keeps the backend default; ARN
// fields nest under ssl_options to match the backend shape.
//
// The scan is scoped to the SELECTED method's container (#aws-av-fields-<method>),
// never the whole form: each method's ssl_options key set differs, and switching
// methods only HIDES the other groups, so a whole-form scan would merge a hidden
// method's values in and produce foreign keys the backend rejects.
function aws_auth_validate_build_body(method) {
    var body = {};
    var $scope = $('#aws-av-fields-' + method);

    // Flat top-level fields for THIS method. A checkbox contributes a boolean
    // true only when checked (an unchecked box is omitted so the backend keeps
    // its default); every other input contributes its non-empty value.
    $scope.find('[data-av-field]').each(function() {
        var el = $(this);
        var key = el.attr('data-av-field');
        if (el.is(':checkbox')) {
            if (el.is(':checked')) { body[key] = true; }
        } else {
            var val = el.val();
            if (val !== null && val !== undefined && ('' + val).length > 0) {
                body[key] = val;
            }
        }
    });

    // servers is a space-separated list for the ldap method.
    if (method === 'ldap' && typeof body.servers === 'string') {
        body.servers = body.servers.split(/\s+/).filter(function(s) { return s.length > 0; });
    }
    // port is an integer.
    if (typeof body.port === 'string' && body.port.length > 0) {
        var p = parseInt(body.port, 10);
        if (!isNaN(p)) { body.port = p; } else { delete body.port; }
    }

    // ssl_options sub-object, collected from THIS method's ssl sub-fields only.
    var ssl = {};
    $scope.find('[data-av-ssl]').each(function() {
        var key = $(this).attr('data-av-ssl');
        var el = $(this);
        var val = el.is(':checkbox') ? el.is(':checked') : el.val();
        if (el.is(':checkbox')) {
            if (val) { ssl[key] = true; }
        } else if (val !== null && val !== undefined && ('' + val).length > 0) {
            ssl[key] = val;
        }
    });
    if (Object.keys(ssl).length > 0) {
        body.ssl_options = ssl;
    }

    // LDAP authorization queries: a map of {query_name: dsl_string} assembled
    // from the four data-av-query textareas. Each value is sent as a raw DSL
    // string; the backend parses it (query_invalid on failure) and, when a
    // username was supplied, evaluates it for that principal. An empty box
    // contributes no entry so the backend keeps that query unset.
    if (method === 'ldap') {
        var queries = aws_auth_validate_build_queries($scope);
        if (Object.keys(queries).length > 0) {
            body.queries = queries;
        }
    }

    // OAuth authorization-evaluation layer. The generic loop above collected the
    // scalar authz-config fields (scope_prefix, additional_scopes_key,
    // scope_pattern_syntax) as-is. Two shapes need building by hand: scope_aliases
    // is a map the backend expects as {alias: [scopes]} (entered as lines here),
    // and authz_check is assembled from its own data-av-authz inputs. Everything
    // here is optional -- an empty permission means "no authz check", matching the
    // backend, which treats authz_check as absent unless a check block is present.
    if (method === 'oauth') {
        if (typeof body.scope_aliases === 'string') {
            var aliases = aws_auth_validate_parse_scope_aliases(body.scope_aliases);
            if (aliases && Object.keys(aliases).length > 0) {
                body.scope_aliases = aliases;
            } else {
                // Blank or comment-only text: omit the field entirely so the
                // backend keeps its default rather than seeing an empty object.
                delete body.scope_aliases;
            }
        }
        var authz = aws_auth_validate_build_authz_check($scope);
        if (authz !== null) {
            body.authz_check = authz;
        }
    }
    return body;
}

// Assemble the LDAP `queries` map from the four data-av-query textareas within
// the ldap field group. Each non-empty box contributes {query_name: dsl_string}
// where the value is the raw DSL text (trimmed); the backend parses and, when a
// username is present, evaluates it. An empty box is omitted so the backend
// keeps that query unset. The DSL string is sent verbatim -- the backend owns
// the grammar (query_invalid on a parse failure), so the UI does not pre-parse.
function aws_auth_validate_build_queries($scope) {
    var queries = {};
    $scope.find('[data-av-query]').each(function() {
        var el = $(this);
        var name = el.attr('data-av-query');
        var val = ('' + el.val()).trim();
        if (val.length > 0) { queries[name] = val; }
    });
    return queries;
}

// Parse the scope_aliases textarea (one "alias = scope1 scope2 ..." per line)
// into the map shape the backend requires: {alias: [scope, ...]}. Blank lines
// and #-comment lines are ignored. A line with no '=' or no scopes is skipped
// (the backend rejects a malformed scope_aliases with input_invalid; we simply
// do not emit an ill-formed entry, so the operator sees their real typo rather
// than a silently-mangled value). Values are kept case-sensitive.
function aws_auth_validate_parse_scope_aliases(text) {
    var out = {};
    var lines = ('' + text).split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (line.length === 0 || line.charAt(0) === '#') { continue; }
        var eq = line.indexOf('=');
        if (eq === -1) { continue; }
        var alias = line.substring(0, eq).trim();
        var scopes = line.substring(eq + 1).trim().split(/\s+/)
            .filter(function(s) { return s.length > 0; });
        if (alias.length === 0 || scopes.length === 0) { continue; }
        out[alias] = scopes;
    }
    return out;
}

// Assemble the authz_check object from its form inputs. Returns null when no
// permission is selected (the check is opt-in: no permission means the operator
// is not asking for an authorization decision, so the field is omitted and the
// backend runs reachability + token verification only). vhost is omitted when
// blank so the backend applies its documented default ("/").
function aws_auth_validate_build_authz_check($form) {
    var perm = $form.find('[data-av-authz="permission"]').val();
    if (!perm || ('' + perm).length === 0) { return null; }
    var check = {permission: perm};
    var resource = $form.find('[data-av-authz="resource"]').val();
    if (resource !== null && resource !== undefined && ('' + resource).length > 0) {
        check.resource = resource;
    }
    var vhost = $form.find('[data-av-authz="vhost"]').val();
    if (vhost !== null && vhost !== undefined && ('' + vhost).length > 0) {
        check.vhost = vhost;
    }
    return check;
}

// The JSON body that most recently returned 204, as a normalized string. Used
// so the "Copy config" button can tell the operator whether the text they are
// about to copy is still the exact body that passed validation, or whether they
// have edited it since. Reset on every render (see the sammy route).
var AWS_AUTH_VALIDATE_LAST_VALID = null;

// Populate the visible method form from a request-body object -- the inverse of
// aws_auth_validate_build_body. Existing field values for the method are cleared
// first so the form reflects exactly what is in the object (no stale leftovers).
// A "method" key, if present, selects the matching method tab and is not treated
// as a form field (the real endpoint takes the method from the URL, not the body).
function aws_auth_validate_populate_form(method, body) {
    var $scope = $('#aws-av-fields-' + method);

    // Fields with no rabbitmq.conf representation (oauth scope_aliases /
    // authz_check, ldap username / queries) carry runtime validation intent the
    // pasted conf knows nothing about. A parse must NOT silently wipe them, so
    // snapshot their current values and restore them after the clear-and-
    // repopulate below.
    var preservedNonConf = aws_auth_validate_snapshot_nonconf(method);

    // Clear the selected method's fields and its own ssl_options. Both scans are
    // scoped to this method's group: ssl inputs now live per-method (the key set
    // differs per backend), so a form-wide clear would wipe another method's
    // values.
    $scope.find('[data-av-field]').each(function() {
        var el = $(this);
        if (el.is(':checkbox')) { el.prop('checked', false); } else { el.val(''); }
    });
    $scope.find('[data-av-ssl]').each(function() {
        var el = $(this);
        if (el.is(':checkbox')) { el.prop('checked', false); } else { el.val(''); }
    });
    aws_auth_validate_restore_nonconf(method, preservedNonConf);

    if (!body || typeof body !== 'object') { return; }

    var ssl = (body.ssl_options && typeof body.ssl_options === 'object') ? body.ssl_options : {};

    // Top-level fields for the selected method.
    $scope.find('[data-av-field]').each(function() {
        var el = $(this);
        var key = el.attr('data-av-field');
        if (!Object.prototype.hasOwnProperty.call(body, key)) { return; }
        var val = body[key];
        if (el.is(':checkbox')) {
            el.prop('checked', val === true || val === 'true');
        } else if (key === 'servers' && $.isArray(val)) {
            el.val(val.join(' '));
        } else if (val !== null && val !== undefined) {
            el.val('' + val);
        }
    });

    // This method's ssl_options sub-fields.
    $scope.find('[data-av-ssl]').each(function() {
        var el = $(this);
        var key = el.attr('data-av-ssl');
        if (!Object.prototype.hasOwnProperty.call(ssl, key)) { return; }
        var val = ssl[key];
        if (el.is(':checkbox')) {
            el.prop('checked', val === true || val === 'true');
        } else if (val !== null && val !== undefined) {
            el.val('' + val);
        }
    });
}

// Mapping between rabbitmq.conf dotted keys (what operators paste from the
// tutorials) and the endpoint's request-body fields. The conf format is NOT 1:1
// with the request body -- e.g. the user DN lives at auth_ldap.dn_lookup_bind.user_dn
// in conf but is just "user_dn" in the body, and secret/cert ARNs are namespaced
// under aws.arns.* -- so each method carries an explicit table.
//
// Each entry maps an exact (lower-cased) conf key to a body descriptor:
//   path: nested location in the request body
//   type: 'string' | 'int' | 'bool' (drives parsing and rendering)
// `list` handles the indexed server list (auth_ldap.servers.1, .2, ...).
// `formOnly` lists fields that have no rabbitmq.conf representation (a runtime
// access token, a listener name) -- they are collected from the form but never
// emitted into or read from the conf text.
// The `ex` on each descriptor is a placeholder example used only to build the
// editable template shown in the preview (see aws_auth_validate_template). It is
// never sent -- the operator replaces it before validating.
var AWS_AUTH_VALIDATE_CONF = {
    ldap: {
        backend: 'ldap',
        list: {re: /^auth_ldap\.servers\.\d+$/, idxRe: /\.(\d+)$/, path: ['servers'], keyBase: 'auth_ldap.servers', ex: 'ldap.example.com'},
        map: {
            'auth_ldap.port':                                   {path: ['port'], type: 'int', ex: '636'},
            'auth_ldap.use_ssl':                                {path: ['use_ssl'], type: 'bool', ex: 'true'},
            'auth_ldap.use_starttls':                           {path: ['use_starttls'], type: 'bool', ex: 'false'},
            'auth_ldap.dn_lookup_bind.user_dn':                 {path: ['user_dn'], type: 'string', ex: 'cn=admin,dc=example,dc=com'},
            'auth_ldap.dn_lookup_base':                         {path: ['dn_lookup_base'], type: 'string', ex: 'dc=example,dc=com'},
            'auth_ldap.dn_lookup_attribute':                    {path: ['dn_lookup_attribute'], type: 'string', ex: 'sAMAccountName'},
            'auth_ldap.ssl_options.verify':                     {path: ['ssl_options', 'verify'], type: 'string', ex: 'verify_peer'},
            // LDAP's ssl_options accepts server_name_indication (NOT sni) and has
            // no client-cert/mTLS material, so no certfile/keyfile ARN lines.
            'auth_ldap.ssl_options.server_name_indication':     {path: ['ssl_options', 'server_name_indication'], type: 'string', ex: 'ldap.example.com'},
            // Mirrors the broker's auth_ldap.ssl_options.hostname_verification
            // (wildcard|none); unset means strict OTP matching. Modeled so the
            // validator matches the broker's hostname check rather than always
            // using the lenient wildcard fun.
            'auth_ldap.ssl_options.hostname_verification':      {path: ['ssl_options', 'hostname_verification'], type: 'string', ex: 'wildcard'},
            'aws.arns.auth_ldap.dn_lookup_bind.password':       {path: ['password_arn'], type: 'string', ex: 'arn:aws:secretsmanager:us-west-2:111122223333:secret:RabbitMqDnLookupUserPassword'},
            'aws.arns.auth_ldap.ssl_options.cacertfile':        {path: ['ssl_options', 'cacertfile_arn'], type: 'string', ex: 'arn:aws:s3:::my-bucket/ca-cert.pem'}
        },
        formOnly: []
    },
    http: {
        backend: 'http',
        map: {
            'auth_http.user_path':                              {path: ['user_path'], type: 'string', ex: 'https://auth.example.com/auth/user'},
            'auth_http.vhost_path':                             {path: ['vhost_path'], type: 'string', ex: 'https://auth.example.com/auth/vhost'},
            'auth_http.resource_path':                          {path: ['resource_path'], type: 'string', ex: 'https://auth.example.com/auth/resource'},
            'auth_http.topic_path':                             {path: ['topic_path'], type: 'string', ex: 'https://auth.example.com/auth/topic'},
            'auth_http.http_method':                            {path: ['http_method'], type: 'string', ex: 'post'},
            // The ssl_options entries below match the oauth ssl_options entries
            // key-for-key; keep the two hand-synced on any change. Only the
            // conf-key PREFIX differs: http uses auth_http.ssl_options.*, while
            // oauth uses auth_oauth2.ssl_options.* EXCEPT hostname_verification,
            // which the broker spells auth_oauth2.https.hostname_verification.
            'auth_http.ssl_options.verify':                     {path: ['ssl_options', 'verify'], type: 'string', ex: 'verify_peer'},
            'auth_http.ssl_options.sni':                        {path: ['ssl_options', 'sni'], type: 'string', ex: 'auth.example.com'},
            // Mirrors the broker's auth_http.ssl_options.hostname_verification
            // (wildcard|none); unset means strict OTP matching. Modeled so the
            // validator matches the broker's hostname check rather than always
            // using the lenient wildcard fun.
            'auth_http.ssl_options.hostname_verification':      {path: ['ssl_options', 'hostname_verification'], type: 'string', ex: 'wildcard'},
            'aws.arns.auth_http.ssl_options.cacertfile':        {path: ['ssl_options', 'cacertfile_arn'], type: 'string', ex: 'arn:aws:s3:::my-bucket/ca-cert.pem'},
            'aws.arns.auth_http.ssl_options.certfile':          {path: ['ssl_options', 'certfile_arn'], type: 'string', ex: 'arn:aws:s3:::my-bucket/client-cert.pem'},
            'aws.arns.auth_http.ssl_options.keyfile':           {path: ['ssl_options', 'keyfile_arn'], type: 'string', ex: 'arn:aws:secretsmanager:us-west-2:111122223333:secret:RabbitMqClientKey'}
        },
        formOnly: []
    },
    oauth: {
        backend: 'oauth2',
        map: {
            'auth_oauth2.jwks_uri':                             {path: ['jwks_uri'], type: 'string', ex: 'https://idp.example.com/.well-known/jwks.json'},
            'auth_oauth2.issuer':                               {path: ['issuer'], type: 'string', ex: 'https://idp.example.com/'},
            'auth_oauth2.resource_server_id':                   {path: ['resource_server_id'], type: 'string', ex: 'rabbitmq'},
            'auth_oauth2.scope_prefix':                         {path: ['scope_prefix'], type: 'string', ex: 'rabbitmq.'},
            'auth_oauth2.additional_scopes_key':               {path: ['additional_scopes_key'], type: 'string', ex: 'roles'},
            'auth_oauth2.scope_pattern_syntax':                 {path: ['scope_pattern_syntax'], type: 'string', ex: 'wildcard'},
            'auth_oauth2.ssl_options.verify':                   {path: ['ssl_options', 'verify'], type: 'string', ex: 'verify_peer'},
            'auth_oauth2.ssl_options.sni':                      {path: ['ssl_options', 'sni'], type: 'string', ex: 'idp.example.com'},
            // The broker spells this one auth_oauth2.https.hostname_verification
            // (NOT under ssl_options), but it maps to the same request field
            // (wildcard|none); unset means strict OTP matching.
            'auth_oauth2.https.hostname_verification':          {path: ['ssl_options', 'hostname_verification'], type: 'string', ex: 'wildcard'},
            'aws.arns.auth_oauth2.ssl_options.cacertfile':      {path: ['ssl_options', 'cacertfile_arn'], type: 'string', ex: 'arn:aws:s3:::my-bucket/ca-cert.pem'},
            'aws.arns.auth_oauth2.ssl_options.certfile':        {path: ['ssl_options', 'certfile_arn'], type: 'string', ex: 'arn:aws:s3:::my-bucket/client-cert.pem'},
            'aws.arns.auth_oauth2.ssl_options.keyfile':         {path: ['ssl_options', 'keyfile_arn'], type: 'string', ex: 'arn:aws:secretsmanager:us-west-2:111122223333:secret:RabbitMqClientKey'}
        },
        // access_token is a runtime bearer token, never part of rabbitmq.conf.
        formOnly: ['access_token'],
        notes: ['# access_token: paste it into the "Access token" form field above (a runtime token, not a rabbitmq.conf key).']
    },
    tls: {
        // TLS validation targets a broker listener; the mTLS/SSL tutorials
        // configure ssl_options at the top level (no auth_<backend> prefix).
        // The material is inbound-listener trust config: cacertfile_arn, verify,
        // and fail_if_no_peer_cert only -- no sni and no client cert/key (the
        // server cert is AWS-managed).
        backend: null,
        map: {
            'ssl_options.verify':                               {path: ['ssl_options', 'verify'], type: 'string', ex: 'verify_peer'},
            'ssl_options.fail_if_no_peer_cert':                 {path: ['ssl_options', 'fail_if_no_peer_cert'], type: 'bool', ex: 'true'},
            'aws.arns.ssl_options.cacertfile':                  {path: ['ssl_options', 'cacertfile_arn'], type: 'string', ex: 'arn:aws:s3:::my-bucket/ca-cert.pem'}
        },
        // `target` names the listener under test; it is a validation concept,
        // not a rabbitmq.conf key.
        formOnly: ['target'],
        notes: ['# target: enter "listener" or "management" in the "Target" form field above (a validation concept, not a rabbitmq.conf key).']
    }
};

// aws.arns.assume_role_arn is read from BROKER config, never from the request
// body: accepting a request-supplied role would let one call swap the broker's
// AWS credentials (confused-deputy). We recognize the key so we can tell the
// operator we skipped it, and never place it in the request body.
var AWS_AUTH_VALIDATE_ASSUME_ROLE_KEY = 'aws.arns.assume_role_arn';

// Set a nested value at obj[path[0]][path[1]]..., creating objects as needed.
function aws_auth_validate_set_path(obj, path, val) {
    var cur = obj;
    for (var i = 0; i < path.length - 1; i++) {
        if (typeof cur[path[i]] !== 'object' || cur[path[i]] === null) {
            cur[path[i]] = {};
        }
        cur = cur[path[i]];
    }
    cur[path[path.length - 1]] = val;
}

// Read a nested value; returns undefined if any segment is missing.
function aws_auth_validate_get_path(obj, path) {
    var cur = obj;
    for (var i = 0; i < path.length; i++) {
        if (cur === null || typeof cur !== 'object' ||
            !Object.prototype.hasOwnProperty.call(cur, path[i])) {
            return undefined;
        }
        cur = cur[path[i]];
    }
    return cur;
}

// Coerce a raw conf value string to the descriptor's type. Only the value is
// treated case-sensitively (ARNs, DNs); the KEY is lower-cased by the caller.
function aws_auth_validate_coerce(type, raw) {
    if (type === 'int') {
        var n = parseInt(raw, 10);
        return isNaN(n) ? undefined : n;
    }
    if (type === 'bool') {
        var l = raw.toLowerCase();
        if (l === 'true') { return true; }
        if (l === 'false') { return false; }
        return undefined;
    }
    return raw;
}

// Parse rabbitmq.conf dotted-key text into a request body for `method`.
// Returns {body, servers, skippedAssumeRole, unknown} where `unknown` counts
// recognized-but-not-applicable lines (e.g. keys for a different method).
// Comment (#) and blank lines are ignored. auth_backends.* lines are ignored
// (the endpoint takes the method from the URL). Unknown keys are counted, not
// rejected -- the operator may paste a fuller config than one method uses.
function aws_auth_validate_conf_to_body(method, text) {
    var spec = AWS_AUTH_VALIDATE_CONF[method];
    var body = {};
    var servers = {};
    var skippedAssumeRole = false;
    var unknown = 0;
    var lines = ('' + text).split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (line.length === 0 || line.charAt(0) === '#') { continue; }
        var eq = line.indexOf('=');
        if (eq === -1) { unknown++; continue; }
        var key = line.substring(0, eq).trim().toLowerCase();
        var val = line.substring(eq + 1).trim();
        if (key === AWS_AUTH_VALIDATE_ASSUME_ROLE_KEY) { skippedAssumeRole = true; continue; }
        if (key.indexOf('auth_backends.') === 0 || key === 'auth_backends') { continue; }
        if (spec.list && spec.list.re.test(key)) {
            var m = key.match(spec.list.idxRe);
            var idx = m ? parseInt(m[1], 10) : (Object.keys(servers).length + 1);
            servers[idx] = val;
            continue;
        }
        var desc = spec.map[key];
        if (!desc) { unknown++; continue; }
        var coerced = aws_auth_validate_coerce(desc.type, val);
        if (coerced !== undefined) { aws_auth_validate_set_path(body, desc.path, coerced); }
    }
    // Assemble the indexed server list in numeric order.
    var idxs = Object.keys(servers).map(Number).sort(function(a, b) { return a - b; });
    if (idxs.length > 0) {
        body.servers = idxs.map(function(k) { return servers[k]; })
                           .filter(function(s) { return ('' + s).length > 0; });
    }
    return {body: body, skippedAssumeRole: skippedAssumeRole, unknown: unknown};
}

// Render a request body back into rabbitmq.conf dotted-key text for `method`.
// Emits an auth_backends header (except tls, which has no auth backend), then
// each mapped key that is present in the body, in table order. Booleans render
// true/false; the server list expands to auth_ldap.servers.N lines.
function aws_auth_validate_body_to_conf(method, body) {
    var spec = AWS_AUTH_VALIDATE_CONF[method];
    var out = [];
    if (spec.backend) { out.push('auth_backends.1 = ' + spec.backend); }
    // Server list first (mirrors the tutorial ordering).
    if (spec.list && $.isArray(body.servers)) {
        for (var s = 0; s < body.servers.length; s++) {
            out.push(spec.list.keyBase + '.' + (s + 1) + ' = ' + body.servers[s]);
        }
    }
    for (var key in spec.map) {
        if (!Object.prototype.hasOwnProperty.call(spec.map, key)) { continue; }
        var desc = spec.map[key];
        var v = aws_auth_validate_get_path(body, desc.path);
        if (v === undefined || v === null || ('' + v).length === 0) { continue; }
        if (desc.type === 'bool') { v = v ? 'true' : 'false'; }
        out.push(key + ' = ' + v);
    }
    return out.join('\n');
}

// Merge form values into EXISTING rabbitmq.conf text, touching only the keys
// this method's form manages and preserving everything else verbatim (comments,
// blank lines, non-auth config, aws.arns.assume_role_arn, and keys belonging to
// other methods). This is what "Update config from fields" uses so it does not
// wipe unrelated lines.
//
// Rules:
//  - A managed scalar key with a non-empty form value updates the existing line
//    in place (keeping its original indentation and key text), or is appended if
//    absent.
//  - A managed key the form left empty is NOT removed -- the existing line, if
//    any, is preserved untouched.
//  - The server list (auth_ldap.servers.N) is treated as one managed block: when
//    the form has servers, the run of existing server lines is replaced in place
//    with the form's set; when the form has none, existing server lines are kept.
//  - An auth_backends header is added only if the method has a backend and no
//    auth_backends line exists at all (never rewrites an operator's header).
function aws_auth_validate_merge_conf(method, existingText, body) {
    var spec = AWS_AUTH_VALIDATE_CONF[method];

    // Desired scalar key -> rendered value, for managed keys the form supplies.
    // remove holds boolean keys the form does NOT supply: an unchecked checkbox
    // is omitted from the body, and for booleans that means "off", so any stale
    // line for it must be dropped rather than preserved. (Empty string/int fields
    // are left absent from both maps and preserved verbatim below, so we never
    // wipe config the operator did not touch.)
    var desired = {};
    var remove = {};
    for (var key in spec.map) {
        if (!Object.prototype.hasOwnProperty.call(spec.map, key)) { continue; }
        var desc = spec.map[key];
        var v = aws_auth_validate_get_path(body, desc.path);
        if (v === undefined || v === null || ('' + v).length === 0) {
            if (desc.type === 'bool') { remove[key.toLowerCase()] = true; }
            continue;
        }
        if (desc.type === 'bool') { v = v ? 'true' : 'false'; }
        desired[key.toLowerCase()] = {canonical: key, value: '' + v};
    }

    // Desired server lines (only when the form actually has servers).
    var hasServers = spec.list && $.isArray(body.servers) && body.servers.length > 0;
    var serverLines = [];
    if (hasServers) {
        for (var s = 0; s < body.servers.length; s++) {
            serverLines.push(spec.list.keyBase + '.' + (s + 1) + ' = ' + body.servers[s]);
        }
    }

    var lines = ('' + existingText).split(/\r?\n/);
    var out = [];
    var seen = {};
    var serverBlockEmitted = false;
    var sawAuthBackends = false;

    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        var trimmed = line.trim();
        // Preserve comments, blank lines, and anything without '=' verbatim.
        if (trimmed.length === 0 || trimmed.charAt(0) === '#') { out.push(line); continue; }
        var eq = trimmed.indexOf('=');
        if (eq === -1) { out.push(line); continue; }
        var k = trimmed.substring(0, eq).trim().toLowerCase();

        if (k.indexOf('auth_backends.') === 0 || k === 'auth_backends') {
            sawAuthBackends = true;
            out.push(line);
            continue;
        }

        // Server-list line: replace the whole run once with the form's servers.
        if (spec.list && spec.list.re.test(k)) {
            if (hasServers) {
                if (!serverBlockEmitted) {
                    for (var j = 0; j < serverLines.length; j++) { out.push(serverLines[j]); }
                    serverBlockEmitted = true;
                }
                // Drop the original server line (replaced by the block above).
            } else {
                // Form has no servers -- leave the existing line untouched.
                out.push(line);
            }
            continue;
        }

        // Managed scalar key the form supplies: update the FIRST occurrence in
        // place, keeping the operator's original indentation and key spelling.
        if (Object.prototype.hasOwnProperty.call(desired, k) && !seen[k]) {
            var leadingWs = line.match(/^\s*/)[0];
            var origKey = trimmed.substring(0, eq).trim();
            out.push(leadingWs + origKey + ' = ' + desired[k].value);
            seen[k] = true;
            continue;
        }
        // A LATER duplicate of a managed key we already updated: drop it. cuttlefish
        // is last-wins, so a stale duplicate left after the updated line would
        // override our value at config-load time -- the exact silent-drift this
        // sync is meant to prevent. Only managed keys are de-duplicated; unrelated
        // duplicate config is none of our business and is preserved below.
        if (Object.prototype.hasOwnProperty.call(desired, k) && seen[k]) {
            continue;
        }

        // Managed boolean key the form left unchecked ("off"): drop the stale
        // line so unchecking (e.g. use_starttls) removes it from the config.
        if (Object.prototype.hasOwnProperty.call(remove, k)) {
            continue;
        }

        // Any other line (unrelated config, another method's keys, a managed
        // string/int key the form left empty, assume_role) is preserved verbatim.
        out.push(line);
    }

    // Append managed keys the form supplied that were not already present, in
    // table order. Prepend an auth_backends header if none existed.
    var appended = [];
    if (spec.backend && !sawAuthBackends) {
        appended.push('auth_backends.1 = ' + spec.backend);
    }
    if (hasServers && !serverBlockEmitted) {
        for (var a = 0; a < serverLines.length; a++) { appended.push(serverLines[a]); }
    }
    for (var mkey in spec.map) {
        if (!Object.prototype.hasOwnProperty.call(spec.map, mkey)) { continue; }
        var lk = mkey.toLowerCase();
        if (Object.prototype.hasOwnProperty.call(desired, lk) && !seen[lk]) {
            appended.push(mkey + ' = ' + desired[lk].value);
            seen[lk] = true;
        }
    }

    if (appended.length > 0) {
        // Separate appended keys from preserved content with a blank line, unless
        // the existing text is empty or already ends blank.
        while (out.length > 0 && out[out.length - 1].trim().length === 0) { out.pop(); }
        if (out.length > 0) { out.push(''); }
        out = out.concat(appended);
    }

    return out.join('\n');
}

// Overlay form-only fields (those with no rabbitmq.conf key -- oauth access_token,
// tls target) onto a body parsed from conf text, so a value typed into the form
// is not lost when the textarea drives the request.
function aws_auth_validate_overlay_form_only(method, body) {
    var spec = AWS_AUTH_VALIDATE_CONF[method];
    var fields = spec.formOnly || [];
    for (var i = 0; i < fields.length; i++) {
        var key = fields[i];
        if (Object.prototype.hasOwnProperty.call(body, key)) { continue; }
        var el = $('#aws-av-fields-' + method).find('[data-av-field="' + key + '"]');
        if (el.length === 0) { continue; }
        var val = el.is(':checkbox') ? el.is(':checked') : el.val();
        if (el.is(':checkbox')) {
            if (val) { body[key] = true; }
        } else if (val !== null && val !== undefined && ('' + val).length > 0) {
            body[key] = val;
        }
    }
}

// Body fields that have NO rabbitmq.conf representation and so must be ignored
// when comparing the fields against the conf box (they can only ever live in the
// form):
//   * oauth scope_aliases (encoded in conf as dynamic sub-keys, not a single
//     line) and authz_check (a runtime validation concept, never broker config).
//   * ldap username (a runtime principal identifier, not config) and queries
//     (the conf map has no auth_ldap.queries.* entries, so the query DSL is only
//     ever entered in the form).
// access_token / target are already handled via formOnly + overlay, so they are
// not repeated here. Returns a shallow copy with these keys removed.
var AWS_AUTH_VALIDATE_NONCONF_FIELDS = {
    oauth: ['scope_aliases', 'authz_check'],
    ldap: ['username', 'queries']
};
function aws_auth_validate_strip_nonconf(method, body) {
    var drop = AWS_AUTH_VALIDATE_NONCONF_FIELDS[method] || [];
    if (drop.length === 0 || !body || typeof body !== 'object') { return body; }
    var out = {};
    for (var k in body) {
        if (!Object.prototype.hasOwnProperty.call(body, k)) { continue; }
        if (drop.indexOf(k) !== -1) { continue; }
        out[k] = body[k];
    }
    return out;
}

// Return a copy of `body` with any key whose value is boolean `false` removed,
// descending one level into ssl_options. Used ONLY to normalize the divergence
// comparison (see the submit handler): to every backend an absent boolean equals
// an explicit `false', so an unchecked box (key omitted) and a pasted `= false'
// (key present as false) must compare equal. This applies to nested ssl_options
// booleans too -- the tls method's ssl_options.fail_if_no_peer_cert is a checkbox
// that omits the key when unchecked but parses to `false' when pasted, so without
// recursing it would read as a false divergence. An ssl_options object emptied by
// stripping is dropped so it matches a fields side that never set it. Non-boolean
// values and `true' are left as-is, so this never masks a real difference.
function aws_auth_validate_strip_false_bools(body) {
    if (!body || typeof body !== 'object') { return body; }
    var out = {};
    for (var k in body) {
        if (!Object.prototype.hasOwnProperty.call(body, k)) { continue; }
        if (body[k] === false) { continue; }
        if (k === 'ssl_options' && body[k] && typeof body[k] === 'object') {
            var ssl = aws_auth_validate_strip_false_bools(body[k]);
            if (Object.keys(ssl).length > 0) { out[k] = ssl; }
            continue;
        }
        out[k] = body[k];
    }
    return out;
}

// The DOM inputs backing the non-conf fields for a method. Snapshot/restore lets
// "Parse into fields" reload the conf-backed fields without discarding work the
// pasted conf cannot express:
//   * oauth: the scope_aliases textarea (a data-av-field with no conf key) and
//     the authz_check sub-inputs (data-av-authz).
//   * ldap: the username field and the four query textareas (data-av-query).
function aws_auth_validate_nonconf_inputs(method) {
    var $group = $('#aws-av-fields-' + method);
    if (method === 'oauth') {
        return $group.find('[data-av-field="scope_aliases"]')
                     .add($group.find('[data-av-authz]'));
    }
    if (method === 'ldap') {
        return $group.find('[data-av-field="username"]')
                     .add($group.find('[data-av-query]'));
    }
    return $();
}
function aws_auth_validate_snapshot_nonconf(method) {
    var snap = [];
    aws_auth_validate_nonconf_inputs(method).each(function() {
        var el = $(this);
        snap.push({el: el, checkbox: el.is(':checkbox'),
                   value: el.is(':checkbox') ? el.is(':checked') : el.val()});
    });
    return snap;
}
function aws_auth_validate_restore_nonconf(_method, snap) {
    if (!snap) { return; }
    for (var i = 0; i < snap.length; i++) {
        var s = snap[i];
        if (s.checkbox) { s.el.prop('checked', !!s.value); } else { s.el.val(s.value); }
    }
}

// Build an editable rabbitmq.conf template listing EVERY possible key for a
// method, each pre-filled with a placeholder example value (the descriptor `ex`).
// Shown in the preview so an operator sees the full shape for the selected
// method and can edit values in place. This is a starting point, not a validated
// config -- values are examples the operator replaces.
function aws_auth_validate_template(method) {
    var spec = AWS_AUTH_VALIDATE_CONF[method];
    var out = [];
    if (spec.backend) { out.push('auth_backends.1 = ' + spec.backend); }
    if (spec.list) {
        out.push(spec.list.keyBase + '.1 = ' + spec.list.ex);
    }
    for (var key in spec.map) {
        if (!Object.prototype.hasOwnProperty.call(spec.map, key)) { continue; }
        out.push(key + ' = ' + spec.map[key].ex);
    }
    if (spec.notes && spec.notes.length > 0) {
        out.push('');
        for (var i = 0; i < spec.notes.length; i++) { out.push(spec.notes[i]); }
    }
    return out.join('\n');
}

// Show the method's full template as the textarea PLACEHOLDER (the greyed-out
// hint shown only while the box is empty). This never becomes content: the
// moment the operator types, their text replaces the hint, and switching methods
// just updates the hint. So there is nothing to clobber and no guard state.
function aws_auth_validate_show_template(method) {
    $('#aws-auth-validate-config').attr('placeholder', aws_auth_validate_template(method));
}

// Put rabbitmq.conf text into the config textarea.
function aws_auth_validate_set_config_text(text) {
    $('#aws-auth-validate-config').val(text);
}

// Set the small status line next to the copy/parse buttons.
function aws_auth_validate_config_status(text, cls) {
    $('#aws-auth-validate-copy-status')
        .text(text ? (' ' + text) : '')
        .attr('class', 'argument' + (cls ? ' ' + cls : ''));
}

// Submit the current method. The left-hand fields are the single source of
// truth for validation; the rabbitmq.conf box is a paste/copy convenience that
// never drives the request. This prevents the source-of-truth trap where the
// fields are invalid but a differing pasted config looks valid -- we would
// otherwise validate one thing while the operator reads another. If the box has
// content that diverges from the fields, we block and point the operator at the
// Parse / Update buttons to reconcile first. Bound as a delegated click so it
// survives re-renders. Never a GET/route param -- the body may carry an ARN.
$(document).on('click', '#aws-auth-validate-submit', function() {
    var method = $('#aws-auth-validate-method').val();
    // Always build the request from the visible fields.
    var body = aws_auth_validate_build_body(method);

    var raw = ('' + $('#aws-auth-validate-config').val()).trim();
    if (raw.length > 0) {
        // The box is non-empty: make sure it matches the fields before we run,
        // so what is validated is exactly what is displayed. Overlay form-only
        // fields (oauth access_token, tls target) onto the parsed body since
        // they have no conf key and would otherwise read as a false divergence.
        var pastedBody = aws_auth_validate_conf_to_body(method, raw).body;
        aws_auth_validate_overlay_form_only(method, pastedBody);
        // Some fields have no rabbitmq.conf representation at all (oauth
        // scope_aliases uses dynamic sub-keys; authz_check is a runtime
        // validation concept, not config). The conf box can never carry them, so
        // comparing them would always read as divergence. Drop them from BOTH
        // sides for the comparison only -- the real request body keeps them.
        //
        // Booleans are also normalized away when false: an unchecked box omits
        // the key entirely while a pasted `use_ssl = false' parses to
        // {use_ssl:false}. To the backend an absent boolean and an explicit
        // `false' are identical (both mean "off"), so treating that difference as
        // divergence would wrongly block Validate. Stripping false-valued keys
        // from both sides makes the comparison match the backend's semantics
        // without altering the request body actually sent.
        // The pasted side carries the false-vs-absent asymmetry (a pasted
        // `= false' vs an unchecked box). build_body never emits `false' today,
        // so the fields-side strip is currently a no-op, but it is kept symmetric
        // so the two sides stay comparable if build_body ever starts emitting one.
        var pastedCmp = aws_auth_validate_strip_false_bools(
            aws_auth_validate_strip_nonconf(method, pastedBody));
        var fieldsCmp = aws_auth_validate_strip_false_bools(
            aws_auth_validate_strip_nonconf(method, body));
        if (aws_auth_validate_normalize_body(pastedCmp) !==
            aws_auth_validate_normalize_body(fieldsCmp)) {
            aws_auth_validate_config_status(
                'The config box differs from the fields. Validation runs on the ' +
                'fields -- click "Parse into fields" to use the pasted config, or ' +
                '"Update config from fields" to sync the box, then Validate again.',
                'status-yellow');
            return false;
        }
    } else {
        // Nothing pasted: reflect the fields into the box so the validated
        // config is always visible and copyable.
        aws_auth_validate_set_config_text(aws_auth_validate_body_to_conf(method, body));
    }

    // Remember the exact conf text on screen so a 204 can mark it validated and
    // the copy button can flag later edits. It is now guaranteed consistent with
    // the fields (verified above, or generated from them).
    var confText = '' + $('#aws-auth-validate-config').val();
    // Clear any prior result and show a spinner immediately. A slow failure can
    // take several seconds, during which a stale success banner would otherwise
    // linger and mislead; the spinner makes "in progress" unambiguous.
    aws_auth_validate_show_loading();
    aws_auth_validate_req(method, body, confText);
    return false;
});

// Stable stringification of a request body for divergence comparison: object
// keys are sorted recursively so key order and whitespace never trigger a false
// mismatch. Array order is preserved (the ldap servers list is meaningful).
function aws_auth_validate_normalize_body(body) {
    return JSON.stringify(aws_auth_validate_sort_keys(body));
}
function aws_auth_validate_sort_keys(v) {
    if (Object.prototype.toString.call(v) === '[object Array]') {
        return v.map(aws_auth_validate_sort_keys);
    }
    if (v && typeof v === 'object') {
        var out = {};
        Object.keys(v).sort().forEach(function(k) {
            out[k] = aws_auth_validate_sort_keys(v[k]);
        });
        return out;
    }
    return v;
}

// Replace the result area with a spinner while a request is in flight. Cleared
// by aws_auth_validate_render_result when the response (or transport error)
// arrives.
function aws_auth_validate_show_loading() {
    $('#aws-auth-validate-result').html(
        '<div class="status-grey" style="padding:8px;">' +
        '<span class="aws-av-spinner"></span>' +
        '<span class="argument">Validating&hellip;</span></div>'
    );
}

// Parse the textarea rabbitmq.conf into the form fields. Lines that do not apply
// to the selected method are ignored; aws.arns.assume_role_arn is skipped (read
// from broker config, never the request).
$(document).on('click', '#aws-auth-validate-parse', function() {
    var raw = ('' + $('#aws-auth-validate-config').val()).trim();
    if (raw.length === 0) {
        aws_auth_validate_config_status('Nothing to parse: the config box is empty.', 'status-yellow');
        return false;
    }
    var method = $('#aws-auth-validate-method').val();
    var parsed = aws_auth_validate_conf_to_body(method, raw);
    aws_auth_validate_populate_form(method, parsed.body);
    var msg = 'Parsed into the ' + method + ' fields.';
    if (parsed.skippedAssumeRole) {
        msg += ' Skipped aws.arns.assume_role_arn (read from broker config).';
    }
    if (parsed.unknown > 0) {
        msg += ' ' + parsed.unknown + ' line(s) did not apply to ' + method + '.';
    }
    aws_auth_validate_config_status(msg,
        (parsed.skippedAssumeRole || parsed.unknown > 0) ? 'status-yellow' : 'status-green');
    return false;
});

// Rebuild the textarea rabbitmq.conf from the current form fields.
$(document).on('click', '#aws-auth-validate-build', function() {
    var method = $('#aws-auth-validate-method').val();
    var body = aws_auth_validate_build_body(method);
    var existing = '' + $('#aws-auth-validate-config').val();
    // Merge into whatever is already in the box: update/add only this method's
    // managed keys, preserve every other line (comments, blank lines, unrelated
    // config, assume_role, other methods' keys).
    aws_auth_validate_set_config_text(aws_auth_validate_merge_conf(method, existing, body));
    aws_auth_validate_config_status('Merged the form fields into the config (other lines preserved).', 'status-green');
    return false;
});

// Copy the current config text to the clipboard. Warns if the text has been
// edited since the last successful (204) validation, so an operator does not
// accidentally save a config that never passed.
$(document).on('click', '#aws-auth-validate-copy', function() {
    var text = '' + $('#aws-auth-validate-config').val();
    if (text.trim().length === 0) {
        aws_auth_validate_config_status('Nothing to copy: the config box is empty.', 'status-yellow');
        return false;
    }
    var edited = (AWS_AUTH_VALIDATE_LAST_VALID === null) ||
        (text !== AWS_AUTH_VALIDATE_LAST_VALID);
    var note = edited
        ? 'Copied (note: this differs from the last validated config).'
        : 'Copied the validated config.';
    var noteCls = edited ? 'status-yellow' : 'status-green';
    aws_auth_validate_copy_text(text, function(ok) {
        if (ok) {
            aws_auth_validate_config_status(note, noteCls);
        } else {
            aws_auth_validate_config_status('Could not access the clipboard; select the text and copy manually.', 'status-red');
        }
    });
    return false;
});

// Clipboard copy with a graceful fallback for older WebViews without the async
// Clipboard API. Invokes cb(true|false).
function aws_auth_validate_copy_text(text, cb) {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        navigator.clipboard.writeText(text).then(function() { cb(true); },
                                                  function() { cb(false); });
        return;
    }
    try {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand('copy');
        document.body.removeChild(ta);
        cb(ok);
    } catch (e) {
        cb(false);
    }
}

// Show/hide the per-method field groups when the method selector changes.
$(document).on('change', '#aws-auth-validate-method', function() {
    var method = $(this).val();
    $('.aws-av-method-fields').hide();
    $('#aws-av-fields-' + method).show();
    $('#aws-auth-validate-result').empty();
    // A prior 204 was for the previous method's body; it no longer applies.
    AWS_AUTH_VALIDATE_LAST_VALID = null;
    aws_auth_validate_config_status('', '');
    // Update the preview placeholder to the newly-selected method's template.
    // This only changes the greyed-out hint, so any content the operator typed
    // is untouched.
    aws_auth_validate_show_template(method);
});

// Issue the PUT and render the fixed category. Modeled on the reference plugin's
// rqm_with_req: a hand-rolled request so we can inspect the status code and the
// {error, message} body directly, rather than routing it through the management
// plugin's CRUD helpers (which would surface a generic proxy error).
function aws_auth_validate_req(method, body, confText) {
    if (typeof has_auth_credentials === 'function' && !has_auth_credentials()) {
        location.reload();
        return;
    }
    var req = xmlHttpRequest();
    req.open('PUT', 'api/aws/auth/validate/' + encodeURIComponent(method), true);
    var header = authorization_header();
    if (header !== null) {
        req.setRequestHeader('authorization', header);
    }
    req.setRequestHeader('content-type', 'application/json');
    // Register with the console's in-flight request list (when present) so a
    // navigate-away aborts this PUT along with every other pending request --
    // main.js abort loop walks outstanding_reqs. Guarded because it is an
    // external console global; a standalone/older console without it still works
    // (the request just is not centrally abortable, as before).
    if (typeof outstanding_reqs !== 'undefined' && outstanding_reqs &&
        typeof outstanding_reqs.push === 'function') {
        outstanding_reqs.push(req);
    }
    // The conf text on screen; on 204 this becomes the "last validated config"
    // so the copy button can flag later edits. The wire body stays JSON (the
    // endpoint's contract) -- only the textarea and clipboard use conf.
    req.onreadystatechange = function() {
        if (req.readyState !== 4) return;
        // De-register from the console's in-flight list before rendering, so a
        // completed request is not left for a later navigate-away to abort.
        if (typeof outstanding_reqs !== 'undefined' && outstanding_reqs &&
            typeof jQuery !== 'undefined') {
            var ix = jQuery.inArray(req, outstanding_reqs);
            if (ix !== -1) { outstanding_reqs.splice(ix, 1); }
        }
        aws_auth_validate_render_result(req, confText);
    };
    req.send(JSON.stringify(body));
}

function aws_auth_validate_render_result(req, confText) {
    var category, message;
    if (req.status === 0) {
        category = 'transport_error';
    } else if (req.status === 204) {
        category = 'success';
        // Record the exact conf text that passed so the copy button knows
        // whether later edits diverged from it. The textarea already holds this
        // text (we do not overwrite the operator's pasted comments/formatting).
        if (typeof confText === 'string') {
            AWS_AUTH_VALIDATE_LAST_VALID = confText;
            aws_auth_validate_config_status('This config validated -- use Copy config to save it.', 'status-green');
        }
    } else {
        try {
            var data = JSON.parse(req.responseText);
            category = data && data.error ? data.error : 'internal_error';
            message = data && data.message ? data.message : undefined;
        } catch (e) {
            category = 'internal_error';
        }
    }
    var info = AWS_AUTH_VALIDATE_CATEGORY[category] ||
        {cls: 'status-red', text: 'Unexpected response (' + req.status + ').'};
    var html = '<div class="' + info.cls + '" style="padding:8px;">' +
        '<strong>' + aws_av_escape_html(category) + '</strong> &mdash; ' +
        aws_av_escape_html(info.text);
    // The backend message is a fixed, non-secret string; safe to show, still escaped.
    if (message) {
        html += '<br/><span class="argument">' + aws_av_escape_html(message) + '</span>';
    }
    html += ' <span class="argument">(HTTP ' + (req.status || 'n/a') + ')</span></div>';
    $('#aws-auth-validate-result').html(html);
}

// Minimal HTML escaper, private to this view. Named with the aws_av_ prefix (not
// fmt_escape_html) so it never shadows the console's own global fmt_escape_html
// (defined in the management plugin's formatters.js and relied on by other
// views, e.g. for \n -> <br/> rendering). Prefer the console's global when it is
// present so behavior matches the rest of the UI; fall back to this local
// implementation on older brokers that do not bundle it.
function aws_av_escape_html(s) {
    if (typeof window.fmt_escape_html === 'function') {
        return window.fmt_escape_html(s);
    }
    return ('' + s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
                   .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
                   .replace(/'/g, '&#39;');
}
