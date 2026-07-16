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
    connection_failed:  {cls: 'status-red',    text: 'Connection failed: the target could not be reached.'},
    tls_failed:         {cls: 'status-red',    text: 'TLS failed: handshake or certificate verification did not succeed.'},
    query_invalid:      {cls: 'status-red',    text: 'Query invalid: an authorization query could not be parsed.'},
    auth_failed:        {cls: 'status-yellow', text: 'Auth failed: the server was reached but did not authenticate/respond as expected.'},
    config_conflict:    {cls: 'status-yellow', text: 'Config conflict: the supplied options are mutually inconsistent (for example an ARN is referenced with no assume_role configured).'},
    authz_unverified:   {cls: 'status-yellow', text: 'Authorization unverified: a configured authorization check could not be confirmed.'},
    method_disabled:    {cls: 'status-yellow', text: 'Method disabled: enable it with aws.auth_validation.enabled_methods.<method> = true (every method is opt-in).'},
    unknown_method:     {cls: 'status-red',    text: 'Unknown method.'},
    insufficient_user_tag: {cls: 'status-red', text: 'Your user lacks the tag required to call this endpoint.'},
    capacity_exhausted: {cls: 'status-yellow', text: 'Service at capacity or not ready. Try again shortly.'},
    internal_error:     {cls: 'status-red',    text: 'Internal error during validation.'},
    transport_error:    {cls: 'status-red',    text: 'Could not reach the management API.'}
};

// Read the visible method form into a JSON request body. Only non-empty fields
// are included so an omitted optional field keeps the backend default. ssl_options
// is collected from a small fixed set of sub-fields; ARN fields nest under it to
// match the backend shape (ssl_options.cacertfile_arn etc.).
function aws_auth_validate_build_body(method) {
    var body = {};
    var $form = $('#aws-auth-validate-form');

    // Flat top-level fields per method. A checkbox contributes a boolean true
    // only when checked (an unchecked box is omitted so the backend keeps its
    // default); every other input contributes its non-empty value.
    $form.find('[data-av-field]').each(function() {
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

    // ssl_options sub-object (shared shape across methods that support TLS).
    var ssl = {};
    $form.find('[data-av-ssl]').each(function() {
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
    return body;
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
    var $form = $('#aws-auth-validate-form');

    // Clear the currently-visible method's fields and the shared ssl_options.
    $('#aws-av-fields-' + method).find('[data-av-field]').each(function() {
        var el = $(this);
        if (el.is(':checkbox')) { el.prop('checked', false); } else { el.val(''); }
    });
    $form.find('[data-av-ssl]').each(function() {
        var el = $(this);
        if (el.is(':checkbox')) { el.prop('checked', false); } else { el.val(''); }
    });

    if (!body || typeof body !== 'object') { return; }

    var ssl = (body.ssl_options && typeof body.ssl_options === 'object') ? body.ssl_options : {};

    // Top-level fields for the selected method.
    $('#aws-av-fields-' + method).find('[data-av-field]').each(function() {
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

    // Shared ssl_options sub-fields.
    $form.find('[data-av-ssl]').each(function() {
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
            'auth_ldap.ssl_options.sni':                        {path: ['ssl_options', 'sni'], type: 'string', ex: 'ldap.example.com'},
            'aws.arns.auth_ldap.dn_lookup_bind.password':       {path: ['password_arn'], type: 'string', ex: 'arn:aws:secretsmanager:us-west-2:111122223333:secret:RabbitMqDnLookupUserPassword'},
            'aws.arns.auth_ldap.ssl_options.cacertfile':        {path: ['ssl_options', 'cacertfile_arn'], type: 'string', ex: 'arn:aws:s3:::my-bucket/ca-cert.pem'},
            'aws.arns.auth_ldap.ssl_options.certfile':          {path: ['ssl_options', 'certfile_arn'], type: 'string', ex: 'arn:aws:s3:::my-bucket/client-cert.pem'},
            'aws.arns.auth_ldap.ssl_options.keyfile':           {path: ['ssl_options', 'keyfile_arn'], type: 'string', ex: 'arn:aws:secretsmanager:us-west-2:111122223333:secret:RabbitMqClientKey'}
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
            'auth_http.ssl_options.verify':                     {path: ['ssl_options', 'verify'], type: 'string', ex: 'verify_peer'},
            'auth_http.ssl_options.sni':                        {path: ['ssl_options', 'sni'], type: 'string', ex: 'auth.example.com'},
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
            'auth_oauth2.ssl_options.verify':                   {path: ['ssl_options', 'verify'], type: 'string', ex: 'verify_peer'},
            'auth_oauth2.ssl_options.sni':                      {path: ['ssl_options', 'sni'], type: 'string', ex: 'idp.example.com'},
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
        backend: null,
        map: {
            'ssl_options.verify':                               {path: ['ssl_options', 'verify'], type: 'string', ex: 'verify_peer'},
            'ssl_options.sni':                                  {path: ['ssl_options', 'sni'], type: 'string', ex: 'listener.example.com'},
            'aws.arns.ssl_options.cacertfile':                  {path: ['ssl_options', 'cacertfile_arn'], type: 'string', ex: 'arn:aws:s3:::my-bucket/ca-cert.pem'},
            'aws.arns.ssl_options.certfile':                    {path: ['ssl_options', 'certfile_arn'], type: 'string', ex: 'arn:aws:s3:::my-bucket/client-cert.pem'},
            'aws.arns.ssl_options.keyfile':                     {path: ['ssl_options', 'keyfile_arn'], type: 'string', ex: 'arn:aws:secretsmanager:us-west-2:111122223333:secret:RabbitMqClientKey'}
        },
        // `target` names the listener under test; it is a validation concept,
        // not a rabbitmq.conf key.
        formOnly: ['target'],
        notes: ['# target: enter the listener name in the "Target" form field above (a validation concept, not a rabbitmq.conf key).']
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
    var desired = {};
    for (var key in spec.map) {
        if (!Object.prototype.hasOwnProperty.call(spec.map, key)) { continue; }
        var desc = spec.map[key];
        var v = aws_auth_validate_get_path(body, desc.path);
        if (v === undefined || v === null || ('' + v).length === 0) { continue; }
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
                out.push(line); // form has no servers -- leave existing untouched
            }
            continue;
        }

        // Managed scalar key the form supplies: update value in place, keeping
        // the operator's original indentation and key spelling.
        if (Object.prototype.hasOwnProperty.call(desired, k) && !seen[k]) {
            var leadingWs = line.match(/^\s*/)[0];
            var origKey = trimmed.substring(0, eq).trim();
            out.push(leadingWs + origKey + ' = ' + desired[k].value);
            seen[k] = true;
            continue;
        }

        // Any other line (unrelated config, another method's keys, a managed key
        // the form left empty, assume_role) is preserved verbatim.
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

// Submit the current method. The rabbitmq.conf textarea is authoritative when it
// holds content (an operator may have pasted or hand-edited config lines), so we
// parse and send that; otherwise we build the body from the visible form and
// reflect it back into the textarea as conf so what was validated is always
// visible. Form-only fields (oauth access_token, tls target) have no conf key,
// so they are always overlaid from the form. Bound as a delegated click so it
// survives re-renders. Never a GET/route param -- the body may carry an ARN.
$(document).on('click', '#aws-auth-validate-submit', function() {
    var method = $('#aws-auth-validate-method').val();
    var raw = ('' + $('#aws-auth-validate-config').val()).trim();
    var body;
    if (raw.length > 0) {
        var parsed = aws_auth_validate_conf_to_body(method, raw);
        body = parsed.body;
        // Form-only fields never appear in conf; take them from the form.
        aws_auth_validate_overlay_form_only(method, body);
    } else {
        body = aws_auth_validate_build_body(method);
        aws_auth_validate_set_config_text(aws_auth_validate_body_to_conf(method, body));
    }
    // Remember the exact conf text on screen so a 204 can mark it validated and
    // the copy button can flag later edits. If the operator pasted conf we keep
    // their text verbatim (comments and all); otherwise it is the generated conf.
    var confText = '' + $('#aws-auth-validate-config').val();
    aws_auth_validate_req(method, body, confText);
    return false;
});

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
    // The conf text on screen; on 204 this becomes the "last validated config"
    // so the copy button can flag later edits. The wire body stays JSON (the
    // endpoint's contract) -- only the textarea and clipboard use conf.
    req.onreadystatechange = function() {
        if (req.readyState !== 4) return;
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
        '<strong>' + fmt_escape_html(category) + '</strong> &mdash; ' +
        fmt_escape_html(info.text);
    // The backend message is a fixed, non-secret string; safe to show, still escaped.
    if (message) {
        html += '<br/><span class="argument">' + fmt_escape_html(message) + '</span>';
    }
    html += ' <span class="argument">(HTTP ' + (req.status || 'n/a') + ')</span></div>';
    $('#aws-auth-validate-result').html(html);
}

// Minimal HTML escaper (the console bundles fmt_escape_html in newer releases;
// fall back to a local one so this works across broker versions).
function fmt_escape_html(s) {
    if (typeof window.fmt_escape_html === 'function' && window.fmt_escape_html !== fmt_escape_html) {
        return window.fmt_escape_html(s);
    }
    return ('' + s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
                   .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
