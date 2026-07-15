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
// as a JSON body and renders that category as a friendly banner. It never puts
// secrets (password_arn, client_secret, ARNs) in the URL/hash or localStorage.

dispatcher_add(function(sammy) {
    sammy.get('#/auth-validate', function() {
        render({}, 'aws_auth_validate', '#/auth-validate');
    });
});

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

// Submit the current method form. Bound as a delegated click so it survives
// re-renders. Never a GET/route param -- the body may carry an ARN.
$(document).on('click', '#aws-auth-validate-submit', function() {
    var method = $('#aws-auth-validate-method').val();
    var body = aws_auth_validate_build_body(method);
    aws_auth_validate_req(method, body);
    return false;
});

// Show/hide the per-method field groups when the method selector changes.
$(document).on('change', '#aws-auth-validate-method', function() {
    var method = $(this).val();
    $('.aws-av-method-fields').hide();
    $('#aws-av-fields-' + method).show();
    $('#aws-auth-validate-result').empty();
});

// Issue the PUT and render the fixed category. Modeled on the reference plugin's
// rqm_with_req: a hand-rolled request so we can inspect the status code and the
// {error, message} body directly, rather than routing it through the management
// plugin's CRUD helpers (which would surface a generic proxy error).
function aws_auth_validate_req(method, body) {
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
    req.onreadystatechange = function() {
        if (req.readyState !== 4) return;
        aws_auth_validate_render_result(req);
    };
    req.send(JSON.stringify(body));
}

function aws_auth_validate_render_result(req) {
    var category, message;
    if (req.status === 0) {
        category = 'transport_error';
    } else if (req.status === 204) {
        category = 'success';
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
