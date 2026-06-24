---
title: "`aws_lib`: XML parser drops attributes and collapses repeated elements"
type: bug
labels: [bug]
modules: [aws_lib_xml]
---

# `aws_lib`: XML parser drops attributes and collapses repeated elements

## Problem

`aws_lib_xml:parse/1` walks the `xmerl` parse tree but only ever reads the `name` and `content` fields of each element:

```erlang
parse_node(#xmlElement{name = Name, content = Content}) ->
    Value = parse_content(Content, []),
    [{atom_to_list(Name), flatten_value(Value, Value)}].
```

Two consequences:

1. **Attributes are silently dropped.** The `#xmlElement.attributes` field is never read, so any data carried in XML attributes is lost. Several EC2/S3 XML responses carry meaningful data in attributes.

2. **Repeated sibling elements collapse.** Each child element produces a `{Name, Value}` tuple, and same-named siblings produce duplicate keys in the resulting proplist. Callers retrieve values with `proplists:get_value/2-3`, which returns only the first match, so all but the first of a repeated element are unreachable. Lists such as `volumeSet`/`attachmentSet` items only work today because of the specific shape the callers expect (see `parse_volumes_response/1` in `aws_lib.erl`), not because the parser models repetition.

The `flatten_value/2` and `flatten_text/2` helpers are also fragile for mixed content (text interleaved with child elements) and can reorder or drop nodes.

## Impact

Low today: the plugin only consumes XML for the narrow `DescribeVolumes` / STS `AssumeRole` shapes it already handles. But the parser is not a general-purpose AWS XML decoder, and `maybe_decode_body/2` routes *any* `*/xml` response through it - so a future caller decoding a richer XML response would silently get incomplete data with no error.

## Options

- Document the parser as intentionally minimal and scoped to the known response shapes, or
- Replace it with attribute-aware, repetition-aware decoding (e.g. an `xmerl_xpath`-based extractor, or returning a structure that preserves attributes and lists of repeated elements).

This is inherited behavior from the original `rabbitmq_aws`/httpc-aws XML handling, not introduced by the `aws_lib` port.
