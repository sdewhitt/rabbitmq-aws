%% @doc AWS Operations module for aws_lib
%% This module provides higher-level AWS operations like EBS snapshots.
%% @end

-module(aws_lib_ops).

-export([
    create_volume_snapshot/2,
    create_volume_snapshot/3,
    delete_volume_snapshot/2,
    delete_volume_snapshot/3
]).

-include("aws_lib.hrl").

-type aws_state() :: aws_lib:aws_state().

-type snapshot_options() :: #{
    description => string(),
    tags => [{string(), string()}],
    dry_run => boolean()
}.

-type delete_options() :: #{
    dry_run => boolean()
}.

-type snapshot_metadata() :: #{
    snapshot_id => string(),
    volume_id => string(),
    state => string(),
    start_time => string(),
    progress => string(),
    description => string()
}.

-export_type([snapshot_options/0, delete_options/0, snapshot_metadata/0]).

-spec create_volume_snapshot(string(), aws_state()) ->
    {ok, string(), snapshot_metadata(), aws_state()} | result_error().
%% @doc Create a snapshot of the specified EBS volume with default options.
%% @end
create_volume_snapshot(VolumeId, State) ->
    create_volume_snapshot(VolumeId, #{}, State).

-spec create_volume_snapshot(string(), snapshot_options(), aws_state()) ->
    {ok, string(), snapshot_metadata(), aws_state()} | result_error().
%% @doc Create a snapshot of the specified EBS volume with custom options.
%% @end
create_volume_snapshot(VolumeId, Options, State) ->
    Description = maps:get(description, Options, "aws_lib automated snapshot"),
    DryRun = maps:get(dry_run, Options, false),

    Body = build_snapshot_body(VolumeId, Description, DryRun),
    Headers = [{"content-type", "application/x-www-form-urlencoded"}],
    case aws_lib:post("ec2", "/", Body, Headers, State) of
        {ok, {_Headers, Response}, State1} ->
            {ok, SnapshotId, Metadata} = parse_snapshot_response(Response),
            {ok, SnapshotId, Metadata, State1};
        Error ->
            Error
    end.

-spec delete_volume_snapshot(string(), aws_state()) ->
    {ok, string(), aws_state()} | result_error().
%% @doc Delete the specified EBS snapshot with default options.
%% @end
delete_volume_snapshot(SnapshotId, State) ->
    delete_volume_snapshot(SnapshotId, #{}, State).

-spec delete_volume_snapshot(string(), delete_options(), aws_state()) ->
    {ok, string(), aws_state()} | result_error().
%% @doc Delete the specified EBS snapshot with custom options.
%% @end
delete_volume_snapshot(SnapshotId, Options, State) ->
    DryRun = maps:get(dry_run, Options, false),

    Body = build_delete_body(SnapshotId, DryRun),
    Headers = [{"content-type", "application/x-www-form-urlencoded"}],
    case aws_lib:post("ec2", "/", Body, Headers, State) of
        {ok, {_Headers, Response}, State1} ->
            {ok, SnapshotId} = parse_delete_response(Response, SnapshotId),
            {ok, SnapshotId, State1};
        Error ->
            Error
    end.

-spec build_snapshot_body(string(), string() | binary(), boolean()) -> string().
build_snapshot_body(VolumeId, Description, DryRun) ->
    DescStr = unicode:characters_to_list(Description),
    BaseBody =
        "Action=CreateSnapshot&VolumeId=" ++ VolumeId ++
            "&Description=" ++ uri_string:quote(DescStr) ++
            "&Version=2016-11-15",
    case DryRun of
        true -> BaseBody ++ "&DryRun=true";
        false -> BaseBody
    end.

-spec build_delete_body(string(), boolean()) -> string().
build_delete_body(SnapshotId, DryRun) ->
    BaseBody =
        "Action=DeleteSnapshot&SnapshotId=" ++ SnapshotId ++
            "&Version=2016-11-15",
    case DryRun of
        true -> BaseBody ++ "&DryRun=true";
        false -> BaseBody
    end.

-spec parse_snapshot_response(term()) -> {ok, string(), snapshot_metadata()}.
parse_snapshot_response([{"CreateSnapshotResponse", SnapshotData}]) ->
    SnapshotId = proplists:get_value("snapshotId", SnapshotData, ""),
    Metadata = #{
        snapshot_id => SnapshotId,
        volume_id => proplists:get_value("volumeId", SnapshotData, ""),
        state => proplists:get_value("status", SnapshotData, ""),
        start_time => proplists:get_value("startTime", SnapshotData, ""),
        progress => proplists:get_value("progress", SnapshotData, ""),
        description => proplists:get_value("description", SnapshotData, "")
    },
    {ok, SnapshotId, Metadata}.

-spec parse_delete_response(term(), string()) -> {ok, string()}.
parse_delete_response([{"DeleteSnapshotResponse", _ResponseData}], SnapshotId) ->
    {ok, SnapshotId}.
