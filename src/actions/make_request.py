# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

import json
from typing import Any

from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams, Param

from ..asset import Asset
from ..client import call_mattermost


class MattermostMakeRequestParams(MakeRequestParams):
    """Parameters for sending an arbitrary Mattermost API request."""

    endpoint: str = Param(
        required=True,
        description=(
            "Mattermost API endpoint relative to /api/v4. For example, "
            "'users/me' or 'teams'. Do not include the server URL."
        ),
    )
    verify_ssl: bool = Param(
        required=False,
        default=True,
        description="Whether to verify the SSL certificate. Default true.",
    )


def _parse_json_object(value: str | None, parameter_name: str) -> dict | None:
    """Parse an optional JSON object parameter."""
    if value is None or not value.strip():
        return None
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ActionFailure(f"Invalid JSON in the {parameter_name} parameter.") from exc
    if not isinstance(parsed, dict):
        raise ActionFailure(f"The {parameter_name} parameter must be a JSON object.")
    return parsed


def _parse_query_parameters(value: str | None) -> tuple[dict | None, str | None]:
    """Parse query parameters as JSON or preserve a raw query string."""
    if value is None or not value.strip():
        return None, None
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None, value.lstrip("?")
    if not isinstance(parsed, dict):
        raise ActionFailure("The query_parameters parameter must be a JSON object.")
    return parsed, None


def _parse_body(value: str | None) -> Any:
    """Parse an optional JSON request body."""
    if value is None or not value.strip():
        return None
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ActionFailure("Invalid JSON in the body parameter.") from exc


def make_request(
    params: MattermostMakeRequestParams, asset: Asset
) -> MakeRequestOutput:
    """Send an arbitrary authenticated request to a Mattermost API endpoint."""
    endpoint = params.endpoint.strip()
    if endpoint.lower().startswith(("http://", "https://")):
        raise ActionFailure(
            "Do not include the server URL in the endpoint. "
            "Only the Mattermost API path is needed."
        )
    if not endpoint.strip("/"):
        raise ActionFailure("The endpoint parameter must contain an API path.")

    headers = _parse_json_object(params.headers, "headers")
    query_parameters, query_string = _parse_query_parameters(params.query_parameters)
    body = _parse_body(params.body)

    response = call_mattermost(
        params.http_method,
        f"/{endpoint.lstrip('/')}",
        asset,
        headers=headers,
        params=query_parameters,
        query_string=query_string,
        json=body,
        timeout=params.timeout,
        verify_ssl=params.verify_ssl,
    )

    return MakeRequestOutput(
        status_code=response.status_code,
        response_body=response.text,
    )
