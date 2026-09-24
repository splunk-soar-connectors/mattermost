# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

from datetime import UTC, datetime
from typing import Any

from soar_sdk.views.template_renderer import get_template_renderer, get_templates_dir


_TEMPLATE_MAP = {
    "list_posts": "list_posts.html",
    "send_message": "send_message.html",
    "upload_file": "upload_file.html",
    "list_users": "list_users.html",
    "list_channels": "list_channels.html",
}


def _parse_data(data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert Mattermost millisecond timestamps for display."""
    parsed = []
    for item in data:
        displayed = dict(item)
        for field in ("create_at", "edit_at", "update_at"):
            value = displayed.get(field)
            if value:
                displayed[field] = datetime.fromtimestamp(
                    value / 1000, tz=UTC
                ).isoformat()
        parsed.append(displayed)
    return parsed


def _get_ctx_result(provides: str, result: Any) -> dict[str, Any]:
    """Build the template context for one SDK action result."""
    data = result.get_data() or []
    return {
        "param": result.get_param(),
        "summary": result.get_summary(),
        "action": provides,
        "data": _parse_data(data),
    }


def display_view(provides: str, all_app_runs: Any, context: dict[str, Any]) -> str:
    """Render an action result with its Mattermost Jinja template."""
    template_name = _TEMPLATE_MAP.get(provides)
    if not template_name:
        return ""

    results = []
    for _summary, action_results in all_app_runs:
        results.extend(_get_ctx_result(provides, result) for result in action_results)

    context["results"] = results
    context["prerender"] = True
    renderer = get_template_renderer("jinja", get_templates_dir(globals()))
    return renderer.render_template(template_name, context)


__all__ = ["display_view"]
