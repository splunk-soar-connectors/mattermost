# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Custom action views for the Mattermost app.
#
# Ported from legacy mattermost_view.py's get_ctx_result/_parse_data/display_view
# trio, rendered via Jinja2 (soar_sdk.views.template_renderer) instead of
# Django, following the display_view/_TEMPLATE_MAP dispatch shape used by
# other SDK apps in this pattern (see sdk_github's src/views.py).
#
# Only the 5 actions the manifest wires to render.type="custom" get an entry
# in _TEMPLATE_MAP: list_users, upload_file, send_message, list_posts,
# list_channels. list_teams uses render.type="table" in mattermost.json and
# has no custom view — it is deliberately absent here.

from datetime import datetime
from typing import Any

from soar_sdk.views.template_renderer import get_template_renderer, get_templates_dir

# Millisecond-epoch fields Mattermost returns on most objects (posts, files,
# teams, channels, users) that legacy's _parse_data converted to ISO 8601
# strings for display. Ported verbatim from mattermost_view.py's _parse_data —
# same three field names, same divide-by-1000 + isoformat + "Z" suffix logic.
_EPOCH_MS_FIELDS = ("create_at", "edit_at", "update_at")


def _parse_data(data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert millisecond-epoch timestamp fields to ISO 8601 strings in place.

    Direct port of legacy mattermost_view.py's _parse_data(). Iterates every
    item in the result list and, for each of create_at/edit_at/update_at, if
    present and truthy, divides by 1000 and formats via
    datetime.fromtimestamp(...).isoformat() with a trailing "Z" appended
    (legacy did not use timezone-aware datetimes here, so this preserves that
    exact — if naive — behavior rather than "fixing" it to use UTC).
    """
    for item in data:
        for field in _EPOCH_MS_FIELDS:
            try:
                if item.get(field):
                    item[field] = item[field] / 1000
                    item[field] = f"{datetime.fromtimestamp(item[field]).isoformat()}Z"  # noqa: DTZ006
            except ValueError:
                pass
    return data


def _get_ctx_result(result: Any, provides: str) -> dict[str, Any] | None:
    """Build a template context dict from a single ActionResult.

    Mirrors legacy's get_ctx_result(provides, result): param/summary/action
    always present, data run through _parse_data when non-empty.
    """
    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx: dict[str, Any] = {
        "param": param,
        "action": provides,
    }
    if summary:
        ctx["summary"] = summary

    ctx["data"] = _parse_data(data) if data else {}
    return ctx


# provides (action name, space-separated as SOAR sends it) -> template file,
# ported 1:1 from legacy mattermost_view.py's display_view if/elif chain.
_TEMPLATE_MAP: dict[str, str] = {
    "list users": "mattermost_list_users.html",
    "upload file": "mattermost_upload_file.html",
    "send message": "mattermost_send_message.html",
    "list posts": "mattermost_list_posts.html",
    "list channels": "mattermost_list_channels.html",
}


def display_view(provides: str, all_app_runs: list, context: dict) -> str:
    """Entry point called by Splunk SOAR for custom action views.

    Mirrors legacy mattermost_view.display_view but renders via Jinja2
    instead of Django and returns a fully-rendered HTML string; SOAR treats
    any string return as prerendered HTML when context["prerender"] is True
    (see soar_sdk.decorators.view_handler's handle_html_output).
    """
    results: list[dict[str, Any]] = []
    for _summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if ctx_result:
                results.append(ctx_result)

    context["results"] = results

    template_name = _TEMPLATE_MAP.get(provides)
    if not template_name:
        return ""

    templates_dir = get_templates_dir(globals())
    renderer = get_template_renderer("jinja", templates_dir)
    html = renderer.render_template(template_name, context)
    context["prerender"] = True
    return html
