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
import ast
import unittest
from pathlib import Path


CONNECTOR = Path(__file__).resolve().parents[1] / "mattermost_connector.py"


def _function_source(name):
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)
    return ast.get_source_segment(source, function)


class ValidationFollowupTests(unittest.TestCase):
    def test_oauth_start_redirect_requires_pending_nonce(self):
        source = _function_source("_handle_login_redirect")
        self.assertIn('request.GET.get("state_nonce", "")', source)
        self.assertIn("hmac.compare_digest", source)
        self.assertLess(source.index("hmac.compare_digest"), source.index("state.get(key)"))

    def test_displayed_oauth_start_link_carries_nonce(self):
        source = _function_source("_handle_interactive_login")
        self.assertIn('"state_nonce": oauth_state', source)
        self.assertIn("urllib.parse.urlencode", source)

    def test_token_debug_suppression_uses_requested_endpoint(self):
        rest_call = _function_source("_make_rest_call")
        process_response = _function_source("_process_response")
        self.assertIn("suppress_debug = url.rstrip", rest_call)
        self.assertIn("suppress_debug=suppress_debug", rest_call)
        self.assertIn("and not suppress_debug", process_response)
        self.assertNotIn("response.url", process_response)


if __name__ == "__main__":
    unittest.main()
