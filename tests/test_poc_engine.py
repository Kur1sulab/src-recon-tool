import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from modules.poc_engine import _match


class TestMatcher(unittest.TestCase):
    def test_status_match(self):
        self.assertTrue(_match([{"type": "status", "status": [200]}], 200, ""))

    def test_status_miss(self):
        self.assertFalse(_match([{"type": "status", "status": [200]}], 404, ""))

    def test_contains_match(self):
        self.assertTrue(_match([{"type": "contains", "words": ["admin"]}], 200, "<title>admin</title>"))

    def test_and_condition(self):
        matchers = [{"type": "status", "status": [200]}, {"type": "contains", "words": ["login"]}]
        self.assertTrue(_match(matchers, 200, "please login", condition="and"))
        self.assertFalse(_match(matchers, 200, "hello", condition="and"))


if __name__ == "__main__":
    unittest.main()
