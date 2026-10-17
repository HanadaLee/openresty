#!/usr/bin/env python3
"""Unit checks for source projection; does not compile or run nginx."""

import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[2] / "util/check-nginx-ext-isolation.py"
spec = importlib.util.spec_from_file_location("isolation", path)
isolation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(isolation)


def source(text, undefined=False):
    return "\n".join(line for line, _ in isolation.project(text, undefined))


class ProjectionTests(unittest.TestCase):
    def test_other_features_remain_symbolic(self):
        text = "#if (NGX_PCRE)\n    int a;\n#else\n    int b;\n#endif\n"
        self.assertEqual(source(text), text.rstrip())

    def test_nested_extension_branches(self):
        text = ("#if (NGX_RESTY_EXT && NGX_EXPR)\n    extended();\n"
                "#else\n#if (NGX_PCRE)\n    native();\n#endif\n#endif\n")
        expected = "#if (NGX_PCRE)\n    native();\n#endif"
        for undefined in (False, True):
            self.assertEqual(source(text, undefined), expected)

    def test_ifdef_is_not_the_same_as_zero(self):
        text = "#ifdef NGX_RESTY_EXT\ndefined();\n#else\nundefined();\n#endif\n"
        self.assertEqual(source(text), "defined();")
        self.assertEqual(source(text, True), "undefined();")

    def test_comments_and_indentation_are_significant(self):
        self.assertNotEqual(source("    int a;"), source("   int a;"))
        self.assertNotEqual(source("/* a */\nint a;"), source("/* b */\nint a;"))
        self.assertEqual(source("\r\n    int a;\r\n \r\n"), "    int a;")

    def test_comment_directives_are_not_evaluated(self):
        text = "/*\n#if (NGX_RESTY_EXT)\nexample\n#endif\n*/\nint a;\n"
        self.assertEqual(source(text), text.rstrip())

    def test_line_numbers_are_preserved(self):
        text = "\n#if (NGX_RESTY_EXT)\nremoved();\n#endif\n\n    int a;\n"
        self.assertEqual(isolation.project(text), [("    int a;", 6)])

    def test_new_source_must_be_fully_guarded(self):
        self.assertEqual(source("#if (NGX_RESTY_EXT)\nint a;\n#endif\n"), "")
        self.assertNotEqual(source("int a;\n#if (NGX_RESTY_EXT)\nint b;\n#endif\n"), "")

    def test_unsupported_expression_fails_closed(self):
        with self.assertRaises(ValueError):
            source("#if NGX_RESTY_EXT == 1\nint a;\n#endif\n")

    def test_unbalanced_guard_fails_closed(self):
        with self.assertRaises(ValueError):
            source("#if (NGX_RESTY_EXT)\nint a;\n")


if __name__ == "__main__":
    unittest.main()
