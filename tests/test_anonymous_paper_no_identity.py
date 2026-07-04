import unittest
from pathlib import Path


class AnonymousPaperNoIdentityTests(unittest.TestCase):
    def test_anonymous_tex_has_no_personal_identity(self):
        path = Path("paper/HeimdallV2_IEEE_Final_Anonymous.tex")
        self.assertTrue(path.exists())
        text = path.read_text(encoding="utf-8").lower()
        self.assertNotIn("zenlik", text)
        self.assertNotIn("github.com/zenlik", text)
        self.assertNotIn("school", text)
        self.assertIn("anonymous authors", text)


if __name__ == "__main__":
    unittest.main()
