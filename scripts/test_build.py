#!/usr/bin/env python3
"""Test suite for build.py. Run: python scripts/test_build.py (stdlib only)."""
import io
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build  # noqa: E402  (after sys.path fix)


class TestParseSrc(unittest.TestCase):
    def setUp(self):
        self.orig_src = build.SRC
        build.SRC = Path(tempfile.mkdtemp())

    def tearDown(self):
        build.SRC = self.orig_src

    def write(self, name, text):
        p = build.SRC / name
        p.write_text(text, encoding="utf-8")

    def test_annotations_and_comments_stripped(self):
        self.write("safe.txt", (
            "# comment line\n"
            "snu.lge.com # STRICT: OTA\n"
            "\n"
            "LGSMARTAD.com # caps lowered, comment stripped\n"
        ))
        self.assertEqual(build.parse_src("safe.txt"), ["lgsmartad.com", "snu.lge.com"])

    def test_new_lg_apexes_accepted(self):
        # lggalleryplus.com / lgsmartweb.com allowlisted 2026-09-11.
        self.write("strict.txt", (
            "lggalleryplus.com # STRICT: weak\n"
            "lgsmartweb.com # STRICT: weak\n"
        ))
        self.assertEqual(build.parse_src("strict.txt"),
                         ["lggalleryplus.com", "lgsmartweb.com"])

    def test_ueiwsp_accepted(self):
        # ueiwsp.com (QuickSet Cloud / UEI) allowlisted 2026-09-11, issue #3.
        self.write("strict.txt", (
            "ueiwsp.com # STRICT: weak — interop: QuickSet Cloud (UEI) discovery API; "
            "community report 2026-09-11 (repo issue #3 querylog; device unstated; "
            "not observed on G1; www subdomain observed live on G1 2026-09-12); "
            "breakage untested\n"
            "www.ueiwsp.com # STRICT: interop: QuickSet Cloud (UEI) discovery API; "
            "community report 2026-09-11 (repo issue #3 querylog); "
            "observed on G1 2026-09-12 (11 queries / 48 min; AGH querylog via Fritz relay); "
            "breakage untested\n"
        ))
        self.assertEqual(build.parse_src("strict.txt"),
                         ["ueiwsp.com", "www.ueiwsp.com"])

    def test_ueiwsp_near_misses_rejected(self):
        # Suffix matching must be label-boundary exact: "notueiwsp.com" ends
        # with "ueiwsp.com" as a bare string (no dot boundary), while
        # "ueiwsp.com.evil.example" only has it as a leading label.
        for host in ("notueiwsp.com", "ueiwsp.com.evil.example"):
            with self.subTest(host=host):
                self.write("strict.txt", f"{host} # STRICT: weak — near-miss fixture\n")
                with self.assertRaises(ValueError) as ctx:
                    build.parse_src("strict.txt")
                self.assertIn("not an LG family hostname", str(ctx.exception))

    def test_malformed_rejected(self):
        self.write("safe.txt", "not a hostname!! # nope\n")
        with self.assertRaises(ValueError):
            build.parse_src("safe.txt")

    def test_non_lg_rejected(self):
        self.write("safe.txt", "evil.example.com # not LG\n")
        with self.assertRaises(ValueError):
            build.parse_src("safe.txt")

    def test_suffix_lookalike_rejected(self):
        # "evillge.com" string-ends with "lge.com" but is not in the LG family.
        self.write("safe.txt", "evillge.com # lookalike suffix\n")
        with self.assertRaises(ValueError) as ctx:
            build.parse_src("safe.txt")
        self.assertIn("not an LG family hostname", str(ctx.exception))

    def test_single_trailing_dot_stripped(self):
        self.write("safe.txt", "snu.lge.com. # exactly one trailing dot\n")
        self.assertEqual(build.parse_src("safe.txt"), ["snu.lge.com"])

    def test_multiple_trailing_dots_rejected(self):
        for host in ("snu.lge.com..", "snu.lge.com..."):
            with self.subTest(host=host):
                self.write("safe.txt", f"{host} # extra trailing dots\n")
                with self.assertRaises(ValueError) as ctx:
                    build.parse_src("safe.txt")
                self.assertIn("safe.txt:1: malformed hostname", str(ctx.exception))

    def test_duplicate_rejected_with_line_numbers(self):
        self.write("safe.txt", "snu.lge.com # one\nsnu.lge.com # two\n")
        with self.assertRaises(ValueError) as ctx:
            build.parse_src("safe.txt")
        self.assertIn("safe.txt:2: duplicate", str(ctx.exception))
        self.assertIn("first at line 1", str(ctx.exception))


class TestCompileTier(unittest.TestCase):
    def test_safe_has_three_formats_no_zones(self):
        out = build.compile_tier("safe", ["a.lge.com"], ["lge.com"])
        self.assertIn("0.0.0.0 a.lge.com", out["safe-hosts.txt"])
        self.assertIn("||a.lge.com^", out["safe-adblock.txt"])
        self.assertIn("a.lge.com", out["safe-domains.txt"])
        body = [l for l in out["safe-domains.txt"].splitlines() if not l.startswith("#")]
        self.assertNotIn("lge.com", body)

    def test_strict_merges_zones_as_apex_and_adblock_zone(self):
        out = build.compile_tier("strict", ["snu.lge.com"], ["lge.com"])
        self.assertIn("0.0.0.0 lge.com", out["strict-hosts.txt"])
        self.assertIn("||lge.com^", out["strict-adblock.txt"])

    def test_headers_shape_and_counts(self):
        out = build.compile_tier("safe", ["a.lge.com", "b.lge.com"], [])
        first = out["safe-domains.txt"].splitlines()
        self.assertEqual(first[0], "# Title: LG TV Blocklist (safe)")
        self.assertEqual(first[2], "# Entries: 2")
        self.assertIn(build.LICENSE_LINE, first)
        self.assertEqual(out["safe-hosts.txt"].splitlines()[5], "0.0.0.0 a.lge.com")


class TestRegionCrossProduct(unittest.TestCase):
    def setUp(self):
        self.orig_src = build.SRC
        build.SRC = Path(tempfile.mkdtemp())

    def tearDown(self):
        build.SRC = self.orig_src

    def write(self, name, text):
        (build.SRC / name).write_text(text, encoding="utf-8")

    def base(self, safe="", strict="", zones="", regions=None):
        self.write("safe.txt", safe)
        self.write("strict.txt", strict)
        self.write("zones.txt", zones)
        if regions is not None:
            self.write("regions.txt", regions)

    def test_absent_regions_file_means_no_expansion(self):
        self.base(safe="de.nextlgsdp.com # SAFE [REGION-SCOPED]\n")
        safe, _, _ = build.load_all()
        self.assertEqual(safe, ["de.nextlgsdp.com"])

    def test_tagged_entry_expands_across_codes(self):
        self.base(safe="de.nextlgsdp.com # SAFE [REGION-SCOPED]\n",
                  regions="de\nfr\nbr\n")
        safe, _, _ = build.load_all()
        self.assertEqual(safe, ["br.nextlgsdp.com", "de.nextlgsdp.com", "fr.nextlgsdp.com"])

    def test_untagged_region_shaped_host_never_expands(self):
        # The whole point of the explicit tag: ad.lgappstv.com is an AD host on
        # the store CDN, not Andorra. Expanding it would emit bogus store-CDN
        # entries and could break the Content Store for everyone.
        self.base(safe="ad.lgappstv.com # SAFE: ad delivery, NOT a region\n"
                       "am.lge.com # SAFE: unknown, NOT a region\n",
                  regions="de\nfr\nbr\nad\nam\n")
        safe, _, _ = build.load_all()
        self.assertEqual(safe, ["ad.lgappstv.com", "am.lge.com"])

    def test_audited_entry_not_duplicated_by_its_generated_twin(self):
        self.base(safe="de.nextlgsdp.com # SAFE: audited [REGION-SCOPED]\n",
                  regions="de\nfr\n")
        safe, _, _ = build.load_all()
        self.assertEqual(sorted(safe), sorted(set(safe)))
        self.assertEqual(safe.count("de.nextlgsdp.com"), 1)

    def test_strict_stays_a_delta_of_safe(self):
        self.base(safe="de.nextlgsdp.com # SAFE [REGION-SCOPED]\n",
                  strict="de.lgeapi.com # STRICT [REGION-SCOPED]\n",
                  regions="de\nfr\n")
        safe, delta, _ = build.load_all()
        self.assertEqual(set(safe) & set(delta), set())
        self.assertEqual(sorted(delta), ["de.lgeapi.com", "fr.lgeapi.com"])

    def test_explicit_subset_limits_expansion(self):
        # ibs.nextlgsdp.com exists in 20 of 49 markets; generating the other 29
        # would ship NXDOMAIN entries, which upstream blocklists reject.
        self.base(safe="a.lge.com # SAFE\n",
                  strict="de.ibs.nextlgsdp.com # STRICT [REGION-SCOPED: de fr]\n",
                  regions="de\nfr\nbr\nza\n")
        _, delta, _ = build.load_all()
        self.assertEqual(sorted(delta), ["de.ibs.nextlgsdp.com", "fr.ibs.nextlgsdp.com"])

    def test_subset_intersected_with_regions_file(self):
        # A code in the tag but not in regions.txt must not be emitted.
        self.base(safe="de.nextlgsdp.com # SAFE [REGION-SCOPED: de fr jp]\n",
                  regions="de\nfr\n")
        safe, _, _ = build.load_all()
        self.assertEqual(safe, ["de.nextlgsdp.com", "fr.nextlgsdp.com"])

    def test_bare_tag_still_expands_to_every_code(self):
        self.base(safe="de.nextlgsdp.com # SAFE [REGION-SCOPED]\n", regions="de\nfr\nbr\n")
        safe, _, _ = build.load_all()
        self.assertEqual(len(safe), 3)

    def test_malformed_tag_is_a_hard_error_never_silently_ignored(self):
        # A tag the parser cannot read must raise. If it merely failed to match,
        # the family would lose its entire regional coverage with no signal.
        for bad in ("[REGION-SCOPED: de FRANCE]", "[REGION-SCOPED de fr]",
                    "[REGION-SCOPED: ]", "[REGION-SCOPED: d]",
                    "[REGION SCOPED]", "[region-scoped: de]"):
            with self.subTest(tag=bad):
                self.base(safe=f"de.nextlgsdp.com # SAFE {bad}\n", regions="de\nfr\n")
                with self.assertRaises(ValueError):
                    build.load_all()

    def test_tag_without_two_letter_first_label_rejected(self):
        self.base(safe="lgtvsdp.com # SAFE: apex, no region label [REGION-SCOPED]\n",
                  regions="de\n")
        with self.assertRaises(ValueError) as cm:
            build.load_all()
        self.assertIn("REGION-SCOPED", str(cm.exception))

    def test_malformed_and_duplicate_region_codes_rejected(self):
        for bad in ("USA\n", "d\n", "deu\n", "de\nde\n"):
            with self.subTest(regions=bad):
                self.base(safe="a.lge.com # SAFE\n", regions=bad)
                with self.assertRaises(ValueError):
                    build.load_all()

    def test_region_names_parsed_for_readme_table(self):
        self.base(safe="a.lge.com # SAFE\n",
                  regions="br # Brazil\nde # Germany — audit origin\nzz\n")
        self.assertEqual(build.parse_regions(),
                         {"br": "Brazil", "de": "Germany", "zz": "ZZ"})

    def test_country_table_links_every_country_and_format(self):
        table = build.country_table({"br": "Brazil", "us": "United States"})
        for code in ("br", "us"):
            for tier in ("safe", "strict"):
                for fmt in ("domains", "adblock", "hosts"):
                    self.assertIn(f"/lists-regions/{code}/{tier}-{fmt}.txt", table)
        self.assertIn("🇧🇷", table)
        self.assertIn("🇺🇸", table)

    def test_readme_missing_markers_raises(self):
        orig = build.README
        build.README = build.SRC / "README.md"
        try:
            build.README.write_text("# no markers here\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                build.update_readme({"br": "Brazil"})
        finally:
            build.README = orig


class TestWildcard(unittest.TestCase):
    def test_region_regex_matches_every_code_including_unlisted(self):
        lines = build.wildcard_lines({"nextlgsdp.com": None}, [])
        pat = re.compile(lines[0])
        for code in ("de", "us", "br", "zz"):  # zz: a market not yet enumerated
            self.assertTrue(pat.search(f"{code}.nextlgsdp.com"), code)
        # It must not reach the apex or non-region subdomains.
        self.assertFalse(pat.search("nextlgsdp.com"))
        self.assertFalse(pat.search("ibs.nextlgsdp.com"))

    def test_family_under_a_wildcarded_apex_is_skipped(self):
        lines = build.wildcard_lines({"ibs.nextlgsdp.com": None}, ["nextlgsdp.com"])
        self.assertEqual(lines, [r"(\.|^)nextlgsdp\.com$"])

    def test_safe_wildcard_never_covers_lge_com(self):
        # lge.com carries the Content Store, OTA and account login. A SAFE
        # wildcard there would break all three -- the exact thing SAFE promises
        # not to do -- so zones.txt must never reach the SAFE wildcard file.
        out = build.compile_wildcard("safe", {"nextlgsdp.com": None},
                                     ["lgsmartad.com"])
        pats = [re.compile(l) for l in out.splitlines()
                if l and not l.startswith("#")]
        for host in ("lge.com", "snu.lge.com", "lgeapi.com", "netflix.com"):
            with self.subTest(host=host):
                self.assertFalse(any(p.search(host) for p in pats), host)

    def test_wildcard_header_warns_against_adlist_use(self):
        out = build.compile_wildcard("safe", {"nextlgsdp.com": None}, [])
        self.assertIn("NOT AN ADLIST", out.upper())
        self.assertIn("# Entries: 1", out)

    def test_every_wildcard_line_is_a_valid_regex(self):
        out = build.compile_wildcard(
            "strict", {"emp.lgsmartplatform.com": None, "ibs.nextlgsdp.com": ("de",)},
            ["lge.com", "nextlgsdp.com"])
        for line in out.splitlines():
            if line and not line.startswith("#"):
                re.compile(line)  # raises on a malformed pattern


class TestLoadAll(unittest.TestCase):
    def test_strict_overlap_fails(self):
        with tempfile.TemporaryDirectory() as td:
            old = build.SRC
            build.SRC = Path(td)
            try:
                (build.SRC / "safe.txt").write_text("snu.lge.com\n", encoding="utf-8")
                (build.SRC / "strict.txt").write_text("snu.lge.com\n", encoding="utf-8")
                (build.SRC / "zones.txt").write_text("lge.com\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    build.load_all()
            finally:
                build.SRC = old

    def test_roundtrip_superset_counts(self):
        with tempfile.TemporaryDirectory() as td:
            old = build.SRC
            build.SRC = Path(td)
            try:
                (build.SRC / "safe.txt").write_text("a.lge.com\n", encoding="utf-8")
                (build.SRC / "strict.txt").write_text("snu.lge.com\n", encoding="utf-8")
                (build.SRC / "zones.txt").write_text("lge.com\n", encoding="utf-8")
                safe, delta, zones = build.load_all()
                strict_total = len(set(safe) | set(delta) | set(zones))
                self.assertEqual((safe, delta, zones), (["a.lge.com"], ["snu.lge.com"], ["lge.com"]))
                self.assertEqual(strict_total, 3)
            finally:
                build.SRC = old


class TestDryRunAndCheck(unittest.TestCase):
    def test_check_prints_ok_no_exception(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            build.check()
        self.assertIn("check OK", buf.getvalue())

    def test_check_missing_source_file_reports_error(self):
        with tempfile.TemporaryDirectory() as td:
            old = build.SRC
            build.SRC = Path(td)
            try:
                err = io.StringIO()
                with redirect_stderr(err):
                    rc = build.main(["check"])
                self.assertEqual(rc, 1)
                self.assertIn("ERROR", err.getvalue())
                self.assertIn("safe.txt", err.getvalue())
            finally:
                build.SRC = old

    def test_check_exit_code_one_on_error(self):
        with tempfile.TemporaryDirectory() as td:
            old = build.SRC
            build.SRC = Path(td)
            try:
                (build.SRC / "safe.txt").write_text("bogus!!\n", encoding="utf-8")
                (build.SRC / "strict.txt").write_text("", encoding="utf-8")
                (build.SRC / "zones.txt").write_text("", encoding="utf-8")
                err = io.StringIO()
                with redirect_stderr(err):
                    rc = build.main(["check"])
                self.assertEqual(rc, 1)
                self.assertIn("ERROR", err.getvalue())
            finally:
                build.SRC = old


if __name__ == "__main__":
    unittest.main()
