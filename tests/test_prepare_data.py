"""Tests for dataset preparation (parsing, cleaning, overlap removal, time split)."""

from __future__ import annotations

import bz2
import csv
import gzip
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ml.features import registered_domain
from ml.prepare_data import (
    BENIGN,
    MALICIOUS,
    TEST,
    TRAIN,
    Report,
    Sample,
    build_dataset,
    cap_per_key,
    discover,
    main,
    parse_time,
    read_benign,
    read_malicious,
    split_by_time,
    url_to_host,
)

DAY0 = datetime(2026, 1, 1, tzinfo=timezone.utc)

PHISHTANK_HEADER = "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"
URLHAUS_HEADER = "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"


def phishtank_line(host: str, day: int, verified: str = "yes", path: str = "/login") -> str:
    when = (DAY0 + timedelta(days=day)).isoformat()
    return f'{day},"http://{host}{path}",http://x/{day},{when},{verified},{when},yes,Other\n'


# ----- url_to_host -----


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://Evil.Example.com/login?a=1", "evil.example.com"),
        ("https://user:pw@evil.example.com:8443/x", "evil.example.com"),
        ("evil.example.com/path", "evil.example.com"),
        ("evil.example.com.", "evil.example.com"),
        ("http://bücher.example/page", "xn--bcher-kva.example"),
    ],
)
def test_url_to_host_extracts_clean_hostnames(value: str, expected: str) -> None:
    assert url_to_host(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "   ", "http://192.168.1.5/login", "http://[::1]/x", "http://-bad-.example/", "http://", "http://a b.com"],
)
def test_url_to_host_rejects_unusable_input(value: str) -> None:
    assert url_to_host(value) is None


# ----- parse_time -----


def test_parse_time_formats() -> None:
    assert parse_time("2026-03-04T05:06:07+00:00") == datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
    assert parse_time("2026-03-04 05:06:07") == datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
    assert parse_time("2026-03-04T08:06:07+03:00") == datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
    assert parse_time("2026-03-04T05:06:07Z") == datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
    assert parse_time("not a date") is None
    assert parse_time("") is None


# ----- readers -----


def test_read_phishtank_style_file(tmp_path: Path) -> None:
    path = tmp_path / "phishtank.csv"
    path.write_text(
        PHISHTANK_HEADER
        + phishtank_line("good.example", 1)
        + phishtank_line("notverified.example", 2, verified="no")
        + phishtank_line("1.2.3.4", 3, path="/x").replace("1.2.3.4", "1.2.3.4")
        + phishtank_line("later.example", 4),
        encoding="utf-8",
    )
    report = Report()
    rows = list(read_malicious(path, report))
    assert [host for host, _, _ in rows] == ["good.example", "later.example"]
    assert rows[0][2] == "phishtank"
    assert report.counts["phishtank: rows not verified"] == 1
    assert report.counts["phishtank: rows with unusable host"] == 1


def test_read_urlhaus_style_file_with_commented_header(tmp_path: Path) -> None:
    path = tmp_path / "urlhaus.csv"
    path.write_text(
        "################\n# URLhaus database dump\n################\n"
        + URLHAUS_HEADER
        + '"1","2026-02-01 10:00:00","http://bad.example/a.exe","online","","malware_download","elf","https://urlhaus/1","r"\n'
        + '"2","2026-02-02 10:00:00","http://worse.example/b","online","","malware_download","","https://urlhaus/2","r"\n',
        encoding="utf-8",
    )
    rows = list(read_malicious(path, Report()))
    assert [host for host, _, _ in rows] == ["bad.example", "worse.example"]
    assert rows[0][1] == datetime(2026, 2, 1, 10, 0, tzinfo=timezone.utc)
    assert rows[0][2] == "urlhaus"


def test_malicious_file_without_header_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "phishtank.csv"
    path.write_text("http://a.example/x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="header"):
        list(read_malicious(path, Report()))


def test_rows_without_a_date_are_counted_and_skipped(tmp_path: Path) -> None:
    path = tmp_path / "phishtank.csv"
    path.write_text(PHISHTANK_HEADER + '1,"http://a.example",x,garbage,yes,,yes,Other\n', encoding="utf-8")
    report = Report()
    assert list(read_malicious(path, report)) == []
    assert report.counts["phishtank: rows without a usable date"] == 1


@pytest.mark.parametrize("kind", ["plain", "gz", "bz2", "zip"])
def test_benign_reader_handles_compressed_files(tmp_path: Path, kind: str) -> None:
    content = "1,google.com\n2,Example.ORG\n3,not a domain!\n"
    if kind == "plain":
        path = tmp_path / "tranco.csv"
        path.write_text(content, encoding="utf-8")
    elif kind == "gz":
        path = tmp_path / "tranco.csv.gz"
        path.write_bytes(gzip.compress(content.encode()))
    elif kind == "bz2":
        path = tmp_path / "tranco.csv.bz2"
        path.write_bytes(bz2.compress(content.encode()))
    else:
        path = tmp_path / "tranco.csv.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("top-1m.csv", content)
    report = Report()
    assert list(read_benign(path, report)) == ["google.com", "example.org"]
    assert report.counts["benign rows invalid"] == 1


# ----- building the dataset -----


def _write_inputs(tmp_path: Path, malicious_days: int = 40) -> tuple[Path, Path]:
    benign = tmp_path / "tranco.csv"
    benign.write_text(
        "".join(f"{i},site{i}.com\n" for i in range(1, 201))
        + "201,overlap.example.net\n"
        + "202,shared-owner.example.org\n",
        encoding="utf-8",
    )
    lines = [PHISHTANK_HEADER]
    for day in range(malicious_days):
        lines.append(phishtank_line(f"phish{day}.bad-{day}.xyz", day))
    lines.append(phishtank_line("overlap.example.net", 5))  # same host as a benign one
    lines.append(phishtank_line("login.shared-owner.example.org", 6))  # benign registered domain
    lines.append(phishtank_line("phish3.bad-3.xyz", 30))  # duplicate, later sighting
    malicious = tmp_path / "phishtank.csv"
    malicious.write_text("".join(lines), encoding="utf-8")
    return benign, malicious


def test_build_dataset_removes_duplicates_and_overlap(tmp_path: Path) -> None:
    benign, malicious = _write_inputs(tmp_path)
    rows, report = build_dataset([benign], [malicious], benign_limit=1000)
    hosts = {sample.host: sample for sample, _ in rows}

    assert "overlap.example.net" not in hosts  # in both sets: dropped from both
    assert "login.shared-owner.example.org" not in hosts  # malicious on a benign registered domain
    assert report.counts["malicious duplicates removed"] == 1
    assert report.counts["hosts in both sets (dropped from both)"] == 1
    assert report.counts["malicious hosts on a benign registered domain (dropped)"] == 1
    # the duplicate keeps its earliest sighting (day 3), not day 30
    assert hosts["phish3.bad-3.xyz"].first_seen == DAY0 + timedelta(days=3)

    labels = [sample.label for sample, _ in rows]
    assert labels.count(MALICIOUS) == 40
    assert labels.count(BENIGN) == 201  # 200 sites + shared-owner.example.org
    assert len({sample.host for sample, _ in rows}) == len(rows)  # no host twice


def test_no_registered_domain_appears_in_both_classes(tmp_path: Path) -> None:
    benign, malicious = _write_inputs(tmp_path)
    rows, _ = build_dataset([benign], [malicious], benign_limit=1000)
    bad = {registered_domain(s.host) for s, _ in rows if s.label == MALICIOUS}
    good = {registered_domain(s.host) for s, _ in rows if s.label == BENIGN}
    assert bad.isdisjoint(good)


def test_split_is_time_based_for_malicious(tmp_path: Path) -> None:
    benign, malicious = _write_inputs(tmp_path)
    rows, _ = build_dataset([benign], [malicious], benign_limit=1000, test_fraction=0.25)
    train = [s.first_seen for s, sp in rows if s.label == MALICIOUS and sp == TRAIN]
    test = [s.first_seen for s, sp in rows if s.label == MALICIOUS and sp == TEST]
    assert train and test
    assert max(t for t in train if t) <= min(t for t in test if t)  # test is strictly newer
    assert len(test) == 10  # 25% of 40


def test_benign_split_follows_the_same_ratio(tmp_path: Path) -> None:
    benign, malicious = _write_inputs(tmp_path)
    rows, _ = build_dataset([benign], [malicious], benign_limit=1000, test_fraction=0.2)
    benign_test = sum(1 for s, sp in rows if s.label == BENIGN and sp == TEST)
    benign_total = sum(1 for s, _ in rows if s.label == BENIGN)
    assert abs(benign_test / benign_total - 0.2) < 0.05


def test_benign_limit_is_a_seeded_random_sample(tmp_path: Path) -> None:
    benign, malicious = _write_inputs(tmp_path)
    first, _ = build_dataset([benign], [malicious], benign_limit=50, seed=1)
    again, _ = build_dataset([benign], [malicious], benign_limit=50, seed=1)
    other, _ = build_dataset([benign], [malicious], benign_limit=50, seed=2)

    def benign_hosts(rows: list[tuple[Sample, str]]) -> set[str]:
        return {s.host for s, _ in rows if s.label == BENIGN}

    assert len(benign_hosts(first)) == 50
    assert benign_hosts(first) == benign_hosts(again)
    assert benign_hosts(first) != benign_hosts(other)
    # a random sample, not simply the first 50 ranks
    assert benign_hosts(first) != {f"site{i}.com" for i in range(1, 51)}


def test_empty_side_after_cleaning_is_an_error(tmp_path: Path) -> None:
    benign = tmp_path / "tranco.csv"
    benign.write_text("1,only.example\n", encoding="utf-8")
    malicious = tmp_path / "phishtank.csv"
    malicious.write_text(PHISHTANK_HEADER + phishtank_line("only.example", 1), encoding="utf-8")
    with pytest.raises(ValueError, match="at least one"):
        build_dataset([benign], [malicious])


# ----- split_by_time directly -----


def _sample(host: str, day: int, label: int = MALICIOUS) -> Sample:
    return Sample(host, label, "test", DAY0 + timedelta(days=day) if label == MALICIOUS else None)


def test_hosts_of_one_registered_domain_stay_together() -> None:
    malicious = [_sample(f"h{i}.attacker.xyz", day) for i, day in enumerate([1, 2, 30, 31])]
    malicious += [_sample(f"x{day}.other{day}.top", day) for day in range(3, 29)]
    assignment = split_by_time(malicious, [], test_fraction=0.3, seed=0)
    sides = {assignment[f"h{i}.attacker.xyz"] for i in range(4)}
    assert len(sides) == 1  # never split across train and test


def test_oldest_group_is_never_in_the_test_set() -> None:
    malicious = [_sample("a.one.xyz", 1), _sample("b.two.xyz", 2)]
    assignment = split_by_time(malicious, [], test_fraction=0.99, seed=0)
    assert assignment["a.one.xyz"] == TRAIN
    assert assignment["b.two.xyz"] == TEST


@pytest.mark.parametrize("fraction", [0.0, 1.0, -0.1, 1.5])
def test_invalid_test_fraction_is_rejected(fraction: float) -> None:
    with pytest.raises(ValueError):
        split_by_time([_sample("a.one.xyz", 1)], [], fraction, 0)


# ----- command line -----


def test_cli_writes_the_dataset(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    benign, malicious = _write_inputs(tmp_path)
    out = tmp_path / "out" / "dataset.csv"
    code = main(["--benign", str(benign), "--malicious", str(malicious), "--out", str(out)])
    assert code == 0
    with out.open(encoding="utf-8", newline="") as handle:
        table = list(csv.DictReader(handle))
    assert set(table[0]) == {"host", "label", "source", "first_seen", "registered_domain", "split"}
    assert {row["split"] for row in table} == {TRAIN, TEST}
    assert {row["label"] for row in table} == {"0", "1"}
    printed = capsys.readouterr().out
    assert "Cleaning report" in printed
    assert "train:" in printed  # the date range of the time-based split


def test_cli_without_inputs_explains_what_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import ml.prepare_data as module

    monkeypatch.setattr(module, "RAW_DIR", tmp_path)  # an empty folder
    assert main([]) == 1
    assert "Missing input" in capsys.readouterr().err


# ----- PhishStats-style files, score filter and per-owner limit -----


def _phishstats_file(path: Path, rows: list[tuple[int, str, int, str]]) -> Path:
    """rows: (id, host, day, score) -> CSV in the format ml.fetch_phishstats writes."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "url", "first_seen", "score"])
        for ident, host, day, score in rows:
            writer.writerow([ident, f"http://{host}/login", (DAY0 + timedelta(days=day)).isoformat(), score])
    return path


def test_score_threshold_skips_weak_and_unscored_reports(tmp_path: Path) -> None:
    path = _phishstats_file(
        tmp_path / "phishstats.csv",
        [(1, "strong.example", 1, "8.0"), (2, "borderline.example", 2, "5.0"), (3, "weak.example", 3, "2.5"), (4, "none.example", 4, "")],
    )
    report = Report()
    rows = list(read_malicious(path, report, min_score=5.0))
    assert [host for host, _, _ in rows] == ["strong.example", "borderline.example"]
    assert report.counts["phishstats: rows below the score threshold"] == 2
    assert rows[0][2] == "phishstats"


def test_keep_unscored_keeps_empty_scores_but_still_drops_weak_ones(tmp_path: Path) -> None:
    path = _phishstats_file(
        tmp_path / "phishstats.csv",
        [(1, "strong.example", 1, "8.0"), (2, "weak.example", 2, "2.5"), (3, "none.example", 3, "")],
    )
    report = Report()
    rows = list(read_malicious(path, report, min_score=5.0, keep_unscored=True))
    assert [host for host, _, _ in rows] == ["strong.example", "none.example"]
    assert report.counts["phishstats: rows below the score threshold"] == 1
    assert report.counts["phishstats: unscored rows kept"] == 1


def test_build_dataset_keep_unscored_flag(tmp_path: Path) -> None:
    benign, _ = _write_inputs(tmp_path)
    reports = [(i, f"phish{i}.bad{i}.xyz", i, "" if i % 2 else "8.0") for i in range(1, 21)]
    malicious = _phishstats_file(tmp_path / "phishstats.csv", reports)
    strict, _ = build_dataset([benign], [malicious], benign_limit=1000, min_score=5.0)
    loose, report = build_dataset([benign], [malicious], benign_limit=1000, min_score=5.0, keep_unscored=True)
    assert sum(s.label == MALICIOUS for s, _ in strict) == 10
    assert sum(s.label == MALICIOUS for s, _ in loose) == 20
    assert report.counts["phishstats: unscored rows kept"] == 10


def test_without_a_threshold_every_row_is_read(tmp_path: Path) -> None:
    path = _phishstats_file(tmp_path / "phishstats.csv", [(1, "a.example", 1, "1.0"), (2, "b.example", 2, "")])
    assert len(list(read_malicious(path, Report()))) == 2


def test_cap_per_key_limits_each_owner_and_platform() -> None:
    hosts = [f"pub-{i}.r2.dev" for i in range(30)]  # one shared platform
    hosts += [f"sub{i}.bigsite.com" for i in range(30)]  # one registered domain
    hosts += ["alone.example.org", "other.example.net"]
    kept, dropped = cap_per_key(hosts, limit=10, seed=1)
    assert dropped == 40
    assert sum(h.endswith(".r2.dev") for h in kept) == 10
    assert sum(h.endswith(".bigsite.com") for h in kept) == 10
    assert "alone.example.org" in kept and "other.example.net" in kept
    assert cap_per_key(hosts, limit=10, seed=1) == (kept, dropped)  # deterministic


def test_cap_does_not_merge_unrelated_domains_under_one_suffix() -> None:
    hosts = [f"site{i}.com" for i in range(30)]  # 30 different owners under ".com"
    kept, dropped = cap_per_key(hosts, limit=5, seed=0)
    assert dropped == 0 and len(kept) == 30


def test_build_dataset_applies_score_and_owner_limits(tmp_path: Path) -> None:
    benign, _ = _write_inputs(tmp_path)
    reports = [(i, f"pub-{i}.r2.dev", i % 40, "9.0") for i in range(1, 81)]  # one platform, 80 hosts
    reports += [(100 + i, f"phish{i}.bad{i}.xyz", i % 40, "7.0") for i in range(30)]
    reports += [(200 + i, f"weak{i}.bad-weak{i}.top", i % 40, "1.0") for i in range(10)]
    malicious = _phishstats_file(tmp_path / "phishstats.csv", reports)
    rows, report = build_dataset(
        [benign], [malicious], benign_limit=1000, min_score=5.0, max_per_key=20
    )
    bad = [s.host for s, _ in rows if s.label == MALICIOUS]
    assert sum(h.endswith(".r2.dev") for h in bad) == 20
    assert not any("weak" in h for h in bad)
    assert len(bad) == 20 + 30
    assert report.counts["malicious hosts over the per-owner limit (dropped)"] == 60
    assert report.counts["phishstats: rows below the score threshold"] == 10


# ----- finding the files -----


def test_discover_finds_phishstats_and_ignores_urlhaus(tmp_path: Path) -> None:
    for name in ("tranco.csv.zip", "phishstats.csv", "phishtank.csv.bz2", "urlhaus.csv", "notes.txt"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    benign, malicious = discover(tmp_path)
    assert [p.name for p in benign] == ["tranco.csv.zip"]
    assert [p.name for p in malicious] == ["phishstats.csv", "phishtank.csv.bz2"]
