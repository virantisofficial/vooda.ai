"""Git-history findings must carry the REAL file line, not a line relative to
the concatenated added-content blob. The diff parser captures each added line's
new-file line number from the ``@@ … +new_start @@`` hunk headers; without it a
history finding lands on a low line number (e.g. line 4 = an import header)
instead of the actual secret deep in the file.
"""
from services.secret_scan.git_history import _parse_commit_block


def _commit(*diff_lines):
    return _parse_commit_block(
        ["abc1234567890", "Author", "a@b.com", "2024-01-01", "msg", *diff_lines]
    )


def test_added_line_maps_to_real_file_line():
    ci = _commit(
        "diff --git a/src/client.rs b/src/client.rs",
        "index 1111111..2222222 100644",
        "--- a/src/client.rs",
        "+++ b/src/client.rs",
        "@@ -2560,6 +2560,7 @@ fn bar() {",
        " ctxA",                                       # 2560
        " ctxB",                                       # 2561
        " ctxC",                                       # 2562
        "+    config.password = Default::default();",  # 2563
        " ctxD",                                       # 2564
    )
    d = ci.diffs[0]
    assert d.file_path == "src/client.rs"
    assert d.added_lines == ["    config.password = Default::default();"]
    assert d.added_line_nums == [2563]  # 2560 + 3 context lines before it


def test_multi_hunk_and_removed_lines_dont_shift_new_file_line():
    ci = _commit(
        "diff --git a/f.py b/f.py",
        "+++ b/f.py",
        "@@ -10,3 +10,4 @@",
        " a",          # 10
        "+SECRET1",    # 11
        " b",          # 12
        "@@ -50,4 +51,5 @@",
        " x",          # 51
        "-removed",    # absent from new file → does not advance the counter
        "+SECRET2",    # 52
        " y",          # 53
    )
    d = ci.diffs[0]
    assert d.added_lines == ["SECRET1", "SECRET2"]
    assert d.added_line_nums == [11, 52]


def test_parallel_arrays_stay_aligned():
    ci = _commit(
        "diff --git a/x b/x",
        "+++ b/x",
        "@@ -1,0 +1,3 @@",
        "+one",        # 1
        "+two",        # 2
        "+three",      # 3
    )
    d = ci.diffs[0]
    assert len(d.added_lines) == len(d.added_line_nums)
    assert d.added_line_nums == [1, 2, 3]
