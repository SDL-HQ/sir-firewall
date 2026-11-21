"""The code scanning page says which alerts it covers, and its table agrees.

`docs/code-scanning-dismissals.md` opened with "Every CodeQL alert raised
against this repository" and "0 open, 6 closed". Both were statements about
GitHub's list, which nothing in this repository can see, so both went stale
without anything failing: three alerts were raised and dismissed on pull
request #517 and the page went on saying six.

The page now states the range of alert numbers it covers. That is a statement
about the page, so it can be held here: the range and the count in the summary
are the table's, every row is discussed below the table, and the tally of
dispositions is the table's too.

What this does not hold is that the table is GitHub's whole list. That needs
the code scanning API, which a test run from a clone does not have. The page
says so and gives the command.
"""

import re
from collections import Counter
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "docs" / "code-scanning-dismissals.md"
ROW = re.compile(r"^\| #(\d+) \| [^|]+ \| `[^`]+` \| (\*\*fixed\*\*|false positive) \|$", re.MULTILINE)
SUMMARY = re.compile(r"covers alerts \*\*#(\d+) to #(\d+)\*\*, (\w+) of them")
WORDS = {6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve"}


def _rows():
    text = PAGE.read_text(encoding="utf-8")
    return text, [(int(number), disposition.strip("*")) for number, disposition in ROW.findall(text)]


def test_the_summary_names_the_range_and_the_count_the_table_holds():
    text, rows = _rows()
    assert rows, "the alert table was not found"
    numbers = [number for number, _ in rows]
    assert numbers == sorted(set(numbers)), "the table lists an alert twice or out of order"
    first, last, count = SUMMARY.search(text).groups()
    assert (int(first), int(last)) == (numbers[0], numbers[-1])
    assert count == WORDS.get(len(numbers), str(len(numbers)))


def test_the_summary_tallies_the_dispositions_the_table_holds():
    text, rows = _rows()
    tally = Counter(disposition for _, disposition in rows)
    summary = " ".join(text[: text.index("| Alert |")].split())
    assert tally["fixed"] == 1 and "One was fixed." in summary
    assert f"{WORDS[tally['false positive']].capitalize()} are the same rule" in summary


def test_every_alert_in_the_table_is_discussed_below_it():
    text, rows = _rows()
    below = text[text.rindex("| #") :]
    below = below[below.index("\n") :]
    for number, _ in rows:
        assert re.search(rf"#{number}\b", below), f"alert #{number} is in the table and nowhere in the text"


def test_the_page_does_not_claim_a_count_it_cannot_see():
    text, _ = _rows()
    assert "Every CodeQL alert raised" not in text.split("It used to open with")[0]
    assert not re.search(r"\*\*\d+ open", text)
