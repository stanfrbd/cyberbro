import pytest

from models.observable import ObservableFlag
from utils.utils import extract_observables, identify_observable_type


@pytest.mark.parametrize(
    "address",
    [
        "alice+alerts@example.com",
        "alice+security+urgent@example.com",
        "first.last+tag@example.co.uk",
        "first_last+2026@example.com",
        "first-last+tag@example.com",
        "Alice+Alerts@Example.COM",
        "+alerts@example.com",
        "+@example.com",
        "alice@example.com",
        "first.last@example.co.uk",
    ],
)
def test_identify_complete_email(address: str) -> None:
    assert identify_observable_type(address) == ObservableFlag.EMAIL


@pytest.mark.parametrize(
    "text,address",
    [
        ("alice+alerts@example.com", "alice+alerts@example.com"),
        ("alice+security+urgent@example.com", "alice+security+urgent@example.com"),
        ("<first.last+tag@example.co.uk>", "first.last+tag@example.co.uk"),
        ("Contact: first_last+2026@example.com", "first_last+2026@example.com"),
        ("(first-last+tag@example.com)", "first-last+tag@example.com"),
        ("Alice+Alerts@Example.COM", "Alice+Alerts@Example.COM"),
        ("<+alerts@example.com>", "+alerts@example.com"),
        ("+@example.com", "+@example.com"),
        ("alice@example.com", "alice@example.com"),
        ("first.last@example.co.uk", "first.last@example.co.uk"),
    ],
)
def test_extract_complete_email(text: str, address: str) -> None:
    emails: list[str] = [
        item.value for item in extract_observables(text) if item.type == ObservableFlag.EMAIL
    ]
    assert emails == [address]


def test_distinct_mailboxes_with_the_same_tag_are_not_deduplicated() -> None:
    addresses: list[str] = ["alice+alerts@example.com", "bob+alerts@example.com"]
    text: str = "\n".join([*addresses, addresses[0]])
    emails: list[str] = [
        item.value for item in extract_observables(text) if item.type == ObservableFlag.EMAIL
    ]
    assert emails == addresses


@pytest.mark.parametrize("text", ["alice+alerts", "alice+alerts@", "alice+alerts@example"])
def test_incomplete_addresses_are_not_emails(text: str) -> None:
    assert not any(item.type == ObservableFlag.EMAIL for item in extract_observables(text))
    with pytest.raises(ValueError, match="Unknown observable type"):
        _ = identify_observable_type(text)
