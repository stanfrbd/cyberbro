import pytest

from models.observable import Observable, ObservableFlag
from utils.utils import extract_observables


@pytest.mark.parametrize(
    "address",
    [
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
        "2001:db8::1:2:3:4:5",
        "2001:db8:1:2:3:4::5",
        "::ffff:192.0.2.128",
        "::ffff:0:192.0.2.128",
        "2001:db8::192.0.2.128",
        "fe80::1%eth0",
        "fe80::7:8%1",
        "::1",
        "::",
        "2001:db8::",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    ],
)
def test_extract_complete_ipv6_address(address: str) -> None:
    results: list[Observable] = extract_observables(address)
    ipv6: list[str] = [item.value for item in results if item.type is ObservableFlag.IPV6]

    assert ipv6 == [address]


@pytest.mark.parametrize("text", ["Address: {}.", "[{}]:443", "({}),", "src={};"])
def test_extract_ipv6_with_surrounding_punctuation(text: str) -> None:
    address: str = "2001:4860:4860::8888"

    assert extract_observables(text.format(address)) == [
        Observable(value=address, type=ObservableFlag.IPV6)
    ]


def test_extract_distinct_ipv6_addresses_and_deduplicate_repeats() -> None:
    first: str = "2001:4860:4860::8888"
    second: str = "2001:4860:4860::8844"

    assert extract_observables(f"{first}\n{second}\n{first}") == [
        Observable(value=first, type=ObservableFlag.IPV6),
        Observable(value=second, type=ObservableFlag.IPV6),
    ]
