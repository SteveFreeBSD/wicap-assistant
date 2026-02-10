from __future__ import annotations

from wicap_assist.extract.signals import extract_operational_signals


def test_meta_first_person_fix_chatter_not_classified_as_outcome() -> None:
    text = "I’ve fixed and revalidated the tests. Next I’ll run one real wicap-assist recommend command."
    signals = extract_operational_signals(text)
    outcome_categories = [signal for signal in signals if signal.category == "outcomes"]
    assert outcome_categories == []
