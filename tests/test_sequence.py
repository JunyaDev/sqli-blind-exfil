from blindsqli.sequence import SequencePredictor


def test_detects_recurring_prefix():
    sp = SequencePredictor(min_prefix=2)
    for v in ["jun_users", "jun_roles", "jun_projects", "jun_tasks"]:
        sp.learn_value(v)
    hyps = sp.propose(known_prefix="", remaining_max=20)
    seqs = [h.sequence for h in hyps]
    assert any(s.startswith("jun_") for s in seqs)


def test_completion_of_seen_value():
    sp = SequencePredictor(min_prefix=2)
    sp.learn_value("jun_users")
    hyps = sp.propose(known_prefix="jun_", remaining_max=20)
    assert any(h.sequence == "users" for h in hyps)


def test_respects_remaining_max():
    sp = SequencePredictor(min_prefix=2)
    sp.learn_value("jun_users")
    hyps = sp.propose(known_prefix="", remaining_max=3)
    assert all(len(h.sequence) <= 3 for h in hyps)


def test_cost_model_prefers_sequence_when_confident():
    sp = SequencePredictor()
    from blindsqli.sequence import SequenceHypothesis
    confident = SequenceHypothesis("jun_", 0.9, "test")
    # with ~4 requests/char char-by-char, a confident 4-char guess should win
    assert sp.worth_testing(confident, per_char_requests=4.0)


def test_cost_model_rejects_unlikely_sequence():
    sp = SequencePredictor()
    from blindsqli.sequence import SequenceHypothesis
    unlikely = SequenceHypothesis("zzzz", 0.05, "test")
    assert not sp.worth_testing(unlikely, per_char_requests=1.0)


def test_no_proposals_without_data():
    sp = SequencePredictor()
    assert sp.propose("abc", 10) == []
