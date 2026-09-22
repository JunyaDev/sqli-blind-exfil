from blindsqli.predictor import CharacterPredictor


def test_ranks_observed_transition_first():
    p = CharacterPredictor(charset="abcnu_ju", order=3)
    # teach it that "ju" -> "n" strongly
    for _ in range(5):
        p.learn_value("jun")
    ranked = p.rank("ju")
    assert ranked[0][0] == "n"
    assert ranked[0][1] > 0.5


def test_probabilities_normalised():
    p = CharacterPredictor(charset="abc", order=2)
    p.learn_value("ab")
    ranked = p.rank("a")
    total = sum(prob for _, prob in ranked)
    assert abs(total - 1.0) < 1e-9


def test_incremental_learning_updates_model():
    p = CharacterPredictor(charset="abxy_", order=3)
    assert p.probability("ab", "x") < 0.9
    for _ in range(10):
        p.learn_transition("ab", "x")
    assert p.rank("ab")[0][0] == "x"


def test_backoff_uses_lower_order_when_context_unseen():
    p = CharacterPredictor(charset="abcz", order=3)
    # only unigram evidence for 'z'
    for _ in range(10):
        p.learn_value("z")
    ranked = p.rank("qqq")  # unseen high-order context
    assert ranked[0][0] == "z"


def test_unknown_charset_char_ignored():
    p = CharacterPredictor(charset="ab", order=2)
    p.learn_value("aXb")  # X not in charset, must be skipped without error
    ranked = p.rank("a")
    assert {c for c, _ in ranked} == {"a", "b"}
