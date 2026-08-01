from recallops.reembed import vector_literal


def test_vector_literal_is_stable_and_database_compatible() -> None:
    assert vector_literal([0.0, 1.25, -0.5]) == "[0,1.25,-0.5]"
