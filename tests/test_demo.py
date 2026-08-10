from recallops.demo import seed_memories
from recallops.embedding import DeterministicEmbedder
from recallops.store import InMemoryStore


def test_demo_seed_is_idempotently_identified_and_governance_attributed() -> None:
    embedder = DeterministicEmbedder()
    first = InMemoryStore()
    second = InMemoryStore()

    seed_memories(first, embedder)
    seed_memories(second, embedder)

    assert [memory.id for memory in first.memories] == [memory.id for memory in second.memories]
    assert all(memory.embedding_space == embedder.space_id for memory in first.memories)
    assert all(memory.observed_by == "fixture-observer" for memory in first.memories)
    assert all(memory.reviewed_by == "fixture-reviewer" for memory in first.memories)
    assert all(memory.reviewed_at is not None for memory in first.memories)
