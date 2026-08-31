import asyncio
import sqlite3

import pytest

from backend.storage.database import Repository
from backend.storage.models import SCHEMA_SQL
from backend.storage.repositories.conversation_repo import (
    ConversationAccessDenied,
    ConversationRepository,
)
from backend.storage.repositories.trajectory_repo import TrajectoryRepository


def _init_db(path):
    connection = sqlite3.connect(path)
    try:
        connection.executescript(SCHEMA_SQL)
    finally:
        connection.close()


def test_conversations_messages_and_trajectories_are_owner_isolated(tmp_path):
    async def scenario():
        db_path = tmp_path / "conversations.db"
        _init_db(db_path)
        database = Repository(f"sqlite:///{db_path}")
        alice = ConversationRepository(database, owner_id="alice")
        bob = ConversationRepository(database, owner_id="bob")
        alice_trajectories = TrajectoryRepository(database, owner_id="alice")
        bob_trajectories = TrajectoryRepository(database, owner_id="bob")

        conversation_id = await alice.create_conversation(
            title="Alice secret", conversation_id="conversation-alice"
        )
        await alice.save_message(conversation_id, "user", "private message")
        await alice_trajectories.save_trajectory(
            conversation_id,
            [{"phase": "think", "output": "private reasoning", "success": True}],
        )

        assert await bob.get_conversation(conversation_id) is None
        assert await bob.list_conversations() == []
        assert await bob_trajectories.get_trajectories() == []
        with pytest.raises(ConversationAccessDenied):
            await bob.get_messages(conversation_id)
        with pytest.raises(ConversationAccessDenied):
            await bob.save_message(conversation_id, "user", "tamper")
        with pytest.raises(ConversationAccessDenied):
            await bob_trajectories.get_conversation_trajectory(conversation_id)

        messages = await alice.get_messages(conversation_id)
        trajectories = await alice_trajectories.get_trajectories(conversation_id)
        assert [message["content"] for message in messages] == ["private message"]
        assert trajectories[0]["steps"][0]["output"] == "private reasoning"
        await database.close()

    asyncio.run(scenario())


def test_owner_is_required(tmp_path):
    database = Repository(f"sqlite:///{tmp_path / 'owner-required.db'}")
    with pytest.raises(ValueError):
        ConversationRepository(database, owner_id="")
    with pytest.raises(ValueError):
        TrajectoryRepository(database, owner_id="  ")
