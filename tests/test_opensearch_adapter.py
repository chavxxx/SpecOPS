"""
Automated tests for OpenSearch Adapter and Durable Buffer Queue
"""
import pytest
from app.database.db import get_db
from app.services.opensearch_adapter import OpenSearchAdapter

@pytest.fixture
def opensearch_fixture():
    db = get_db()
    with db._get_connection() as conn:
        conn.execute("DELETE FROM opensearch_queue")
        conn.commit()
    return db

def test_opensearch_durable_buffer_queue_lifecycle(opensearch_fixture):
    db = opensearch_fixture
    adapter = OpenSearchAdapter(db=db)

    # 1. Initially queue is empty
    assert db.get_opensearch_queue_depth() == 0

    # 2. Enqueue documents
    doc1 = {"event_id": "e1", "source_ip": "100.91.0.2"}
    doc2 = {"event_id": "e2", "source_ip": "100.91.0.3"}
    id1 = db.enqueue_opensearch_doc("wisp-security-events", "e1", doc1)
    id2 = db.enqueue_opensearch_doc("wisp-security-events", "e2", doc2)

    assert db.get_opensearch_queue_depth() == 2

    # 3. Retrieve pending docs
    pending = db.get_pending_opensearch_docs(limit=10)
    assert len(pending) == 2
    assert pending[0]["doc_id"] == "e1"

    # 4. Mark doc 1 completed
    db.mark_opensearch_docs_completed([id1])
    assert db.get_opensearch_queue_depth() == 1

    # 5. Mark doc 2 failed with retry increment
    db.mark_opensearch_doc_failed(id2, "Connection reset by peer")
    pending_after_fail = db.get_pending_opensearch_docs(limit=10)
    assert len(pending_after_fail) == 1
    assert pending_after_fail[0]["attempts"] == 1

def test_opensearch_index_templates_structure():
    tpl_events = OpenSearchAdapter.get_index_template("wisp-security-events")
    assert "index_patterns" in tpl_events
    assert tpl_events["index_patterns"] == ["wisp-security-events-*"]
    props = tpl_events["template"]["mappings"]["properties"]
    assert props["source_ip"]["type"] == "ip"
    assert props["subscriber_cgnat_ip"]["type"] == "ip"
    assert props["destination_port"]["type"] == "integer"
    assert props["event_timestamp"]["type"] == "date"
