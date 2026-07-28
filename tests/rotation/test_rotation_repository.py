import pytest
from muraq_kms.rotation.repository import RotationRepository

@pytest.mark.asyncio
async def test_get_overdue_jobs_async(mock_storage_pool):
    repo = RotationRepository(mock_storage_pool)
    mock_storage_pool.async_backend.fetchall.return_value = [
        (1, 10, 30, "db-key"),
        (2, 11, 60, "auth-key")
    ]
    
    jobs = await repo.get_overdue_jobs_async()
    assert len(jobs) == 2
    assert jobs[0] == {"job_id": 1, "logical_key_id": 10, "interval_days": 30, "key_name": "db-key"}
    assert jobs[1]["key_name"] == "auth-key"

@pytest.mark.asyncio
async def test_get_overdue_jobs_async_empty(mock_storage_pool):
    repo = RotationRepository(mock_storage_pool)
    mock_storage_pool.async_backend.fetchall.return_value = []
    
    jobs = await repo.get_overdue_jobs_async()
    assert jobs == []

def test_get_overdue_jobs_sync(mock_storage_pool):
    repo = RotationRepository(mock_storage_pool)
    mock_storage_pool.sync_backend.fetchall.return_value = [
        (5, 100, 90, "app-key")
    ]
    
    jobs = repo.get_overdue_jobs_sync()
    assert len(jobs) == 1
    assert jobs[0]["job_id"] == 5
    assert jobs[0]["key_name"] == "app-key"

@pytest.mark.asyncio
async def test_update_job_schedule_async(mock_storage_pool):
    repo = RotationRepository(mock_storage_pool)
    await repo.update_job_schedule_async(job_id=10, last_run=1000.0, next_run=2000.0)
    
    mock_storage_pool.async_backend.execute.assert_called_once_with(
        "UPDATE rotation_jobs SET last_run = ?, next_run = ? WHERE _id = ?;",
        (1000.0, 2000.0, 10)
    )

def test_update_job_schedule_sync(mock_storage_pool):
    repo = RotationRepository(mock_storage_pool)
    repo.update_job_schedule_sync(job_id=12, last_run=1500.0, next_run=2500.0)
    
    mock_storage_pool.sync_backend.execute.assert_called_once_with(
        "UPDATE rotation_jobs SET last_run = ?, next_run = ? WHERE _id = ?;",
        (1500.0, 2500.0, 12)
    )

@pytest.mark.asyncio
async def test_register_rotation_job_async(mock_storage_pool):
    repo = RotationRepository(mock_storage_pool)
    res = await repo.register_rotation_job_async(logical_key_id=42, interval_days=90)
    
    assert res["interval_days"] == 90
    assert "next_run" in res

def test_register_rotation_job_sync(mock_storage_pool):
    repo = RotationRepository(mock_storage_pool)
    res = repo.register_rotation_job_sync(logical_key_id=42, interval_days=30)
    
    assert res["interval_days"] == 90
    assert "next_run" in res