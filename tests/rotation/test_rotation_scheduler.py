import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock
from muraq_kms.rotation.scheduler import RotationScheduler

@pytest.mark.asyncio
async def test_scheduler_start_and_stop():
    mock_manager = MagicMock()
    mock_manager.process_scheduled_rotations = AsyncMock()

    scheduler = RotationScheduler(mock_manager)
    scheduler.start(interval_seconds=1)

    assert scheduler._task is not None
    assert not scheduler._task.done()

    scheduler.start(interval_seconds=1)

    await asyncio.sleep(0.05)
    await scheduler.stop()

    assert scheduler._task.done()

@pytest.mark.asyncio
async def test_scheduler_loop_catches_exceptions():
    mock_manager = MagicMock()
    mock_manager.process_scheduled_rotations = AsyncMock(side_effect=[Exception("DB Connection Lost"), None])

    scheduler = RotationScheduler(mock_manager)
    scheduler.start(interval_seconds=1)

    await asyncio.sleep(0.05)
    await scheduler.stop()

    assert mock_manager.process_scheduled_rotations.call_count >= 1

@pytest.mark.asyncio
async def test_scheduler_stop_timeout_cancels_task():
    mock_manager = MagicMock()
    
    async def slow_rotation():
        await asyncio.sleep(10)

    mock_manager.process_scheduled_rotations = slow_rotation

    scheduler = RotationScheduler(mock_manager)
    scheduler.start(interval_seconds=1)
    await asyncio.sleep(0.01)

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(scheduler.stop(), timeout=0.01)