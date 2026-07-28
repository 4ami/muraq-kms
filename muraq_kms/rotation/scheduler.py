import asyncio
import logging
from typing import Optional

from muraq_kms.rotation.manager import RotationManager

logger = logging.getLogger("muraq_kms.rotation.scheduler")

class RotationScheduler:
    def __init__(self, manager:RotationManager):
        self.manager = manager
        self._task:Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()

    def start(self, interval_seconds:int = 60) -> None:
        """
        Spins up the rotation worker loop inside a non-blocking 
        background task window.
        """
        if self._task and not self._task.done():
            logger.warning("Rotation scheduler background daemon is already running")
            return

        self._shutdown_event.clear()
        self._task = asyncio.create_task(self._run_loop(interval_seconds))
        logger.info("Rotation scheduler background task initialized.")
    
    async def _run_loop(self, interval:int) -> None:
        """
        The continuous internal cron loop ticking at designated intervals.
        """
        logger.info(f"Cron daemon active. Checking policies every {interval} seconds.")

        while not self._shutdown_event.is_set():
            try:
                await self.manager.process_scheduled_rotations()
            except Exception as e:
                logger.error(f"Uncaught exception in background rotation loop: {e}")
            
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue
    
    async def stop(self) -> None:
        """
        Gracefully terminates the background daemon worker.
        """
        if not self._task or self._task.done():
            return
        
        logger.info("Signaling background rotation scheduler to gracefully halt...")
        self._shutdown_event.set()

        try:
            await asyncio.wait_for(self._task, timeout=10.0)
        except asyncio.TimeoutError:
            logger.error("Rotation task forced to cancel due to shutdown timeout.")
            self._task.cancel()
        
        logger.info("Rotation scheduler background daemon successfully shut down.")