# SPDX-License-Identifier: MIT

import asyncio


class HeartbeatTimer:
    """
    Simple Asynchronous Timer that expires after a given time
    """

    def __init__(self, timeout, callback):
        """ Initialize the timer
        Args:
            timeout: timeout in seconds
            callback: this function will be called when the timer expires
        """
        self._timeout = timeout
        self._callback = callback
        self._task = None

    async def _job(self):
        while True:
            try:
                await asyncio.sleep(self._timeout)
                self._callback()
            except asyncio.CancelledError:
                break

    def start(self):
        self._task = asyncio.ensure_future(self._job())

    def stop(self):
        if self._task is not None:
            self._task.cancel()
            self._task = None

    def reset(self):
        self.stop()
        self.start()
