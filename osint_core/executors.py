"""Async queue-based parallel execution with progress tracking.

Provides executors for running async username-check tasks concurrently with
configurable parallelism and optional progress bars. Extracted from Maigret's
executors module.
"""

import asyncio
import sys
from typing import Any, Callable, Iterable, List, Optional


def _create_task(coro):
    if sys.version_info.minor > 6:
        return asyncio.create_task(coro)
    loop = asyncio.get_event_loop()
    return loop.create_task(coro)


class AsyncQueueExecutor:
    """Execute async callables in parallel with a bounded worker pool.

    Usage::

        executor = AsyncQueueExecutor(in_parallel=20, timeout=10)
        results = await executor.run(queries)
    """

    def __init__(self, in_parallel: int = 10, timeout: Optional[float] = None):
        self.workers_count = in_parallel
        self.timeout = timeout

    async def run(self, queries: Iterable[tuple]) -> List[Any]:
        """Run a list of (func, args, kwargs) tuples concurrently.

        Returns a list of results in completion order.
        """
        queries_list = list(queries)
        if not queries_list:
            return []

        queue: asyncio.Queue = asyncio.Queue()
        results: List[Any] = []
        sem = asyncio.Semaphore(self.workers_count)

        async def worker():
            while True:
                try:
                    f, args, kwargs = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    async with sem:
                        coro = f(*args, **kwargs)
                        task = _create_task(coro)
                        try:
                            result = await asyncio.wait_for(task, timeout=self.timeout)
                        except asyncio.TimeoutError:
                            result = kwargs.get("default")
                        results.append(result)
                except Exception:
                    results.append(kwargs.get("default"))
                finally:
                    queue.task_done()

        for q in queries_list:
            await queue.put(q)

        workers = [_create_task(worker()) for _ in range(min(len(queries_list), self.workers_count))]
        await queue.join()

        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        return results


class AsyncGeneratorExecutor:
    """Execute async callables and yield results as they complete.

    Like AsyncQueueExecutor but yields results one by one via an async generator,
    useful for streaming progress updates.
    """

    def __init__(self, in_parallel: int = 10, timeout: Optional[float] = None):
        self.workers_count = in_parallel
        self.timeout = timeout

    async def run(self, queries: Iterable[tuple]):
        """Yield (result) as each query completes."""
        queries_list = list(queries)
        if not queries_list:
            return

        queue: asyncio.Queue = asyncio.Queue()
        result_queue: asyncio.Queue = asyncio.Queue()
        stop = object()

        async def worker():
            while True:
                item = await queue.get()
                if item is stop:
                    queue.task_done()
                    break
                f, args, kwargs = item
                try:
                    coro = f(*args, **kwargs)
                    task = _create_task(coro)
                    try:
                        result = await asyncio.wait_for(task, timeout=self.timeout)
                    except asyncio.TimeoutError:
                        result = kwargs.get("default")
                    await result_queue.put(result)
                except Exception:
                    await result_queue.put(kwargs.get("default"))
                finally:
                    queue.task_done()

        for q in queries_list:
            await queue.put(q)

        workers = [_create_task(worker()) for _ in range(min(len(queries_list), self.workers_count))]

        for _ in range(self.workers_count):
            await queue.put(stop)

        try:
            done = 0
            total = len(queries_list)
            while done < total:
                try:
                    result = await asyncio.wait_for(result_queue.get(), timeout=1)
                    done += 1
                    yield result
                except asyncio.TimeoutError:
                    pass
        finally:
            await asyncio.gather(*workers, return_exceptions=True)


async def run_checks_parallel(
    check_func: Callable,
    targets: List[tuple],
    in_parallel: int = 20,
    timeout: Optional[float] = None,
) -> List[Any]:
    """Convenience function: run check_func(*args) for each target tuple in parallel."""
    queries = [(check_func, args, {"default": None}) for args in targets]
    executor = AsyncQueueExecutor(in_parallel=in_parallel, timeout=timeout)
    return await executor.run(queries)
