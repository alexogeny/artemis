from __future__ import annotations

from typing import cast

import pytest

from artemis.execution import ExecutionConfig, ExecutionMode, TaskExecutor


def add_numbers(a: int, b: int) -> int:
    return a + b


def describe(value: int) -> str:
    return f"value={value}"


@pytest.mark.asyncio
async def test_thread_execution() -> None:
    executor = TaskExecutor(ExecutionConfig(default_mode=ExecutionMode.THREAD, max_workers=1))
    result = await executor.run(add_numbers, 2, 3)
    assert result == 5
    await executor.shutdown()


@pytest.mark.asyncio
async def test_process_execution() -> None:
    executor = TaskExecutor(ExecutionConfig(default_mode=ExecutionMode.PROCESS, max_workers=1))
    result = await executor.run(add_numbers, 4, 5, mode=ExecutionMode.PROCESS)
    assert result == 9
    await executor.shutdown()


@pytest.mark.asyncio
async def test_remote_execution_serializes_arguments() -> None:
    executor = TaskExecutor(ExecutionConfig(default_mode=ExecutionMode.REMOTE))
    result = await executor.run(describe, 7, mode=ExecutionMode.REMOTE)
    assert result == "value=7"
    await executor.shutdown()


@pytest.mark.asyncio
async def test_executor_context_manager_with_async_function() -> None:
    async def async_add(a: int, b: int) -> int:
        return a + b

    async with TaskExecutor() as executor:
        assert await executor.run(async_add, 1, 2) == 3


@pytest.mark.asyncio
async def test_remote_execution_with_coroutine() -> None:
    async def identify(value: int) -> int:
        return value

    executor = TaskExecutor(ExecutionConfig(default_mode=ExecutionMode.REMOTE))
    result = await executor.run(identify, 9, mode=ExecutionMode.REMOTE)
    assert result == 9
    await executor.shutdown()


@pytest.mark.asyncio
async def test_invalid_execution_mode() -> None:
    executor = TaskExecutor()
    with pytest.raises(ValueError):
        await executor.run(add_numbers, 1, 1, mode=cast(ExecutionMode, "invalid"))
    await executor.shutdown()
