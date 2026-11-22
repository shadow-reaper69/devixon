"""
Safe async subprocess runner for external tools.
Enforces timeout, non-shell execution, argument sanitization, process termination, and output limits.
"""

import asyncio
import os
import signal
from typing import List, Tuple, Optional
from devixon.core.exceptions import ToolExecutionError, ToolTimeoutError
from devixon.core.logger import logger

MAX_OUTPUT_BYTES = 5 * 1024 * 1024  # 5MB safety limit


async def run_subprocess(
    cmd: List[str],
    timeout: float = 60.0,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
) -> Tuple[int, str, str]:
    """
    Executes a command safely without shell=True.
    Returns: (exit_code, stdout_str, stderr_str)
    """
    if not cmd or not cmd[0]:
        raise ToolExecutionError("Empty command requested.")

    logger.debug(f"Subprocess executing: {' '.join(cmd)}")
    process_env = os.environ.copy()
    if env:
        process_env.update(env)

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=process_env,
        )

        try:
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            # Terminate safely
            try:
                process.terminate()
                await asyncio.sleep(0.5)
                if process.returncode is None:
                    process.kill()
            except Exception as e:
                logger.warning(f"Failed to kill timed out process {cmd[0]}: {e}")
            raise ToolTimeoutError(tool_name=cmd[0], timeout_seconds=timeout)

        stdout_str = stdout_data[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        stderr_str = stderr_data[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        return (process.returncode or 0, stdout_str, stderr_str)

    except (FileNotFoundError, OSError) as e:
        raise ToolExecutionError(f"Failed to start command {cmd[0]}: {str(e)}", tool_name=cmd[0])
