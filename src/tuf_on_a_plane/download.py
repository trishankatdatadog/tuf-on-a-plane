from datetime import datetime
import tempfile

import httpx

from . import __version__
from .config import Config
from .exceptions import (
    EndlessDataAttack,
    NotFoundError,
    SlowRetrievalAttack,
)
from .models.common import (
    Filepath,
    Length,
    Url,
)


class DownloaderMixIn:
    """A mixin to separate download functions."""

    def init_downloader(self) -> None:
        """Override this function to initialize your downloader."""
        raise NotImplementedError

    def close_downloader(self) -> None:
        """Override this function to clean up after your downloader."""
        raise NotImplementedError

    def download(self, path: Url, length: Length, config: Config) -> Filepath:
        """Override this function to implement your own custom download logic.

        length is expected to be in number of bytes."""
        raise NotImplementedError


class HTTPXDownloaderMixIn(DownloaderMixIn):
    """A mixin that uses httpx to download."""

    def init_downloader(self) -> None:
        # Use a 10s timeout everywhere (connect/read/write/pool).
        self.__client = httpx.Client(
            headers={
                "User-Agent": f"tuf-on-a-plane/{__version__} httpx/{httpx.__version__}"
            },
            http2=True,
            timeout=10,
        )

    def close_downloader(self) -> None:
        self.__client.close()

    def download(self, path: Url, expected_length: Length, config: Config) -> Filepath:
        temp_fd, temp_path = tempfile.mkstemp(dir=config.temp_dir)

        with open(temp_fd, "wb") as temp_file:
            with self.__client.stream("GET", path) as response:
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError as e:
                    if e.response.status_code in {403, 404}:
                        raise NotFoundError(path)
                    raise

                alleged_length = response.headers.get(
                    "Content-Length", expected_length.value
                )
                if expected_length < alleged_length:
                    raise EndlessDataAttack(
                        f"{alleged_length} > {expected_length} bytes on {path}"
                    )

                prev_length, prev_time = 0, datetime.now()
                try:
                    for chunk in response.iter_bytes():
                        curr_length, curr_time = (
                            response.num_bytes_downloaded,
                            datetime.now(),
                        )
                        length_diff = curr_length - prev_length
                        time_diff = (curr_time - prev_time).total_seconds()
                        prev_length, prev_time = curr_length, curr_time
                        chunk_speed = length_diff // time_diff

                        if length_diff and config.MIN_BYTES_PER_SEC > chunk_speed:
                            raise SlowRetrievalAttack(
                                f"{chunk_speed} < {config.MIN_BYTES_PER_SEC} bytes/sec on {path}"
                            )
                        if expected_length < curr_length:
                            raise EndlessDataAttack(
                                f"{curr_length} > {expected_length} bytes on {path}"
                            )

                        temp_file.write(chunk)
                except httpx.TimeoutException:
                    raise SlowRetrievalAttack(f"timeout on {path}")

        return temp_path
