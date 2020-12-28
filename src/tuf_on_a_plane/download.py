import tempfile
from typing import IO, Tuple

import httpx

from . import __version__
from .config import Config
from .exceptions import (
    DownloadNotFoundError,
    EndlessDataAttack,
    SlowRetrievalAttack,
)
from .models.common import (
    DateTime,
    Filepath,
    Length,
    Speed,
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
        self.__client = httpx.Client(
            headers={
                "User-Agent": f"tuf-on-a-plane/{__version__} httpx/{httpx.__version__}"
            },
            # Opportunistically use HTTP/2, if available.
            http2=True,
            # Use the same timeout everywhere (connect/read/write/pool).
            # FIXME: Make this configurable.
            timeout=2.0,
        )

    def close_downloader(self) -> None:
        self.__client.close()

    def __check_length(self, path: Url, observed: Length, expected: Length) -> None:
        if observed > expected:
            raise EndlessDataAttack(f"{observed} > {expected} bytes on {path}")

    def __check_not_found(self, path: Url, response: httpx.Response) -> None:
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code in {403, 404}:
                raise DownloadNotFoundError(path) from e
            raise

    def __check_speed(self, path: Url, observed: Speed, expected: Speed) -> None:
        if observed < expected:
            raise SlowRetrievalAttack(f"{observed} < {expected} bytes/sec on {path}")

    def __chunk(
        self,
        response: httpx.Response,
        path: Url,
        expected_length: Length,
        prev_downloaded: int,
        prev_time: DateTime,
        config: Config,
        chunk: bytes,
        written_bytes: int,
        temp_file: IO,
    ) -> Tuple[int, DateTime, int]:
        curr_downloaded, curr_time = (
            response.num_bytes_downloaded,
            DateTime.now(),
        )
        self.__check_length(path, curr_downloaded, expected_length)
        downloaded_length = curr_downloaded - prev_downloaded

        if downloaded_length:
            time_diff = (curr_time - prev_time).total_seconds()
            chunk_speed = Speed(downloaded_length / time_diff)
            self.__check_speed(path, chunk_speed, config.SLOW_RETRIEVAL_THRESHOLD)

        chunk_length = len(chunk)
        if chunk_length:
            written_bytes += chunk_length
            written_length = Length(written_bytes)
            self.__check_length(path, curr_downloaded, written_length)
            self.__check_length(path, written_length, expected_length)
            temp_file.write(chunk)

        return curr_downloaded, DateTime.now(), written_bytes

    def download(self, path: Url, expected_length: Length, config: Config) -> Filepath:
        temp_fd, temp_path = tempfile.mkstemp(dir=config.temp_dir)

        with open(temp_fd, "wb") as temp_file:
            with self.__client.stream("GET", path) as response:
                self.__check_not_found(path, response)
                alleged_length = response.headers.get(
                    "Content-Length", expected_length.value
                )
                self.__check_length(path, alleged_length, expected_length)
                prev_downloaded, prev_time, written_bytes = 0, DateTime.now(), 0

                try:
                    for chunk in response.iter_bytes():
                        prev_downloaded, prev_time, written_bytes = self.__chunk(
                            response,
                            path,
                            expected_length,
                            prev_downloaded,
                            prev_time,
                            config,
                            chunk,
                            written_bytes,
                            temp_file,
                        )

                except httpx.TimeoutException as e:
                    raise SlowRetrievalAttack(f"timeout on {path}") from e

        return temp_path
