# SPDX-FileCopyrightText: 2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import tracemalloc
from argparse import ArgumentParser, Namespace
from typing import Sequence

import shtab
from rich.progress import Progress

from greenbone.scap.cli import CLIRunner
from greenbone.scap.cpe_match.cli.processor import CpeMatchProcessor
from greenbone.scap.cpe_match.producer.db import CpeMatchDatabaseProducer

from ..worker.json import CpeMatchJsonWriteWorker


def parse_args(args: Sequence[str] | None = None) -> Namespace:
    parser = ArgumentParser(
        description="Write CPE match strings from a database to a JSON file. "
        "Queries CPE match string information from a database "
        "and consolidates it into a single JSON file."
    )
    shtab.add_argument_to(parser)

    CpeMatchDatabaseProducer.add_args_to_parser(parser)

    CpeMatchJsonWriteWorker.add_args_to_parser(parser)

    CpeMatchProcessor.add_args_to_parser(parser)

    return parser.parse_args(args)


async def download(console, error_console) -> None:
    args = parse_args()

    tracemalloc.start()
    with Progress(console=console) as progress:
        producer = CpeMatchDatabaseProducer.from_args(
            args,
            console,
            error_console,
            progress,
        )

        worker = CpeMatchJsonWriteWorker.from_args(
            args,
            console,
            error_console,
            progress,
        )

        processor = CpeMatchProcessor.from_args(
            args,
            console,
            error_console,
            producer,
            worker,
        )

        await processor.run()
        print(f"tracemalloc {tracemalloc.get_traced_memory()}")


def main() -> None:
    CLIRunner.run(download)


if __name__ == "__main__":
    main()
