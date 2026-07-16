#!/usr/bin/env python3
"""Dependency-free reference decoder for the practice-puzzle-six cube walk.

Rust's cubemorse command is the calibrated instrument. This script keeps the
underlying cube/Morse construction easy to inspect and share: it performs the
same finite orientation/role sweep, exact re-encoding, planted control, and
direction-shuffle matched null without importing project code.
"""

from __future__ import annotations

import argparse
import random
import re
from pathlib import Path
from typing import Iterable, NamedTuple

NORTH, EAST, SOUTH, WEST = range(4)
DIRECTION_NAMES = ("N", "E", "S", "W")

MORSE_ROWS = (
    ".- A|-... B|-.-. C|-.. D|. E|..-. F|--. G|.... H|.. I|.--- J|"
    "-.- K|.-.. L|-- M|-. N|--- O|.--. P|--.- Q|.-. R|... S|- T|"
    "..- U|...- V|.-- W|-..- X|-.-- Y|--.. Z|----- 0|.---- 1|"
    "..--- 2|...-- 3|....- 4|..... 5|-.... 6|--... 7|---.. 8|"
    "----. 9|.-.-.- .|--..-- ,|..--.. ?|.----. '|-.-.-- !|"
    "-..-. /|-.--. (|-.--.- )|.-... &|---... :|-.-.-. ;|-...- =|"
    ".-.-. +|-....- -|..--.- _|.-..-. \"|...-..- $|.--.-. @"
)
MORSE_TO_CHAR = dict(row.rsplit(" ", 1) for row in MORSE_ROWS.split("|"))
CHAR_TO_MORSE = {char: code for code, char in MORSE_TO_CHAR.items()}


class Cell(NamedTuple):
    """Initial orientation plus dot/dash/separator directions."""

    start: tuple[int, int, int, int, int, int]
    dot: int
    dash: int
    separator: int


def opposite(face: int) -> int:
    """Return the opposite face under pairs 0/5, 1/4, and 2/3."""

    return 5 - face


def orientations() -> Iterable[tuple[int, int, int, int, int, int]]:
    """Enumerate both handed cube nets (48 labeled orientations)."""

    for top in range(6):
        for north in range(6):
            if north in (top, opposite(top)):
                continue
            for east in range(6):
                if east in (top, opposite(top), north, opposite(north)):
                    continue
                yield (top, north, east, opposite(north), opposite(east), opposite(top))


def roll(state: tuple[int, ...], direction: int) -> tuple[int, ...]:
    """Roll one quarter turn and return (top,north,east,south,west,bottom)."""

    top, north, east, south, west, bottom = state
    if direction == NORTH:
        return north, bottom, east, top, west, south
    if direction == EAST:
        return east, north, bottom, south, top, west
    if direction == SOUTH:
        return south, top, east, bottom, west, north
    return west, north, top, south, bottom, east


def direction_of(state: tuple[int, ...], face: int) -> int | None:
    """Return the roll that brings an adjacent face to the top."""

    for direction, position in enumerate((1, 2, 3, 4)):
        if state[position] == face:
            return direction
    return None


def derive(words: list[list[int]], start: tuple[int, ...]) -> list[list[int]] | None:
    """Derive roll commands from observed successive top faces."""

    state = start
    output: list[list[int]] = []
    for word in words:
        commands = []
        for face in word:
            direction = direction_of(state, face)
            if direction is None:
                return None
            state = roll(state, direction)
            commands.append(direction)
        output.append(commands)
    return output


def encode_commands(commands: list[list[int]], start: tuple[int, ...]) -> list[list[int]]:
    """Encode roll commands as successive top faces."""

    state = start
    output = []
    for word in commands:
        faces = []
        for direction in word:
            state = roll(state, direction)
            faces.append(state[0])
        output.append(faces)
    return output


def decode_morse(commands: list[list[int]], cell: Cell) -> str | None:
    """Decode one direction carrier under a declared Morse-role cell."""

    plaintext_words = []
    for word in commands:
        letters = []
        code = ""
        for direction in word:
            if direction == cell.separator:
                if not code or code not in MORSE_TO_CHAR:
                    return None
                letters.append(MORSE_TO_CHAR[code])
                code = ""
            elif direction == cell.dot:
                code += "."
            elif direction == cell.dash:
                code += "-"
            else:
                return None
        if not code or code not in MORSE_TO_CHAR:
            return None
        letters.append(MORSE_TO_CHAR[code])
        plaintext_words.append("".join(letters))
    return " ".join(plaintext_words)


def encode_text(text: str, cell: Cell) -> list[list[int]] | None:
    """Encode International Morse text through one cube cell."""

    command_words = []
    for word in text.upper().split(" "):
        if not word:
            return None
        commands = []
        for index, char in enumerate(word):
            code = CHAR_TO_MORSE.get(char)
            if code is None:
                return None
            if index:
                commands.append(cell.separator)
            commands.extend(cell.dot if mark == "." else cell.dash for mark in code)
        command_words.append(commands)
    return encode_commands(command_words, cell.start)


def scan(words: list[list[int]]) -> dict[str, tuple[Cell, int]]:
    """Return distinct all-valid-Morse, exact-replay candidates."""

    candidates: dict[str, tuple[Cell, int]] = {}
    for start in orientations():
        commands = derive(words, start)
        if commands is None:
            continue
        used = sorted(set(direction for word in commands for direction in word))
        if len(used) != 3:
            continue
        for separator in used:
            marks = [direction for direction in used if direction != separator]
            for dot, dash in (marks, marks[::-1]):
                cell = Cell(start, dot, dash, separator)
                plaintext = decode_morse(commands, cell)
                if plaintext is None or encode_text(plaintext, cell) != words:
                    continue
                if plaintext in candidates:
                    old_cell, equivalent = candidates[plaintext]
                    candidates[plaintext] = (min(old_cell, cell), equivalent + 1)
                else:
                    candidates[plaintext] = (cell, 1)
    return candidates


def matched_nulls(words: list[list[int]], trials: int, seed: int) -> int:
    """Count shuffled, count/length-matched walks with any Morse candidate."""

    carrier = next(
        (
            (start, commands)
            for start in orientations()
            if (commands := derive(words, start)) is not None
            and len(set(direction for word in commands for direction in word)) == 3
        ),
        None,
    )
    if carrier is None:
        return 0
    start, commands = carrier
    lengths = [len(word) for word in commands]
    flat = [direction for word in commands for direction in word]
    survivors = 0
    rng = random.Random(seed)
    for _trial in range(trials):
        shuffled = flat.copy()
        rng.shuffle(shuffled)
        cursor = 0
        shuffled_words = []
        for length in lengths:
            shuffled_words.append(shuffled[cursor : cursor + length])
            cursor += length
        survivors += bool(scan(encode_commands(shuffled_words, start)))
    return survivors


def self_test() -> None:
    """Exercise the same encoder, sweep, exact replay, and matched null."""

    cell = Cell((2, 1, 0, 4, 5, 3), EAST, WEST, NORTH)
    phrase = "CUBES MAKE ROLLS NON-COMMUTATIVE."
    plant = encode_text(phrase, cell)
    assert plant is not None
    assert phrase in scan(plant)
    assert matched_nulls(plant, 32, 0x6375626574657374) == 0


def parse_messages(text: str, alphabet: str) -> list[list[list[int]]]:
    """Parse blank-line messages and whitespace-delimited face words."""

    if len(alphabet) != 6 or len(set(alphabet)) != 6:
        raise ValueError("--alphabet must contain six distinct characters")
    face = {char: index for index, char in enumerate(alphabet)}
    messages = []
    for block in re.split(r"\n\s*\n", text.strip()):
        words = []
        for token in block.split():
            try:
                words.append([face[char] for char in token])
            except KeyError as error:
                raise ValueError(f"symbol {error.args[0]!r} is outside --alphabet") from error
        if words:
            messages.append(words)
    return messages


def main() -> None:
    """CLI entry point."""

    root = Path(__file__).resolve().parents[1]
    default_input = root / "research/data/practice-puzzles/six"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, default=default_input)
    parser.add_argument("--alphabet", default="123456")
    parser.add_argument("--null-trials", type=int, default=64)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0x637562656D6F7273)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    self_test()
    print("cubemorse Python reference self-test: PASS")
    if args.self_test:
        return
    messages = parse_messages(args.input.read_text(encoding="utf-8"), args.alphabet)
    for index, words in enumerate(messages, 1):
        candidates = scan(words)
        survivors = matched_nulls(words, args.null_trials, args.seed + index)
        print(f"message {index}: {sum(map(len, words))} faces, {len(words)} words")
        print(f"  matched null survivors: {survivors}/{args.null_trials}")
        for plaintext, (cell, equivalents) in sorted(candidates.items()):
            roles = tuple(DIRECTION_NAMES[value] for value in cell[1:])
            print(
                f"  {plaintext!r} RoundTrip exact; {equivalents} equivalent cells; "
                f"start={cell.start[:3]} roles(dot,dash,sep)={roles}"
            )


if __name__ == "__main__":
    main()
