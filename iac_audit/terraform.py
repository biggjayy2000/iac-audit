"""A deliberately small HCL reader.

This is not a general HCL2 implementation. It reads what an audit needs — blocks, labels,
attributes, lists, maps, heredocs and `jsonencode` payloads — and keeps every construct it
cannot evaluate as an opaque string rather than guessing at its value. A rule that silently
misreads a reference is worse than a rule that stays quiet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .models import Resource

# Terraform resource type -> the language-neutral kind rules dispatch on.
TF_KINDS = {
    "aws_s3_bucket": "s3_bucket",
    "aws_s3_bucket_policy": "s3_bucket_policy",
    "aws_security_group": "security_group",
    "aws_vpc_security_group_ingress_rule": "sg_rule",
    "aws_ebs_volume": "ebs_volume",
    "aws_db_instance": "rds_instance",
    "aws_iam_policy": "iam_policy",
    "aws_iam_role_policy": "iam_policy",
    "aws_iam_role": "iam_role",
    "aws_instance": "ec2_instance",
}


class Opaque(str):
    """A value the parser could not evaluate: a reference, an operator, a function call."""

    __slots__ = ()


@dataclass
class Token:
    kind: str
    value: Any
    line: int


@dataclass
class Block:
    type: str
    labels: List[str]
    attrs: Dict[str, Any]
    blocks: List["Block"]
    line: int

    def as_dict(self) -> Dict[str, Any]:
        """Attributes plus nested blocks, with repeated block types collected into lists."""
        body: Dict[str, Any] = dict(self.attrs)
        for child in self.blocks:
            body.setdefault(child.type, []).append(child.as_dict())
        return body


PUNCT = set("{}[]=(),:")


def tokenize(text: str) -> List[Token]:
    tokens: List[Token] = []
    index, line, size = 0, 1, len(text)

    while index < size:
        char = text[index]

        if char in " \t\r":
            index += 1
            continue

        if char == "\n":
            tokens.append(Token("newline", "\n", line))
            line += 1
            index += 1
            continue

        if char == "#" or text.startswith("//", index):
            while index < size and text[index] != "\n":
                index += 1
            continue

        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end == -1:
                break
            line += text.count("\n", index, end)
            index = end + 2
            continue

        if text.startswith("<<", index):
            start_line = line
            cursor = index + 2
            if cursor < size and text[cursor] == "-":
                cursor += 1
            end_of_line = text.find("\n", cursor)
            if end_of_line == -1:
                break
            delimiter = text[cursor:end_of_line].strip().strip('"')
            cursor = end_of_line + 1
            collected: List[str] = []
            while cursor < size:
                next_line_end = text.find("\n", cursor)
                if next_line_end == -1:
                    next_line_end = size
                row = text[cursor:next_line_end]
                line += 1
                if row.strip() == delimiter:
                    cursor = next_line_end + 1
                    break
                collected.append(row)
                cursor = next_line_end + 1
            tokens.append(Token("string", "\n".join(collected), start_line))
            index = cursor
            continue

        if char == '"':
            start_line = line
            cursor = index + 1
            buffer: List[str] = []
            while cursor < size:
                current = text[cursor]
                if current == "\\" and cursor + 1 < size:
                    escape = text[cursor + 1]
                    buffer.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}.get(escape, escape))
                    cursor += 2
                    continue
                if current == '"':
                    cursor += 1
                    break
                if current == "\n":
                    line += 1
                buffer.append(current)
                cursor += 1
            tokens.append(Token("string", "".join(buffer), start_line))
            index = cursor
            continue

        if char.isdigit() or (char == "-" and index + 1 < size and text[index + 1].isdigit()):
            cursor = index + 1
            while cursor < size and (text[cursor].isdigit() or text[cursor] in "._"):
                cursor += 1
            raw = text[index:cursor]
            try:
                value: Any = float(raw) if "." in raw else int(raw)
            except ValueError:
                value = Opaque(raw)
            tokens.append(Token("number", value, line))
            index = cursor
            continue

        if char.isalpha() or char == "_":
            cursor = index + 1
            while cursor < size and (text[cursor].isalnum() or text[cursor] in "_-"):
                cursor += 1
            tokens.append(Token("ident", text[index:cursor], line))
            index = cursor
            continue

        if char in PUNCT:
            tokens.append(Token("punct", char, line))
            index += 1
            continue

        # Operators and anything else are kept as text, so expressions stay intact.
        tokens.append(Token("raw", char, line))
        index += 1

    tokens.append(Token("eof", "", line))
    return tokens


class Parser:
    def __init__(self, tokens: List[Token]) -> None:
        self.tokens = tokens
        self.index = 0

    def peek(self, offset: int = 0) -> Token:
        position = min(self.index + offset, len(self.tokens) - 1)
        return self.tokens[position]

    def skip_newlines(self) -> None:
        while self.peek().kind == "newline":
            self.index += 1

    def document(self) -> Tuple[Dict[str, Any], List[Block]]:
        return self.parse_body(terminator=None)

    def parse_body(self, terminator: Optional[str]) -> Tuple[Dict[str, Any], List[Block]]:
        attrs: Dict[str, Any] = {}
        blocks: List[Block] = []

        while True:
            self.skip_newlines()
            token = self.peek()

            if token.kind == "eof":
                break
            if terminator and token.kind == "punct" and token.value == terminator:
                self.index += 1
                break
            if token.kind != "ident":
                self.index += 1
                continue

            name, line = token.value, token.line
            self.index += 1

            if self.peek().kind == "punct" and self.peek().value == "=":
                self.index += 1
                attrs[name] = self.parse_value()
                continue

            labels: List[str] = []
            while self.peek().kind in ("string", "ident"):
                labels.append(self.peek().value)
                self.index += 1

            if self.peek().kind == "punct" and self.peek().value == "{":
                self.index += 1
                child_attrs, child_blocks = self.parse_body(terminator="}")
                blocks.append(Block(name, labels, child_attrs, child_blocks, line))

        return attrs, blocks

    def parse_value(self) -> Any:
        token = self.peek()

        if token.kind in ("string", "number"):
            self.index += 1
            return token.value

        if token.kind == "punct" and token.value == "[":
            return self.parse_list()
        if token.kind == "punct" and token.value == "{":
            return self.parse_map()

        if token.kind == "ident":
            if token.value in ("true", "false"):
                self.index += 1
                return token.value == "true"
            if token.value == "null":
                self.index += 1
                return None
            if token.value == "jsonencode":
                self.index += 1
                if self.peek().kind == "punct" and self.peek().value == "(":
                    self.index += 1
                    value = self.parse_value()
                    self.consume_until_close()
                    return value
                return Opaque("jsonencode")
            if token.value == "file":
                self.index += 1
                self.consume_until_close()
                return Opaque("file()")

        return Opaque(self.consume_expression())

    def parse_list(self) -> List[Any]:
        self.index += 1  # [
        items: List[Any] = []
        while True:
            self.skip_newlines()
            token = self.peek()
            if token.kind == "eof":
                break
            if token.kind == "punct" and token.value == "]":
                self.index += 1
                break
            items.append(self.parse_value())
            self.skip_newlines()
            if self.peek().kind == "punct" and self.peek().value == ",":
                self.index += 1
        return items

    def parse_map(self) -> Dict[str, Any]:
        self.index += 1  # {
        result: Dict[str, Any] = {}
        while True:
            self.skip_newlines()
            token = self.peek()
            if token.kind == "eof":
                break
            if token.kind == "punct" and token.value == "}":
                self.index += 1
                break
            if token.kind in ("ident", "string"):
                key = token.value
                self.index += 1
                if self.peek().kind == "punct" and self.peek().value in ("=", ":"):
                    self.index += 1
                result[key] = self.parse_value()
                self.skip_newlines()
                if self.peek().kind == "punct" and self.peek().value == ",":
                    self.index += 1
                continue
            self.index += 1
        return result

    def consume_until_close(self) -> None:
        depth = 1
        while self.peek().kind != "eof":
            token = self.peek()
            if token.kind == "punct" and token.value == "(":
                depth += 1
            elif token.kind == "punct" and token.value == ")":
                depth -= 1
                self.index += 1
                if depth == 0:
                    return
                continue
            self.index += 1

    def consume_expression(self) -> str:
        parts: List[str] = []
        depth = 0
        while True:
            token = self.peek()
            if token.kind == "eof":
                break
            if depth == 0 and (
                token.kind == "newline"
                or (token.kind == "punct" and token.value in (",", ")", "]", "}"))
            ):
                break
            if token.kind == "punct" and token.value in ("(", "[", "{"):
                depth += 1
            elif token.kind == "punct" and token.value in (")", "]", "}"):
                depth -= 1
            parts.append(str(token.value))
            self.index += 1
        return "".join(parts).strip()


def parse_terraform(text: str, path: str) -> List[Resource]:
    """Return the resource blocks in one Terraform file."""
    _, blocks = Parser(tokenize(text)).document()
    resources: List[Resource] = []

    for block in blocks:
        if block.type != "resource" or len(block.labels) != 2:
            continue
        source_type, name = block.labels
        resources.append(
            Resource(
                kind=TF_KINDS.get(source_type, source_type),
                source_type=source_type,
                name=name,
                body=block.as_dict(),
                file=path,
                line=block.line,
                fmt="terraform",
            )
        )

    return resources
