from __future__ import annotations

from abc import ABC, abstractmethod


class Command(ABC):
    """qpa 프롬프트에서 실행되는 명령 인터페이스.

    새 기능을 추가할 때는 '실행할 객체.run()'을 만든 뒤 main.py에서
    FunctionCommand("dac", ("d",), "DAC 권한부여", dac_tool.run, "DAC")처럼 등록합니다.
    이렇게 하면 main loop는 바꾸지 않고 명령만 늘릴 수 있습니다.
    """

    name: str
    aliases: tuple[str, ...] = ()
    description: str
    category: str = "공통"
    visible: bool = True
    alias_label: str = ""

    @abstractmethod
    def run(self):
        raise NotImplementedError

    def matches(self, raw: str) -> bool:
        value = raw.strip().lower()
        return value == self.name or value in self.aliases


class FunctionCommand(Command):
    """일반 함수를 Command 인터페이스처럼 감싸는 어댑터."""

    def __init__(
        self,
        name: str,
        aliases: tuple[str, ...],
        description: str,
        callback,
        category: str = "공통",
        visible: bool = True,
        alias_label: str = "",
    ):
        self.name = name
        self.aliases = aliases
        self.description = description
        self.callback = callback
        self.category = category
        self.visible = visible
        self.alias_label = alias_label

    def run(self):
        return self.callback()


class CommandDispatcher:
    """사용자 입력을 어떤 Command가 처리할지 찾아 실행한다."""

    def __init__(self, commands: list[Command]):
        self.commands = commands

    def dispatch(self, raw: str) -> bool:
        for command in self.commands:
            if command.matches(raw):
                command.run()
                return True
        return False

    def rows(self) -> list[list[str]]:
        return [
            [command.category, command.name, command.alias_label or "/".join(command.aliases) or "-", command.description]
            for command in self.commands
            if command.visible
        ]
