from enum import Enum
import re
import textwrap
import os

from muraq_kms.cli.ui.ui import UIColors, UI

class _FrameStyle(Enum):
    BOX = {
        "top_left": "╭─", "top_right": "╮",
        "bottom_left": "╰─", "bottom_right": "╯",
        "line": "─", "rail": "│"
    }
    BRACKET = {
        "top_left": "⎴ ", "top_right": " ⎴",
        "bottom_left": "⎵ ", "bottom_right": " ⎵",
        "line": " ", "rail": "▕"
    }

class Frame:
    FrameStyle = _FrameStyle

    def __init__(self, title:str, color:UIColors = UI.COLORS.BLUE, style:FrameStyle = _FrameStyle.BOX) -> None:
        self.title = title
        self.color = color
        self.style = style.value
        self.reset = UI.ANSIESCAPE.RESET
        self.bold = UI.ANSIESCAPE.BOLD
        try:
            terminal_width = os.get_terminal_size().columns
        except OSError:
            terminal_width = 80
        self.width = min(90, max(40, terminal_width - 2))

    @staticmethod
    def _visible_length(text: str) -> int:
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_text = ansi_escape.sub('', text)
        
        length = 0
        for char in clean_text:
            if ord(char) > 0xffff or char in "💡🚨✔✗":
                length += 2
            else:
                length += 1
        return length

    def __enter__(self):
        title_len = self._visible_length(self.title)
        padding = self.width - title_len - 4
        if padding < 0: 
            padding = 0
        
        top_border = f"{self.color}{self.style['top_left']}{self.bold}{self.title}{self.reset}{self.color}"
        top_border += f"{self.style['line'] * padding}{self.style['top_right']}{self.reset}"
        print(top_border)
        return self
    
    def line(self, content: str) -> None:
        max_content_width = self.width - 4
        
        prefix_match = re.match(r'^(\s*(?:\x1B\[[0-9;]*m)*[💡🚨✔✗]\s*(?:\x1B\[[0-9;]*m)*\s*)', content)
        
        if prefix_match:
            prefix = prefix_match.group(1)
            actual_text = content[len(prefix):]
            prefix_len = self._visible_length(prefix)
            wrap_width = max_content_width - prefix_len
            indent_space = " " * prefix_len
        else:
            prefix = ""
            actual_text = content
            wrap_width = max_content_width
            indent_space = ""

        wrapped_chunks = textwrap.wrap(actual_text, width=wrap_width, break_long_words=False)
        
        if not wrapped_chunks:
            print(f"{self.color}{self.style['rail']}{self.reset}{' ' * (self.width - 2)}{self.color}{self.style['rail']}{self.reset}")
            return

        for idx, chunk in enumerate(wrapped_chunks):
            if idx == 0:
                line_str = f"{prefix}{chunk}"
            else:
                line_str = f"{indent_space}{chunk}"
                
            line_len = self._visible_length(line_str)
            padding = self.width - line_len - 4
            if padding < 0: 
                padding = 0
                
            print(f"{self.color}{self.style['rail']}{self.reset} {line_str}{' ' * padding} {self.color}{self.style['rail']}{self.reset}")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        padding = self.width - 4
        bottom_border = f"{self.color}{self.style['bottom_left']}{self.style['line'] * padding}{self.style['bottom_right']}{self.reset}"
        print(bottom_border)
        return False