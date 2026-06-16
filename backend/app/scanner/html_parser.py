from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser


@dataclass
class FormMetadata:
    action: str | None
    method: str
    inputs: list[str] = field(default_factory=list)


@dataclass
class HtmlMetadata:
    links: list[str] = field(default_factory=list)
    forms: list[FormMetadata] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)


class MetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.metadata = HtmlMetadata()
        self._current_form: FormMetadata | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): value for key, value in attrs}
        if tag == "a" and attr_map.get("href"):
            self.metadata.links.append(attr_map["href"] or "")
        if tag == "form":
            self._current_form = FormMetadata(
                action=attr_map.get("action"),
                method=(attr_map.get("method") or "get").lower(),
            )
            self.metadata.forms.append(self._current_form)
        if tag == "input":
            input_type = (attr_map.get("type") or "text").lower()
            self.metadata.inputs.append(input_type)
            if self._current_form is not None:
                self._current_form.inputs.append(input_type)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


def extract_html_metadata(body: str) -> HtmlMetadata:
    parser = MetadataParser()
    parser.feed(body)
    return parser.metadata
