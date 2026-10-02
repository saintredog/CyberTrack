"""Load curriculum YAML files into CurriculumItem rows."""
from __future__ import annotations

import re
from pathlib import Path

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import CurriculumItem

TRACK_LABELS = {
    "cysa": "CySA+",
    "pentest": "Pen Test",
    "wgu": "WGU",
    "cwe": "CWE Path",
}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


def load_file(session: Session, path: Path, position_start: int = 0) -> int:
    data = yaml.safe_load(path.read_text())
    track = data["track"]
    pos = position_start
    seen_keys = set()
    for section in data.get("sections", []):
        section_name = section["section"]
        section_phase = section.get("phase")
        for raw in section.get("items", []):
            topic = raw["topic"]
            key = f"{track}.{_slug(section_name)}.{_slug(topic)}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            existing = session.scalar(select(CurriculumItem).where(CurriculumItem.key == key))
            if existing:
                pos += 1
                continue
            session.add(
                CurriculumItem(
                    key=key,
                    track=track,
                    section=section_name,
                    topic=topic,
                    description=raw.get("description", ""),
                    minutes=int(raw.get("minutes", 20)),
                    phase=raw.get("phase", section_phase),
                    hands_on=bool(raw.get("hands_on", False)),
                    position=pos,
                    active=bool(raw.get("active", True)),
                )
            )
            pos += 1
    return pos


def load_curriculum(session: Session, directory: str | Path) -> int:
    directory = Path(directory)
    pos = 0
    for name in ("cwe.yaml", "cysa.yaml", "pentest.yaml", "wgu.yaml"):
        f = directory / name
        if f.exists():
            pos = load_file(session, f, pos)
    session.commit()
    return pos


def load_curriculum_if_empty(session: Session, directory: str | Path) -> bool:
    count = session.scalar(select(func.count()).select_from(CurriculumItem))
    if count:
        return False
    load_curriculum(session, directory)
    return True
