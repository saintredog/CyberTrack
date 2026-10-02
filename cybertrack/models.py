"""Database models for CyberTrack.

Two halves share one SQLite file:
- SOC side: Alert, Triage, Turnover
- Study side: CurriculumItem, ReviewState, StudyLog
DailyPlan ties a day's alerts and study items together, and Setting holds
small user preferences such as the current CWE phase.
"""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- SOC


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    shift_date: Mapped[date] = mapped_column(Date, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    scenario: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(200))
    technique: Mapped[str] = mapped_column(String(32))
    raw_log: Mapped[str] = mapped_column(Text)
    enrichment: Mapped[dict] = mapped_column(JSON, default=dict)
    # Answer key. Hidden in the UI until the alert is triaged.
    true_disposition: Mapped[str] = mapped_column(String(16))
    indicators: Mapped[list] = mapped_column(JSON, default=list)
    explanation: Mapped[str] = mapped_column(Text)
    response: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="new")  # new | closed | escalated

    triage: Mapped["Triage | None"] = relationship(back_populates="alert", uselist=False)


class Triage(Base):
    __tablename__ = "triage"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), unique=True)
    user_disposition: Mapped[str] = mapped_column(String(16))  # benign | malicious
    reason: Mapped[str] = mapped_column(Text)
    notes: Mapped[str] = mapped_column(Text, default="")
    decided_at: Mapped[datetime] = mapped_column(DateTime)
    decided_on: Mapped[date] = mapped_column(Date, index=True)
    correct: Mapped[bool] = mapped_column(Boolean)

    alert: Mapped[Alert] = relationship(back_populates="triage")


class Turnover(Base):
    __tablename__ = "turnovers"

    id: Mapped[int] = mapped_column(primary_key=True)
    shift_date: Mapped[date] = mapped_column(Date, unique=True)
    summary: Mapped[str] = mapped_column(Text)
    open_items: Mapped[list] = mapped_column(JSON, default=list)
    written_at: Mapped[datetime] = mapped_column(DateTime)


# ------------------------------------------------------------------------- Study


class CurriculumItem(Base):
    __tablename__ = "curriculum_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(120), unique=True)  # e.g. "cysa.secops-tools"
    track: Mapped[str] = mapped_column(String(32), index=True)  # cysa | pentest | wgu | cwe
    section: Mapped[str] = mapped_column(String(200))
    topic: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    minutes: Mapped[int] = mapped_column(Integer, default=20)
    phase: Mapped[int | None] = mapped_column(Integer, nullable=True)  # CWE phase 1-4
    hands_on: Mapped[bool] = mapped_column(Boolean, default=False)
    position: Mapped[int] = mapped_column(Integer, default=0)
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    review: Mapped["ReviewState | None"] = relationship(back_populates="item", uselist=False)
    logs: Mapped[list["StudyLog"]] = relationship(back_populates="item")


class ReviewState(Base):
    """Spaced-repetition state for one curriculum item (SM-2 style)."""

    __tablename__ = "review_states"

    item_id: Mapped[int] = mapped_column(ForeignKey("curriculum_items.id"), primary_key=True)
    ease: Mapped[float] = mapped_column(Float, default=2.5)
    interval_days: Mapped[int] = mapped_column(Integer, default=0)
    repetitions: Mapped[int] = mapped_column(Integer, default=0)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    last_reviewed: Mapped[date | None] = mapped_column(Date, nullable=True)
    last_confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)

    item: Mapped[CurriculumItem] = relationship(back_populates="review")


class StudyLog(Base):
    __tablename__ = "study_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("curriculum_items.id"))
    logged_on: Mapped[date] = mapped_column(Date, index=True)
    action: Mapped[str] = mapped_column(String(32))  # studied | quizzed | built
    minutes: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[int] = mapped_column(Integer)  # 1-5
    notes: Mapped[str] = mapped_column(Text, default="")

    item: Mapped[CurriculumItem] = relationship(back_populates="logs")


# ------------------------------------------------------------------------- Daily


class DailyPlan(Base):
    __tablename__ = "daily_plans"

    id: Mapped[int] = mapped_column(primary_key=True)
    plan_date: Mapped[date] = mapped_column(Date, unique=True)
    alert_ids: Mapped[list] = mapped_column(JSON, default=list)
    study_item_ids: Mapped[list] = mapped_column(JSON, default=list)
    completed: Mapped[bool] = mapped_column(Boolean, default=False)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(200))
