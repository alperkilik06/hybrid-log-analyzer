"""Hybrid Intelligent Log & Threat Analyzer.

This single-file application implements a zero-cost first-pass rule engine,
then escalates only suspicious lines to Groq for structured JSON analysis.

Requirements:
    pip install groq customtkinter
    set GROQ_API_KEY=your_key_here

The GUI works with CustomTkinter when available and falls back to Tkinter.
"""

from __future__ import annotations

import json
import time
import os
import queue
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


def _load_dotenv_file() -> None:
    """Load local .env values without requiring an extra dependency."""
    env_path = Path(__file__).with_name(".env")
    if not env_path.exists():
        return

    try:
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    except OSError:
        return


_load_dotenv_file()

try:
    from groq import Groq
except Exception:  # pragma: no cover - optional dependency
    Groq = None  # type: ignore[assignment]

try:
    import customtkinter as ctk
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    USING_CUSTOMTKINTER = True
except Exception:  # pragma: no cover - optional dependency
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    ctk = None  # type: ignore[assignment]
    USING_CUSTOMTKINTER = False


APP_TITLE = "Hybrid Smart Log & Threat Analyzer"
DEFAULT_LOG_NAME = "access.log"
DEFAULT_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
DEFAULT_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3:8b")
MAX_AI_CALLS_PER_FILE = int(os.getenv("MAX_AI_CALLS_PER_FILE", "20"))
HIGH_RISK_COUNTRIES = {"china", "russia", "iran", "north korea", "belarus"}
MODEL_MODE_LABELS = {
    "groq": "Groq Cloud API",
    "ollama": "Ollama Local (Offline)",
}

SYSTEM_PROMPT = """You are a senior cybersecurity log analyst. 
Analyze the provided log entry and return ONLY a valid JSON object. 
IMPORTANT: All text fields ("technical_summary" and "mitigation_step") MUST BE WRITTEN IN TURKISH (Türkçe).

JSON Format:
{
  "status": "VULNERABLE" | "SUSPICIOUS" | "SAFE",
  "threat_category": "string",
  "cvss_score": float,
  "attacker_country": "Detect country name from IP if present, otherwise 'Bilinmiyor'",
  "technical_summary": "Türkçe teknik açıklama (Maksimum 2 cümle)",
  "mitigation_step": "Türkçe çözüm önerisi (Maksimum 1 cümle)"
}
"""


@dataclass
class RuleMatch:
    line_number: int
    line_text: str
    category: str
    matched_rule: str
    evidence: List[str] = field(default_factory=list)


@dataclass
class ThreatReport:
    line_number: int
    line_text: str
    category: str
    status: str
    cvss_score: float
    technical_summary: str
    mitigation_step: str
    matched_rule: str
    evidence: List[str] = field(default_factory=list)
    source_ip: str = ""
    source_country: str = "Unknown"
    source_city: str = "Unknown"
    source_region: str = "Unknown"
    geo_provider: str = "Unknown"


class GeoIPResolver:
    """Best-effort IP geolocation with safe fallbacks and caching."""

    IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
    IPV6_RE = re.compile(r"(?i)(?<![\w:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}(?![\w:])")

    def __init__(self) -> None:
        self._cache: Dict[str, Dict[str, str]] = {}
        self._geoip_reader = self._build_geoip_reader()

    def extract_ip(self, line_text: str) -> str:
        ipv4_match = self.IPV4_RE.search(line_text)
        if ipv4_match:
            return ipv4_match.group(0)
        ipv6_match = self.IPV6_RE.search(line_text)
        if ipv6_match:
            return ipv6_match.group(0)
        return ""

    def resolve(self, ip_address: str) -> Dict[str, str]:
        if not ip_address:
            return self._empty()
        if ip_address in self._cache:
            return self._cache[ip_address]

        result = self._resolve_with_geoip2(ip_address)
        if result is None:
            result = self._resolve_with_ip_api(ip_address)
        if result is None:
            result = self._empty()

        self._cache[ip_address] = result
        return result

    @staticmethod
    def _empty() -> Dict[str, str]:
        return {
            "ip": "",
            "country": "Unknown",
            "city": "Unknown",
            "region": "Unknown",
            "provider": "Unknown",
        }

    def _build_geoip_reader(self):
        db_path = os.getenv("GEOIP2_DB_PATH", "").strip()
        if not db_path:
            return None
        try:
            from geoip2.database import Reader  # type: ignore

            return Reader(db_path)
        except Exception:
            return None

    def _resolve_with_geoip2(self, ip_address: str) -> Optional[Dict[str, str]]:
        if self._geoip_reader is None:
            return None
        try:
            response = self._geoip_reader.city(ip_address)
            country = getattr(response.country, "name", None) or "Unknown"
            city = getattr(response.city, "name", None) or "Unknown"
            region = "Unknown"
            if response.subdivisions.most_specific and response.subdivisions.most_specific.name:
                region = response.subdivisions.most_specific.name
            return {
                "ip": ip_address,
                "country": country,
                "city": city,
                "region": region,
                "provider": "geoip2",
            }
        except Exception:
            return None

    def _resolve_with_ip_api(self, ip_address: str) -> Optional[Dict[str, str]]:
        if os.getenv("GEOIP_LOOKUP_DISABLED", "0") == "1":
            return None
        url = f"http://ip-api.com/json/{urllib.parse.quote(ip_address)}?fields=status,country,regionName,city,query,message"
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
            if payload.get("status") != "success":
                return None
            return {
                "ip": str(payload.get("query", ip_address)),
                "country": str(payload.get("country", "Unknown")),
                "city": str(payload.get("city", "Unknown")),
                "region": str(payload.get("regionName", "Unknown")),
                "provider": "ip-api.com",
            }
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            return None


class RuleEngine:
    """Zero-cost first-pass detection engine."""

    def __init__(self) -> None:
        self._patterns: Sequence[Tuple[str, str, Sequence[re.Pattern[str]]]] = [
            (
                "SQL Injection",
                "sql_injection",
                [
                    re.compile(r"(?i)\bunion\b\s+\bselect\b"),
                    re.compile(r"(?i)(?:'|\")\s*or\s*(?:'|\")?1(?:'|\")?\s*=\s*(?:'|\")?1"),
                    re.compile(r"(?i)\b(select|insert|update|delete|drop|union)\b.{0,40}\b(from|into|table)\b"),
                    re.compile(r"(?i)information_schema|sleep\s*\(|benchmark\s*\("),
                ],
            ),
            (
                "XSS",
                "xss",
                [
                    re.compile(r"(?i)<\s*script\b"),
                    re.compile(r"(?i)javascript:\s*"),
                    re.compile(r"(?i)on\w+\s*=\s*['\"]?"),
                    re.compile(r"(?i)<\s*img\b.*?onerror\s*="),
                ],
            ),
            (
                "Path Traversal",
                "path_traversal",
                [
                    re.compile(r"(?:\.\./|\.\.\\)+"),
                    re.compile(r"(?i)(?:/etc/passwd|windows\\win\.ini|boot\.ini)"),
                    re.compile(r"(?i)(?:%2e%2e%2f|%2e%2e%5c)"),
                ],
            ),
        ]

    def scan_line(self, line_number: int, line_text: str) -> Optional[RuleMatch]:
        normalized = line_text.strip()
        if not normalized:
            return None

        for category, rule_name, patterns in self._patterns:
            evidence = [pattern.pattern for pattern in patterns if pattern.search(normalized)]
            if evidence:
                return RuleMatch(
                    line_number=line_number,
                    line_text=normalized,
                    category=category,
                    matched_rule=rule_name,
                    evidence=evidence,
                )

        if self._looks_abnormal(normalized):
            return RuleMatch(
                line_number=line_number,
                line_text=normalized,
                category="Anomaly",
                matched_rule="anomaly_heuristic",
                evidence=["high_entropy_or_encoded_payload"],
            )

        return None

    def scan_file(self, file_path: Path) -> Tuple[int, List[RuleMatch]]:
        scanned = 0
        suspicious: List[RuleMatch] = []

        with file_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, line_text in enumerate(handle, start=1):
                scanned += 1
                match = self.scan_line(line_number, line_text)
                if match is not None:
                    suspicious.append(match)

        return scanned, suspicious

    @staticmethod
    def _looks_abnormal(line_text: str) -> bool:
        suspicious_characters = sum(1 for character in line_text if character in "%{}<>\\\"'`|")
        encoded_sequences = len(re.findall(r"(?:%[0-9a-fA-F]{2}){3,}", line_text))
        return len(line_text) > 512 or suspicious_characters > 18 or encoded_sequences > 0


class OllamaJudgementEngine:
    """Local offline analyst backed by the Ollama HTTP API."""

    SYSTEM_PROMPT = SYSTEM_PROMPT

    def __init__(self, model_name: str = DEFAULT_OLLAMA_MODEL) -> None:
        self.model_name = model_name

    def available(self) -> bool:
        try:
            with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=2) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
            models = data.get("models", [])
            return isinstance(models, list)
        except Exception:
            return False

    def analyze_match(self, match: RuleMatch, file_path: Path) -> ThreatReport:
        if self._client is None:
            return self._fallback_report(match, "Groq istemcisi hazır değil; yerel analiz yapıldı.")

        user_prompt = self._build_user_prompt(match, file_path)

        # Kronometre başlatılıyor
        start_time = time.perf_counter()

        try:
            response = self._client.chat.completions.create(
                model=self.model_name,
                temperature=0.1,
                max_tokens=250,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            )
            
            # Geçen süre
            elapsed_time = time.perf_counter() - start_time
            time_str = f"⏱️ {elapsed_time:.2f}s"
            
            print(f"[{time_str}] Groq AI analizi tamamlandı.")

            raw_content = response.choices[0].message.content or ""
            payload = self._extract_json_object(raw_content)
            
            # Raporu süreyi de içerecek şekilde normalize ediyoruz
            return self._normalize_report(match, payload, elapsed_str=time_str)
            
        except Exception as exc:
            elapsed_time = time.perf_counter() - start_time
            time_str = f"⏱️ {elapsed_time:.2f}s"
            print(f"[{time_str}] Groq analizi başarısız: {exc}")
            return self._fallback_report(match, f"Groq analizi başarısız oldu: {exc}")


class GroqJudgementEngine:
    """Groq-backed structured analyst with strict JSON output parsing."""

    SYSTEM_PROMPT = SYSTEM_PROMPT

    def __init__(self, model_name: str = DEFAULT_MODEL) -> None:
        self.model_name = model_name
        self._client = self._build_client()

    def available(self) -> bool:
        return self._client is not None

    def analyze_match(self, match: RuleMatch, file_path: Path) -> ThreatReport:
        if self._client is None:
            return self._fallback_report(match, "Groq client unavailable; local triage only.")

        user_prompt = self._build_user_prompt(match, file_path)

        try:
            # Stream ve reasoning_effort parametrelerinden temizlenmiş stabil çağrı
            response = self._client.chat.completions.create(
                model=self.model_name,
                temperature=0.1,
                max_tokens=250,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            )
            raw_content = response.choices[0].message.content or ""
            payload = self._extract_json_object(raw_content)
            return self._normalize_report(match, payload)
        except Exception as exc:
            return self._fallback_report(match, f"Groq analysis failed: {exc}")

    def _build_client(self) -> Optional[Any]:
        api_key = os.getenv("GROQ_API_KEY", "").strip()
        if not api_key or Groq is None:
            return None
        return Groq(api_key=api_key)

    @staticmethod
    def _build_user_prompt(match: RuleMatch, file_path: Path) -> str:
        return (
            "Bu şüpheli log satırını analiz et ve olası tehdidi Türkçe olarak raporla.\n"
            f"Dosya: {file_path.name}\n"
            f"Satır No: {match.line_number}\n"
            f"Tespit Edilen Kategori: {match.category}\n"
            f"Eşleşen Kural: {match.matched_rule}\n"
            f"Kanıt: {', '.join(match.evidence) if match.evidence else 'yok'}\n"
            f"Log Satırı: {match.line_text}\n"
            "Sadece ve sadece istenen JSON formatında yanıt ver."
        )
    @staticmethod
    def _extract_json_object(raw_content: str) -> Dict[str, Any]:
        cleaned = raw_content.strip()
        try:
            payload = json.loads(cleaned)
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            pass

        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = cleaned[start : end + 1]
            payload = json.loads(candidate)
            if isinstance(payload, dict):
                return payload

        raise ValueError("Model did not return valid JSON")

    @staticmethod
    def _normalize_report(match: RuleMatch, payload: Dict[str, Any], elapsed_str: str = "") -> ThreatReport:
        status = str(payload.get("status", "SUSPICIOUS")).upper().strip()
        if status not in {"VULNERABLE", "SUSPICIOUS", "SAFE"}:
            status = "SUSPICIOUS"

        category = str(payload.get("threat_category", match.category)).strip() or match.category
        cvss_raw = payload.get("cvss_score", 5.0)
        try:
            cvss_score = max(0.0, min(10.0, float(cvss_raw)))
        except (TypeError, ValueError):
            cvss_score = 5.0

        technical_summary = str(payload.get("technical_summary", "")).strip()
        mitigation_step = str(payload.get("mitigation_step", "")).strip()

        if not technical_summary:
            technical_summary = "Log satırı bilinen bir saldırı deseniyle eşleşen şüpheli içerik barındırıyor."
        if not mitigation_step:
            mitigation_step = "Saldırı desenini sınırda engelleyin ve sunucu tarafı girdi doğrulamasını kontrol edin."

        # Süre bilgisini özetin başına [⏱️ 0.24s] formatında ekliyoruz
        final_summary = f"[{elapsed_str}] {GroqJudgementEngine._cap_sentence_count(technical_summary, 2)}" if elapsed_str else GroqJudgementEngine._cap_sentence_count(technical_summary, 2)

        return ThreatReport(
            line_number=match.line_number,
            line_text=match.line_text,
            category=category,
            status=status,
            cvss_score=cvss_score,
            technical_summary=final_summary,
            mitigation_step=GroqJudgementEngine._cap_sentence_count(mitigation_step, 1),
            matched_rule=match.matched_rule,
            evidence=match.evidence,
        )

    @staticmethod
    def _fallback_report(match: RuleMatch, reason: str) -> ThreatReport:
        status_map = {
            "SQL Injection": ("VULNERABLE", 9.2),
            "XSS": ("VULNERABLE", 8.1),
            "Path Traversal": ("VULNERABLE", 8.8),
            "Anomaly": ("SUSPICIOUS", 4.6),
        }
        status, score = status_map.get(match.category, ("SUSPICIOUS", 5.0))
        return ThreatReport(
            line_number=match.line_number,
            line_text=match.line_text,
            category=match.category,
            status=status,
            cvss_score=score,
            technical_summary=f"{reason} Local rule engine flagged this line as {match.category.lower()}.",
            mitigation_step="Inspect the upstream request, block the payload signature, and confirm server-side sanitization.",
            matched_rule=match.matched_rule,
            evidence=match.evidence,
        )

    @staticmethod
    def _cap_sentence_count(text: str, max_sentences: int) -> str:
        sentences = re.split(r"(?<=[.!?])\s+", text.strip())
        if not sentences:
            return text.strip()
        return " ".join(sentences[:max_sentences]).strip()


class HybridAnalyzer:
    """Coordinates the rule engine and the Groq jury engine."""

    def __init__(self, model_mode: str = "groq") -> None:
        self.rule_engine = RuleEngine()
        self.geo_resolver = GeoIPResolver()
        self.ai_engine = self._build_engine(model_mode)

    @staticmethod
    def _build_engine(model_mode: str):
        if model_mode == "ollama":
            return OllamaJudgementEngine()
        return GroqJudgementEngine(model_name=DEFAULT_MODEL)

    def analyze_file(self, file_path: Path, model_mode: str = "groq") -> Tuple[int, List[RuleMatch], List[ThreatReport]]:
        self.ai_engine = self._build_engine(model_mode)
        scanned_count, matches = self.rule_engine.scan_file(file_path)
        enriched_matches = [self._enrich_match(match) for match in matches]
        selected_matches = matches[:MAX_AI_CALLS_PER_FILE]
        selected_enriched = enriched_matches[:MAX_AI_CALLS_PER_FILE]
        reports = [self.ai_engine.analyze_match(match, file_path) for match in selected_enriched]

        if len(matches) > len(selected_matches):
            skipped = len(matches) - len(selected_matches)
            reports.append(
                ThreatReport(
                    line_number=-1,
                    line_text=f"Skipped {skipped} extra suspicious lines to control API usage.",
                    category="Cost Guard",
                    status="SAFE",
                    cvss_score=0.0,
                    technical_summary="Additional suspicious lines were intentionally not sent to Groq to keep token usage and cost low.",
                    mitigation_step="Increase MAX_AI_CALLS_PER_FILE only if you need deeper analysis for a trusted, bounded file.",
                    matched_rule="cost_guard",
                    evidence=[],
                    source_ip="",
                    source_country="Unknown",
                    source_city="Unknown",
                    source_region="Unknown",
                    geo_provider="Unknown",
                )
            )

        return scanned_count, enriched_matches, reports

    def _enrich_match(self, match: RuleMatch) -> ThreatReport:
        geo = self.geo_resolver.resolve(self.geo_resolver.extract_ip(match.line_text))
        return ThreatReport(
            line_number=match.line_number,
            line_text=match.line_text,
            category=match.category,
            status="SUSPICIOUS",
            cvss_score=5.0,
            technical_summary="Rule engine flagged this line for threat review.",
            mitigation_step="Review the request and confirm server-side input validation.",
            matched_rule=match.matched_rule,
            evidence=match.evidence,
            source_ip=geo.get("ip", ""),
            source_country=geo.get("country", "Unknown"),
            source_city=geo.get("city", "Unknown"),
            source_region=geo.get("region", "Unknown"),
            geo_provider=geo.get("provider", "Unknown"),
        )


class LogThreatApp:
    """Dark-themed GUI for file selection, scanning, and threat review."""

    def __init__(self) -> None:
        self.analyzer = HybridAnalyzer(model_mode=self._initial_mode())
        self.event_queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self.selected_file: Optional[Path] = None
        self.all_reports: List[ThreatReport] = []
        self.visible_reports: List[ThreatReport] = []
        self.root = self._create_root()
        self._build_ui()
        self._auto_select_default_log()
        self.root.after(100, self._process_queue)

    def run(self) -> None:
        self.root.mainloop()

    def _create_root(self):
        if USING_CUSTOMTKINTER:
            ctk.set_appearance_mode("Dark")
            ctk.set_default_color_theme("dark-blue")
            root = ctk.CTk()
        else:
            root = tk.Tk()
            root.configure(bg="#111317")
        root.title(APP_TITLE)
        root.geometry("1180x760")
        root.minsize(1040, 680)
        return root

    def _build_ui(self) -> None:
        self._configure_style()

        if USING_CUSTOMTKINTER:
            container = ctk.CTkFrame(self.root, corner_radius=14)
        else:
            container = ttk.Frame(self.root, padding=14)
            container.pack(fill="both", expand=True)

        if USING_CUSTOMTKINTER:
            container.pack(fill="both", expand=True, padx=14, pady=14)

        header = self._panel(container)
        header.pack(fill="x", padx=8, pady=(8, 10))

        title = self._title_widget(header, "Hybrid Smart Log & Threat Analyzer")
        title.pack(anchor="w", padx=16, pady=(14, 2))

        subtitle = self._subtitle_widget(
            header,
            "0-cost rule engine filters normal traffic first; Groq only reviews suspicious payloads. Gizli ve hassas sistemler için %100 yerel ve offline analiz seçeneği Ollama ile burada sunulur.",
        )
        subtitle.pack(anchor="w", padx=16, pady=(0, 12))

        control_row = self._row(container)
        control_row.pack(fill="x", padx=8, pady=(0, 10))

        self.file_label = self._label(control_row, "File: not selected")
        self.file_label.pack(side="left", padx=(0, 12))

        self.select_button = self._button(control_row, "Select Log File", self.select_file)
        self.select_button.pack(side="left", padx=(0, 10))

        self.scan_button = self._button(control_row, "Scan & Analyze", self.start_analysis, state="disabled")
        self.scan_button.pack(side="left")

        model_row = self._row(container)
        model_row.pack(fill="x", padx=8, pady=(0, 10))

        self.model_mode_var = tk.StringVar(value="groq")
        mode_caption = self._subtitle_widget(
            model_row,
            "Analysis mode: choose Groq Cloud API for online AI or Ollama Local (Offline) for private, air-gapped operation.",
        )
        mode_caption.pack(side="left", padx=(0, 12))

        self.model_mode_selector = ttk.Combobox(
            model_row,
            state="readonly",
            values=[MODEL_MODE_LABELS["groq"], MODEL_MODE_LABELS["ollama"]],
            width=28,
        )
        self.model_mode_selector.set(MODEL_MODE_LABELS[self._initial_mode()])
        self.model_mode_selector.pack(side="left", padx=(0, 10))
        self.model_mode_selector.bind("<<ComboboxSelected>>", self._on_model_mode_changed)

        self.model_info_label = self._label(model_row, "Cloud: fast structured review | Local: fully offline privacy mode")
        self.model_info_label.pack(side="left", padx=(8, 0))

        filter_row = self._row(container)
        filter_row.pack(fill="x", padx=8, pady=(0, 10))

        self.filter_vulnerable_var = tk.BooleanVar(value=False)
        self.filter_only_checkbox = ttk.Checkbutton(
            filter_row,
            text="Show only VULNERABLE",
            variable=self.filter_vulnerable_var,
            command=self.apply_filters,
        )
        self.filter_only_checkbox.pack(side="left", padx=(0, 10))

        self.search_var = tk.StringVar(value="") if not USING_CUSTOMTKINTER else ctk.StringVar(value="")
        search_label = self._label(filter_row, "Category search:")
        search_label.pack(side="left", padx=(0, 8))
        self.search_entry = ttk.Entry(filter_row, textvariable=self.search_var, width=28)
        self.search_entry.pack(side="left", padx=(0, 10))
        self.search_entry.bind("<KeyRelease>", self._on_filter_changed)

        clear_button = self._button(filter_row, "Clear Filters", self.clear_filters)
        clear_button.pack(side="left")

        metrics_row = self._row(container)
        metrics_row.pack(fill="x", padx=8, pady=(0, 10))

        self.scanned_var = self._metric_card(metrics_row, "Taranan Log Sayısı", "0")
        self.scanned_var.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.threat_var = self._metric_card(metrics_row, "Yakalanan Tehdit Sayısı", "0")
        self.threat_var.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.ai_var = self._metric_card(metrics_row, "AI Durumu", "Idle")
        self.ai_var.pack(side="left", fill="x", expand=True)

        table_panel = self._panel(container)
        table_panel.pack(fill="both", expand=True, padx=8, pady=(0, 10))

        table_header = self._subtitle_widget(table_panel, "Threat details")
        table_header.pack(anchor="w", padx=16, pady=(14, 6))

        self.table = self._build_table(table_panel)
        self.table.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.table.bind("<<TreeviewSelect>>", self._show_selected_report)

        details_panel = self._panel(container)
        details_panel.pack(fill="x", padx=8, pady=(0, 8))

        details_title = self._subtitle_widget(details_panel, "Selected finding")
        details_title.pack(anchor="w", padx=16, pady=(12, 6))

        self.details_text = self._details_widget(details_panel)
        self.details_text.pack(fill="x", padx=12, pady=(0, 12))

        self.status_var = self._status_widget(container)
        self.status_var.pack(fill="x", padx=8, pady=(0, 8))

        self._insert_empty_state()

    def _configure_style(self) -> None:
        if USING_CUSTOMTKINTER:
            return

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dark.TFrame", background="#111317")
        style.configure("Dark.TLabel", background="#111317", foreground="#e8eaed")
        style.configure("Accent.TButton", background="#1f6feb", foreground="#ffffff", padding=(12, 8))
        style.map("Accent.TButton", background=[("active", "#2f81f7")])
        style.configure(
            "Treeview",
            background="#151a21",
            fieldbackground="#151a21",
            foreground="#e8eaed",
            rowheight=28,
            bordercolor="#2a2f38",
            lightcolor="#2a2f38",
            darkcolor="#2a2f38",
        )
        style.configure(
            "Treeview.Heading",
            background="#1c2128",
            foreground="#f0f3f6",
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", "#2457a6")],
            foreground=[("selected", "#ffffff")],
        )

    def _panel(self, parent):
        if USING_CUSTOMTKINTER:
            return ctk.CTkFrame(parent, corner_radius=14)
        return ttk.Frame(parent, style="Dark.TFrame")

    def _row(self, parent):
        if USING_CUSTOMTKINTER:
            return ctk.CTkFrame(parent, fg_color="transparent")
        return ttk.Frame(parent, style="Dark.TFrame")

    def _title_widget(self, parent, text: str):
        if USING_CUSTOMTKINTER:
            return ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=26, weight="bold"))
        return ttk.Label(parent, text=text, style="Dark.TLabel", font=("Segoe UI", 20, "bold"))

    def _subtitle_widget(self, parent, text: str):
        if USING_CUSTOMTKINTER:
            return ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=13), text_color="#b9c0cc")
        return ttk.Label(parent, text=text, style="Dark.TLabel", font=("Segoe UI", 10))

    def _label(self, parent, text: str):
        if USING_CUSTOMTKINTER:
            return ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=13))
        return ttk.Label(parent, text=text, style="Dark.TLabel", font=("Segoe UI", 10))

    def _button(self, parent, text: str, command, state: str = "normal"):
        if USING_CUSTOMTKINTER:
            return ctk.CTkButton(parent, text=text, command=command, state=state)
        return ttk.Button(parent, text=text, command=command, style="Accent.TButton", state=state)

    def _metric_card(self, parent, title: str, value: str):
        if USING_CUSTOMTKINTER:
            card = ctk.CTkFrame(parent, corner_radius=14)
            title_label = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12), text_color="#9aa4b2")
            value_label = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=26, weight="bold"))
            title_label.pack(anchor="w", padx=14, pady=(12, 2))
            value_label.pack(anchor="w", padx=14, pady=(0, 12))
        else:
            card = ttk.Frame(parent, style="Dark.TFrame")
            card.configure(padding=12)
            title_label = ttk.Label(card, text=title, style="Dark.TLabel", font=("Segoe UI", 9))
            value_label = ttk.Label(card, text=value, style="Dark.TLabel", font=("Segoe UI", 22, "bold"))
            title_label.pack(anchor="w")
            value_label.pack(anchor="w")

        card.value_label = value_label  # type: ignore[attr-defined]
        return card

    def _build_table(self, parent):
        columns = ("line", "category", "status", "cvss", "country", "summary")
        table = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        table.heading("line", text="Line")
        table.heading("category", text="Threat Category")
        table.heading("status", text="Status")
        table.heading("cvss", text="CVSS")
        table.heading("country", text="Saldırgan Ülkesi")
        table.heading("summary", text="Technical Summary")
        table.column("line", width=90, anchor="center")
        table.column("category", width=180, anchor="w")
        table.column("status", width=120, anchor="center")
        table.column("cvss", width=80, anchor="center")
        table.column("country", width=150, anchor="center")
        table.column("summary", width=500, anchor="w")

        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        table.tag_configure("critical", background="#5b1d1d", foreground="#fff1f1")
        table.tag_configure("high", background="#7a2f12", foreground="#fff7ed")
        table.tag_configure("medium", background="#5b4a12", foreground="#fff8d6")
        table.tag_configure("low", background="#173b20", foreground="#ecfdf3")
        table.tag_configure("high_risk_country", font=("Segoe UI", 9, "bold"))
        return table

    def _details_widget(self, parent):
        if USING_CUSTOMTKINTER:
            text = ctk.CTkTextbox(parent, height=120, wrap="word")
            text.configure(state="disabled")
            return text
        text = tk.Text(parent, height=8, wrap="word", bg="#151a21", fg="#e8eaed", insertbackground="#e8eaed", relief="flat")
        text.configure(state="disabled")
        return text

    def _status_widget(self, parent):
        if USING_CUSTOMTKINTER:
            return ctk.CTkLabel(parent, text="Ready.", anchor="w", text_color="#aab2bf")
        return ttk.Label(parent, text="Ready.", style="Dark.TLabel", anchor="w")

    def _insert_empty_state(self) -> None:
        self._clear_table()
        self._set_details("Select a log file to start scanning.")

    def select_file(self) -> None:
        file_name = filedialog.askopenfilename(
            title="Select access.log",
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")],
        )
        if not file_name:
            return

        self.selected_file = Path(file_name)
        self._set_file_label(self.selected_file)
        self.scan_button.configure(state="normal")
        self.status_var.configure(text="File selected. Ready to scan.")

    def _auto_select_default_log(self) -> None:
        candidate = Path.cwd() / DEFAULT_LOG_NAME
        if candidate.exists():
            self.selected_file = candidate
            self._set_file_label(candidate)
            self.scan_button.configure(state="normal")
            self.status_var.configure(text=f"Auto-detected {DEFAULT_LOG_NAME}. Ready to scan.")

    @staticmethod
    def _initial_mode() -> str:
        if os.getenv("GROQ_API_KEY", "").strip() and Groq is not None:
            return "groq"
        return "ollama"

    def _on_model_mode_changed(self, _event=None) -> None:
        selected_label = self.model_mode_selector.get()
        reverse_lookup = {value: key for key, value in MODEL_MODE_LABELS.items()}
        mode = reverse_lookup.get(selected_label, "groq")
        self.status_var.configure(text=f"Analysis mode set to {selected_label}.")
        self.analyzer = HybridAnalyzer(model_mode=mode)

    def _on_filter_changed(self, _event=None) -> None:
        self.apply_filters()

    def clear_filters(self) -> None:
        self.filter_vulnerable_var.set(False)
        self.search_var.set("")
        self.apply_filters()

    def apply_filters(self) -> None:
        category_query = self.search_var.get().strip().lower()
        show_only_vulnerable = bool(self.filter_vulnerable_var.get())
        self.visible_reports = []
        self._clear_table()

        for report in self.all_reports:
            if show_only_vulnerable and report.status != "VULNERABLE":
                continue
            if category_query and category_query not in report.category.lower():
                continue
            self.visible_reports.append(report)
            self._insert_report_row(report)

        self._update_details_after_filter()

    def _update_details_after_filter(self) -> None:
        first_item = self.table.get_children()
        if first_item:
            self.table.selection_set(first_item[0])
            self.table.focus(first_item[0])
            self._show_report(self.visible_reports[0])
        else:
            self._set_details("No rows match the current filters.")

    def start_analysis(self) -> None:
        if self.selected_file is None:
            messagebox.showwarning("No file selected", "Please select a log file first.")
            return
        if not self.selected_file.exists():
            messagebox.showerror("File not found", f"The file does not exist:\n{self.selected_file}")
            return

        self.select_button.configure(state="disabled")
        self.scan_button.configure(state="disabled")
        self.status_var.configure(text="Scanning file and analyzing suspicious lines...")
        self._set_metric(self.scanned_var, "...")
        self._set_metric(self.threat_var, "...")
        self._set_metric(self.ai_var, "Running")
        self._clear_table()
        self._set_details("Working...")

        worker = threading.Thread(target=self._worker_analyze, args=(self.selected_file,), daemon=True)
        worker.start()

    def _worker_analyze(self, file_path: Path) -> None:
        try:
            mode = self._select_engine_mode()
            scanned_count, matches, reports = self.analyzer.analyze_file(file_path, model_mode=mode)
            self.event_queue.put(("success", (file_path, scanned_count, matches, reports)))
        except Exception as exc:
            self.event_queue.put(("error", exc))

    def _process_queue(self) -> None:
        try:
            while True:
                event_type, payload = self.event_queue.get_nowait()
                if event_type == "success":
                    file_path, scanned_count, matches, reports = payload
                    self._render_results(file_path, scanned_count, matches, reports)
                elif event_type == "error":
                    self._handle_error(payload)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._process_queue)

    def _render_results(
        self,
        file_path: Path,
        scanned_count: int,
        matches: List[RuleMatch],
        reports: List[ThreatReport],
    ) -> None:
        self._set_metric(self.scanned_var, str(scanned_count))
        self._set_metric(self.threat_var, str(len(matches)))
        self._set_metric(self.ai_var, "Done")
        self.status_var.configure(text=f"Completed analysis for {file_path.name}.")

        self.all_reports = reports
        self.apply_filters()
        if not reports:
            self._set_details("No suspicious lines were detected in this file.")

        self.select_button.configure(state="normal")
        self.scan_button.configure(state="normal")

    def _handle_error(self, exc: Exception) -> None:
        self.select_button.configure(state="normal")
        self.scan_button.configure(state="normal")
        self._set_metric(self.ai_var, "Error")
        self.status_var.configure(text="Analysis failed.")
        messagebox.showerror("Analysis error", str(exc))

    def _show_selected_report(self, _event) -> None:
        selection = self.table.selection()
        if not selection:
            return

        index = self.table.index(selection[0])
        if 0 <= index < len(self.visible_reports):
            self._show_report(self.visible_reports[index])

    def _show_report(self, report: ThreatReport) -> None:
        details = self._format_report(report)
        self._set_details(details)

    def _format_report(self, report: ThreatReport) -> str:
        lines = [
            f"Line: {report.line_number if report.line_number != -1 else '-'}",
            f"Category: {report.category}",
            f"Status: {report.status}",
            f"CVSS: {report.cvss_score:.1f}",
            f"Saldırgan IP: {report.source_ip or 'Unknown'}",
            f"Saldırgan Ülkesi: {report.source_country}",
            f"Saldırgan Şehri: {report.source_city}",
            f"Geo Provider: {report.geo_provider}",
            f"Matched rule: {report.matched_rule}",
            f"Evidence: {', '.join(report.evidence) if report.evidence else 'none'}",
            f"Technical summary: {report.technical_summary}",
            f"Mitigation step: {report.mitigation_step}",
        ]
        if report.line_text:
            lines.append(f"Log line: {report.line_text}")
        return "\n".join(lines)

    @staticmethod
    def _report_as_dict(report: ThreatReport) -> Dict[str, Any]:
        return {
            "line_number": report.line_number,
            "line_text": report.line_text,
            "category": report.category,
            "status": report.status,
            "cvss_score": report.cvss_score,
            "technical_summary": report.technical_summary,
            "mitigation_step": report.mitigation_step,
            "matched_rule": report.matched_rule,
            "evidence": report.evidence,
            "source_ip": report.source_ip,
            "source_country": report.source_country,
            "source_city": report.source_city,
            "source_region": report.source_region,
            "geo_provider": report.geo_provider,
        }

    def _set_metric(self, metric_widget, value: str) -> None:
        metric_widget.value_label.configure(text=value)

    def _set_file_label(self, file_path: Path) -> None:
        self.file_label.configure(text=f"File: {file_path.name}")

    def _set_details(self, text: str) -> None:
        if USING_CUSTOMTKINTER:
            self.details_text.configure(state="normal")
            self.details_text.delete("1.0", "end")
            self.details_text.insert("1.0", text)
            self.details_text.configure(state="disabled")
            return

        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", text)
        self.details_text.configure(state="disabled")

    def _clear_table(self) -> None:
        for item in self.table.get_children():
            self.table.delete(item)

    def _insert_report_row(self, report: ThreatReport) -> None:
        line_value = "-" if report.line_number == -1 else str(report.line_number)
        summary = report.technical_summary if len(report.technical_summary) <= 120 else self._truncate(report.technical_summary, 120)
        country_display = report.source_country
        if report.source_country.lower() in HIGH_RISK_COUNTRIES:
            country_display = f"{report.source_country} *"

        tags: List[str] = []
        if report.cvss_score >= 9.0:
            tags.append("critical")
        elif report.cvss_score >= 8.0:
            tags.append("high")
        elif report.cvss_score >= 5.0:
            tags.append("medium")
        else:
            tags.append("low")

        if report.source_country.lower() in HIGH_RISK_COUNTRIES:
            tags.append("high_risk_country")

        self.table.insert(
            "",
            "end",
            values=(line_value, report.category, report.status, f"{report.cvss_score:.1f}", country_display, summary),
            tags=tuple(tags),
        )

    def _select_engine_mode(self) -> str:
        selected_label = self.model_mode_selector.get() if hasattr(self, "model_mode_selector") else MODEL_MODE_LABELS["groq"]
        reverse_lookup = {value: key for key, value in MODEL_MODE_LABELS.items()}
        return reverse_lookup.get(selected_label, "groq")

    @staticmethod
    def _truncate(text: str, length: int) -> str:
        if len(text) <= length:
            return text
        return text[: max(0, length - 3)].rstrip() + "..."


def main() -> None:
    app = LogThreatApp()
    app.run()


if __name__ == "__main__":
    main()