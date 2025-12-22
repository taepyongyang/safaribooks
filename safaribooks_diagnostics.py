"""
SafariBooks Diagnostic System

Tracks download completeness and validates EPUB integrity.
Enabled with --debug flag for minimal performance impact when disabled.
"""

import os
import json
import time
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum
from collections import defaultdict


class FailureCategory(Enum):
    """Categorizes failure types for reporting."""
    NETWORK = "network"           # Connection/timeout errors
    PARSING = "parsing"           # HTML/CSS parse errors
    MISSING_CONTENT = "missing"   # Expected content not found
    VALIDATION = "validation"     # Integrity check failures
    SKIPPED = "skipped"           # Deliberately skipped (e.g., SVG)


@dataclass
class FailureRecord:
    """Detailed record of a single failure."""
    category: FailureCategory
    stage: str                    # e.g., "chapters", "css", "images", "epub"
    url: str
    status_code: Optional[int] = None
    error_message: str = ""
    content_sample: str = ""      # First 500 chars of response/content
    timestamp: float = field(default_factory=time.time)
    context: Dict = field(default_factory=dict)  # Additional metadata


@dataclass
class StageMetrics:
    """Tracks expected vs actual counts for a download stage."""
    expected: int = 0
    attempted: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0

    @property
    def completion_rate(self) -> float:
        if self.expected == 0:
            return 100.0
        return (self.succeeded / self.expected) * 100

    @property
    def is_complete(self) -> bool:
        return self.succeeded >= self.expected


class DiagnosticCollector:
    """
    Collects diagnostic data throughout the download process.

    Usage:
        diagnostics = DiagnosticCollector(enabled=args.debug, book_id=args.bookid)
        diagnostics.set_expected("chapters", len(book_chapters))
        # ... during download ...
        diagnostics.record_success("chapters", chapter_url)
        # or
        diagnostics.record_failure("chapters", chapter_url, FailureCategory.NETWORK, ...)
        # ... at end ...
        diagnostics.validate_epub(epub_path)
        report = diagnostics.generate_report()
    """

    def __init__(self, enabled: bool = False, book_id: str = "", output_dir: str = ""):
        self.enabled = enabled
        self.book_id = book_id
        self.output_dir = output_dir
        self.start_time = time.time()

        # Stage metrics tracking
        self.stages: Dict[str, StageMetrics] = {
            "chapters": StageMetrics(),
            "css": StageMetrics(),
            "images": StageMetrics(),
            "epub_files": StageMetrics(),
        }

        # Detailed failure records
        self.failures: List[FailureRecord] = []

        # Asset tracking for cross-referencing
        self.detected_assets: Dict[str, Set[str]] = {
            "css": set(),           # URLs found in HTML
            "images": set(),        # URLs found in HTML (including link_replace)
            "downloaded_css": set(),
            "downloaded_images": set(),
        }

        # Reference tracking for EPUB validation
        self.chapter_files: List[str] = []      # Expected chapter files
        self.toc_references: Set[str] = set()   # TOC href references

        # Pagination tracking for get_book_chapters
        self.pagination_pages: List[int] = []
        self.pagination_errors: List[Dict] = []

        # Chapter metadata tracking (raw API data for debugging)
        self.chapter_metadata: List[Dict] = []

    # ============================================================
    # Stage Tracking Methods
    # ============================================================

    def set_expected(self, stage: str, count: int) -> None:
        """Set expected count for a stage."""
        if not self.enabled:
            return
        if stage in self.stages:
            self.stages[stage].expected = count

    def record_success(self, stage: str, identifier: str, metadata: Dict = None) -> None:
        """Record successful completion of an item."""
        if not self.enabled:
            return
        if stage in self.stages:
            self.stages[stage].attempted += 1
            self.stages[stage].succeeded += 1

            # Track downloaded assets (use filename only for comparison)
            if stage == "css":
                self.detected_assets["downloaded_css"].add(identifier)
            elif stage == "images":
                # Extract filename from URL for cross-reference matching
                image_name = identifier.split("/")[-1] if "/" in identifier else identifier
                self.detected_assets["downloaded_images"].add(image_name)

    def record_failure(
        self,
        stage: str,
        url: str,
        category: FailureCategory,
        status_code: Optional[int] = None,
        error_message: str = "",
        content_sample: str = "",
        context: Dict = None
    ) -> None:
        """Record a failure with full context."""
        if not self.enabled:
            return
        if stage in self.stages:
            self.stages[stage].attempted += 1
            self.stages[stage].failed += 1

        self.failures.append(FailureRecord(
            category=category,
            stage=stage,
            url=url,
            status_code=status_code,
            error_message=error_message,
            content_sample=content_sample[:500] if content_sample else "",
            context=context or {}
        ))

    def record_skipped(self, stage: str, url: str, reason: str) -> None:
        """Record an intentionally skipped item (e.g., SVG image)."""
        if not self.enabled:
            return
        if stage in self.stages:
            self.stages[stage].skipped += 1

        self.failures.append(FailureRecord(
            category=FailureCategory.SKIPPED,
            stage=stage,
            url=url,
            error_message=reason,
        ))

    # ============================================================
    # Asset Detection Tracking (for cross-referencing)
    # ============================================================

    def track_detected_asset(self, asset_type: str, url: str) -> None:
        """Track an asset detected in HTML that should be downloaded."""
        if not self.enabled:
            return
        if asset_type in self.detected_assets:
            self.detected_assets[asset_type].add(url)

    def track_chapter_file(self, filename: str) -> None:
        """Track expected chapter file for EPUB validation."""
        if not self.enabled:
            return
        self.chapter_files.append(filename)

    def track_toc_reference(self, href: str) -> None:
        """Track TOC reference for validation."""
        if not self.enabled:
            return
        self.toc_references.add(href)

    def track_pagination(self, page: int, success: bool, error: str = "") -> None:
        """Track chapter pagination for detecting silent failures."""
        if not self.enabled:
            return
        self.pagination_pages.append(page)
        if not success:
            self.pagination_errors.append({"page": page, "error": error})

    def track_chapter_metadata(self, chapter: Dict) -> None:
        """Track raw chapter metadata from API for debugging."""
        if not self.enabled:
            return
        # Store essential fields for debugging
        self.chapter_metadata.append({
            "filename": chapter.get("filename", "MISSING"),
            "title": chapter.get("title", "MISSING"),
            "content": chapter.get("content", "MISSING")[:100] if chapter.get("content") else "MISSING",
            "has_images": "images" in chapter and len(chapter.get("images", [])) > 0,
            "has_stylesheets": "stylesheets" in chapter and len(chapter.get("stylesheets", [])) > 0,
        })

    # ============================================================
    # EPUB Validation
    # ============================================================

    def validate_epub(self, epub_path: str) -> Dict:
        """
        Validate EPUB integrity before completion.

        Returns dict with validation results and any issues found.
        """
        if not self.enabled:
            return {"status": "skipped", "enabled": False}

        validation_results = {
            "status": "passed",
            "epub_exists": False,
            "epub_size": 0,
            "required_files": {},
            "chapter_files": {},
            "asset_files": {},
            "issues": []
        }

        if not os.path.isfile(epub_path):
            validation_results["status"] = "failed"
            validation_results["issues"].append(f"EPUB file not found: {epub_path}")
            return validation_results

        validation_results["epub_exists"] = True
        validation_results["epub_size"] = os.path.getsize(epub_path)

        try:
            with zipfile.ZipFile(epub_path, 'r') as epub:
                epub_files = set(epub.namelist())

                # Check required EPUB structure
                required = ["mimetype", "META-INF/container.xml",
                            "OEBPS/content.opf", "OEBPS/toc.ncx"]
                for req in required:
                    exists = req in epub_files
                    validation_results["required_files"][req] = exists
                    if not exists:
                        validation_results["status"] = "failed"
                        validation_results["issues"].append(f"Missing required file: {req}")

                # Check chapter files
                for chapter in self.chapter_files:
                    chapter_path = f"OEBPS/{chapter}"
                    exists = chapter_path in epub_files
                    validation_results["chapter_files"][chapter] = exists
                    if not exists:
                        validation_results["status"] = "failed"
                        validation_results["issues"].append(f"Missing chapter: {chapter}")

                # Check downloaded images exist in EPUB
                for img_url in self.detected_assets.get("downloaded_images", set()):
                    img_name = img_url.split("/")[-1] if "/" in img_url else img_url
                    img_path = f"OEBPS/Images/{img_name}"
                    exists = img_path in epub_files
                    validation_results["asset_files"][img_name] = exists

        except zipfile.BadZipFile as e:
            validation_results["status"] = "failed"
            validation_results["issues"].append(f"Corrupt EPUB file: {e}")
        except Exception as e:
            validation_results["status"] = "failed"
            validation_results["issues"].append(f"Validation error: {e}")

        return validation_results

    # ============================================================
    # Report Generation
    # ============================================================

    def generate_report(self) -> Dict:
        """
        Generate comprehensive diagnostic report.

        Returns structured dict suitable for JSON serialization or display.
        """
        duration = time.time() - self.start_time

        # Analyze undownloaded assets
        missing_css = self.detected_assets["css"] - self.detected_assets["downloaded_css"]
        missing_images = self.detected_assets["images"] - self.detected_assets["downloaded_images"]

        # Categorize failures
        failures_by_category = defaultdict(list)
        failures_by_stage = defaultdict(list)
        for f in self.failures:
            failures_by_category[f.category.value].append(f)
            failures_by_stage[f.stage].append(f)

        report = {
            "meta": {
                "book_id": self.book_id,
                "duration_seconds": round(duration, 2),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "diagnostics_enabled": self.enabled,
            },
            "summary": {
                "overall_status": self._compute_overall_status(),
                "total_failures": len(self.failures),
                "stages": {}
            },
            "stage_details": {},
            "asset_tracking": {
                "css_detected": len(self.detected_assets["css"]),
                "css_downloaded": len(self.detected_assets["downloaded_css"]),
                "css_missing": list(missing_css),
                "images_detected": len(self.detected_assets["images"]),
                "images_downloaded": len(self.detected_assets["downloaded_images"]),
                "images_missing": list(missing_images),
            },
            "pagination": {
                "pages_fetched": len(self.pagination_pages),
                "errors": self.pagination_errors,
            },
            "failures": {
                "by_category": {k: len(v) for k, v in failures_by_category.items()},
                "by_stage": {k: len(v) for k, v in failures_by_stage.items()},
                "details": [self._serialize_failure(f) for f in self.failures[:50]],  # Limit to 50
            },
            "chapter_metadata": self.chapter_metadata,  # Raw API data for debugging
        }

        # Add per-stage metrics
        for stage_name, metrics in self.stages.items():
            report["summary"]["stages"][stage_name] = {
                "expected": metrics.expected,
                "succeeded": metrics.succeeded,
                "failed": metrics.failed,
                "skipped": metrics.skipped,
                "completion_rate": round(metrics.completion_rate, 1),
                "is_complete": metrics.is_complete,
            }

        return report

    def _compute_overall_status(self) -> str:
        """Determine overall download status."""
        total_failures = len([f for f in self.failures if f.category != FailureCategory.SKIPPED])
        all_complete = all(m.is_complete for m in self.stages.values())

        if total_failures == 0 and all_complete:
            return "SUCCESS"
        elif total_failures > 0 and all_complete:
            return "SUCCESS_WITH_WARNINGS"
        elif any(m.completion_rate >= 80 for m in self.stages.values()):
            return "PARTIAL"
        else:
            return "FAILED"

    def _serialize_failure(self, f: FailureRecord) -> Dict:
        """Convert FailureRecord to serializable dict."""
        return {
            "category": f.category.value,
            "stage": f.stage,
            "url": f.url,
            "status_code": f.status_code,
            "error_message": f.error_message,
            "content_sample": f.content_sample,
            "context": f.context,
        }

    def save_report(self, output_path: str) -> None:
        """Save diagnostic report to JSON file."""
        if not self.enabled:
            return
        report = self.generate_report()
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

    def print_summary(self) -> str:
        """Generate human-readable summary for console output."""
        if not self.enabled:
            return ""

        report = self.generate_report()
        lines = [
            "",
            "=" * 60,
            "DOWNLOAD DIAGNOSTIC SUMMARY",
            "=" * 60,
            f"Book ID: {report['meta']['book_id']}",
            f"Duration: {report['meta']['duration_seconds']}s",
            f"Status: {report['summary']['overall_status']}",
            "",
            "Stage Metrics:",
        ]

        for stage, metrics in report["summary"]["stages"].items():
            status_icon = "[OK]" if metrics["is_complete"] else "[!!]"
            lines.append(
                f"  {status_icon} {stage}: {metrics['succeeded']}/{metrics['expected']} "
                f"({metrics['completion_rate']}%) - {metrics['failed']} failed, {metrics['skipped']} skipped"
            )

        if report["asset_tracking"]["css_missing"]:
            lines.append(f"\nMissing CSS: {len(report['asset_tracking']['css_missing'])}")
            for css in report["asset_tracking"]["css_missing"][:5]:
                lines.append(f"  - {css}")
            if len(report["asset_tracking"]["css_missing"]) > 5:
                lines.append(f"  ... and {len(report['asset_tracking']['css_missing']) - 5} more")

        if report["asset_tracking"]["images_missing"]:
            lines.append(f"\nMissing Images: {len(report['asset_tracking']['images_missing'])}")
            for img in report["asset_tracking"]["images_missing"][:5]:
                lines.append(f"  - {img}")
            if len(report["asset_tracking"]["images_missing"]) > 5:
                lines.append(f"  ... and {len(report['asset_tracking']['images_missing']) - 5} more")

        if report["failures"]["by_category"]:
            lines.append("\nFailures by Category:")
            for cat, count in report["failures"]["by_category"].items():
                lines.append(f"  - {cat}: {count}")

        lines.append("=" * 60)
        return "\n".join(lines)
