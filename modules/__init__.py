"""Threat Intelligence Aggregator core modules package."""

from modules.blocklist_generator import BlocklistExportResult, BlocklistGenerator
from modules.correlation import CorrelationEngine, CorrelationResult
from modules.database_manager import DatabaseManager
from modules.feed_collector import FeedCollector, FeedResult
from modules.ioc_parser import IOCParser, ParsedIOC
from modules.normalizer import DeduplicatedIOC, IOCNormalizer, NormalizedIOC
from modules.pipeline import PipelineResult, ThreatIntelligencePipeline
from modules.report_generator import ReportGenerator, ReportResult
from modules.validator import IOCValidator, ValidationResult

__all__ = [
    "FeedCollector",
    "FeedResult",
    "IOCParser",
    "ParsedIOC",
    "IOCValidator",
    "ValidationResult",
    "IOCNormalizer",
    "NormalizedIOC",
    "DeduplicatedIOC",
    "DatabaseManager",
    "CorrelationEngine",
    "CorrelationResult",
    "BlocklistGenerator",
    "BlocklistExportResult",
    "ReportGenerator",
    "ReportResult",
    "ThreatIntelligencePipeline",
    "PipelineResult",
]
