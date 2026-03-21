"""
P6-10: Noise Layering Tests

Tests for P6-04 conditional/informational subtype classification
and noise layering functionality.

Noise layering classifies findings into:
- Conditional: Needs environment verification (strong/weak)
- Informational: Not exploitable but worth noting (not_exploitable/speculative_signal/environmental_risk)
"""

import pytest

from src.layers.l3_analysis.models import (
    CodeLocation,
    ConditionalSubtype,
    Finding,
    FindingType,
    InformationalSubtype,
    SeverityLevel,
)
from src.layers.l3_analysis.taint_report import (
    Controllability,
    SanitizerType,
    SinkType,
    SourceType,
    TaintSource,
)


# =============================================================================
# Test ConditionalSubtype Enum
# =============================================================================


class TestConditionalSubtype:
    """Test ConditionalSubtype enum values and behavior."""

    def test_strong_exists(self):
        """Verify STRONG subtype exists."""
        assert ConditionalSubtype.STRONG.value == "conditional-strong"

    def test_weak_exists(self):
        """Verify WEAK subtype exists."""
        assert ConditionalSubtype.WEAK.value == "conditional-weak"

    def test_all_subtypes_count(self):
        """Verify we have exactly 2 conditional subtypes."""
        subtypes = list(ConditionalSubtype)
        assert len(subtypes) == 2

    def test_strong_serialization(self):
        """Verify STRONG serializes correctly."""
        assert ConditionalSubtype.STRONG.value == "conditional-strong"
        assert ConditionalSubtype("conditional-strong") == ConditionalSubtype.STRONG

    def test_weak_serialization(self):
        """Verify WEAK serializes correctly."""
        assert ConditionalSubtype.WEAK.value == "conditional-weak"
        assert ConditionalSubtype("conditional-weak") == ConditionalSubtype.WEAK


# =============================================================================
# Test InformationalSubtype Enum
# =============================================================================


class TestInformationalSubtype:
    """Test InformationalSubtype enum values and behavior."""

    def test_not_exploitable_exists(self):
        """Verify NOT_EXPLOITABLE subtype exists."""
        assert InformationalSubtype.NOT_EXPLOITABLE.value == "not_exploitable"

    def test_speculative_signal_exists(self):
        """Verify SPECULATIVE_SIGNAL subtype exists."""
        assert InformationalSubtype.SPECULATIVE_SIGNAL.value == "speculative_signal"

    def test_environmental_risk_exists(self):
        """Verify ENVIRONMENTAL_RISK subtype exists."""
        assert InformationalSubtype.ENVIRONMENTAL_RISK.value == "environmental_risk"

    def test_all_subtypes_count(self):
        """Verify we have exactly 3 informational subtypes."""
        subtypes = list(InformationalSubtype)
        assert len(subtypes) == 3

    def test_not_exploitable_serialization(self):
        """Verify NOT_EXPLOITABLE serializes correctly."""
        assert InformationalSubtype("not_exploitable") == InformationalSubtype.NOT_EXPLOITABLE


# =============================================================================
# Test Finding with ConditionalSubtype
# =============================================================================


class TestFindingConditionalSubtype:
    """Test Finding model integration with ConditionalSubtype."""

    def _create_finding(self, **kwargs) -> Finding:
        """Helper to create a Finding for testing."""
        defaults = {
            "id": "test-001",
            "severity": SeverityLevel.HIGH,
            "title": "Test vulnerability",
            "description": "Test description",
            "location": CodeLocation(file="test.py", line=1),
            "source": "agent",
        }
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_finding_with_conditional_strong(self):
        """Test Finding can have conditional_subtype=STRONG."""
        finding = self._create_finding(
            conditional_subtype=ConditionalSubtype.STRONG,
            report_status="conditional",
        )
        assert finding.conditional_subtype == ConditionalSubtype.STRONG
        assert finding.report_status == "conditional"

    def test_finding_with_conditional_weak(self):
        """Test Finding can have conditional_subtype=WEAK."""
        finding = self._create_finding(
            conditional_subtype=ConditionalSubtype.WEAK,
            report_status="conditional",
        )
        assert finding.conditional_subtype == ConditionalSubtype.WEAK

    def test_finding_conditional_subtype_none_by_default(self):
        """Test Finding has None for conditional_subtype by default."""
        finding = self._create_finding()
        assert finding.conditional_subtype is None

    def test_finding_conditional_requires_report_status(self):
        """Test that conditional findings should have report_status='conditional'."""
        finding = self._create_finding(
            conditional_subtype=ConditionalSubtype.STRONG,
            report_status="conditional",
        )
        assert finding.report_status == "conditional"
        assert finding.conditional_subtype is not None

    def test_conditional_strong_high_confidence(self):
        """Test conditional-strong typically has higher confidence."""
        finding = self._create_finding(
            conditional_subtype=ConditionalSubtype.STRONG,
            confidence=0.8,
            exploitability="likely",
        )
        assert finding.confidence >= 0.7
        assert finding.conditional_subtype == ConditionalSubtype.STRONG

    def test_conditional_weak_low_confidence(self):
        """Test conditional-weak typically has lower confidence."""
        finding = self._create_finding(
            conditional_subtype=ConditionalSubtype.WEAK,
            confidence=0.5,
            exploitability="possible",
        )
        assert finding.confidence < 0.7
        assert finding.conditional_subtype == ConditionalSubtype.WEAK


# =============================================================================
# Test Finding with InformationalSubtype
# =============================================================================


class TestFindingInformationalSubtype:
    """Test Finding model integration with InformationalSubtype."""

    def _create_finding(self, **kwargs) -> Finding:
        """Helper to create a Finding for testing."""
        defaults = {
            "id": "test-001",
            "severity": SeverityLevel.LOW,
            "title": "Test finding",
            "description": "Test description",
            "location": CodeLocation(file="test.py", line=1),
            "source": "agent",
        }
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_finding_with_not_exploitable(self):
        """Test Finding can have informational_subtype=NOT_EXPLOITABLE."""
        finding = self._create_finding(
            informational_subtype=InformationalSubtype.NOT_EXPLOITABLE,
            report_status="informational",
            exploitability="not_exploitable",
        )
        assert finding.informational_subtype == InformationalSubtype.NOT_EXPLOITABLE
        assert finding.report_status == "informational"

    def test_finding_with_speculative_signal(self):
        """Test Finding can have informational_subtype=SPECULATIVE_SIGNAL."""
        finding = self._create_finding(
            informational_subtype=InformationalSubtype.SPECULATIVE_SIGNAL,
            report_status="informational",
        )
        assert finding.informational_subtype == InformationalSubtype.SPECULATIVE_SIGNAL

    def test_finding_with_environmental_risk(self):
        """Test Finding can have informational_subtype=ENVIRONMENTAL_RISK."""
        finding = self._create_finding(
            informational_subtype=InformationalSubtype.ENVIRONMENTAL_RISK,
            report_status="informational",
        )
        assert finding.informational_subtype == InformationalSubtype.ENVIRONMENTAL_RISK

    def test_finding_informational_subtype_none_by_default(self):
        """Test Finding has None for informational_subtype by default."""
        finding = self._create_finding()
        assert finding.informational_subtype is None

    def test_not_exploitable_with_sanitization(self):
        """Test NOT_EXPLOITABLE typically indicates sanitization."""
        finding = self._create_finding(
            informational_subtype=InformationalSubtype.NOT_EXPLOITABLE,
            exploitability="not_exploitable",
            taint_analysis={
                "has_sanitizer": True,
                "sanitizer_type": "parameterized_query",
            },
        )
        assert finding.informational_subtype == InformationalSubtype.NOT_EXPLOITABLE
        assert finding.taint_analysis.get("has_sanitizer") is True

    def test_speculative_signal_with_suspicious_type(self):
        """Test SPECULATIVE_SIGNAL often pairs with SUSPICIOUS type."""
        finding = self._create_finding(
            type=FindingType.SUSPICIOUS,
            informational_subtype=InformationalSubtype.SPECULATIVE_SIGNAL,
        )
        assert finding.type == FindingType.SUSPICIOUS
        assert finding.informational_subtype == InformationalSubtype.SPECULATIVE_SIGNAL


# =============================================================================
# Test Taint Report Models
# =============================================================================


class TestTaintReportModels:
    """Test taint analysis report models."""

    def test_source_type_enum(self):
        """Test SourceType enum values."""
        assert SourceType.HTTP_PARAM.value == "http_param"
        assert SourceType.HTTP_HEADER.value == "http_header"
        assert SourceType.COOKIE.value == "cookie"
        assert SourceType.FILE_UPLOAD.value == "file_upload"

    def test_sink_type_enum(self):
        """Test SinkType enum values."""
        assert SinkType.SQL_EXEC.value == "sql_exec"
        assert SinkType.COMMAND_EXEC.value == "command_exec"
        assert SinkType.FILE_WRITE.value == "file_write"
        assert SinkType.TEMPLATE_RENDER.value == "template_render"

    def test_sanitizer_type_enum(self):
        """Test SanitizerType enum values."""
        assert SanitizerType.INPUT_VALIDATION.value == "input_validation"
        assert SanitizerType.OUTPUT_ENCODING.value == "output_encoding"
        assert SanitizerType.PARAMETERIZED_QUERY.value == "parameterized_query"

    def test_controllability_enum(self):
        """Test Controllability enum values."""
        assert Controllability.FULL.value == "full"
        assert Controllability.PARTIAL.value == "partial"
        assert Controllability.NONE.value == "none"

    def test_taint_source_creation(self):
        """Test TaintSource model creation."""
        source = TaintSource(
            location="test.py:10",
            source_type=SourceType.HTTP_PARAM,
            variable_name="user_input",
            controllability=Controllability.FULL,
        )
        assert source.location == "test.py:10"
        assert source.source_type == SourceType.HTTP_PARAM
        assert source.variable_name == "user_input"
        assert source.controllability == Controllability.FULL

    def test_taint_source_default_controllability(self):
        """Test TaintSource defaults to FULL controllability."""
        source = TaintSource(
            location="test.py:10",
            source_type=SourceType.HTTP_PARAM,
        )
        assert source.controllability == Controllability.FULL

    def test_taint_source_auth_required(self):
        """Test TaintSource auth_required field."""
        source = TaintSource(
            location="test.py:10",
            source_type=SourceType.HTTP_PARAM,
            auth_required=True,
        )
        assert source.auth_required is True

    def test_taint_source_entry_point(self):
        """Test TaintSource entry_point field."""
        source = TaintSource(
            location="test.py:10",
            source_type=SourceType.HTTP_PARAM,
            entry_point="/api/users/{id}",
        )
        assert source.entry_point == "/api/users/{id}"


# =============================================================================
# Test Noise Layering Integration
# =============================================================================


class TestNoiseLayeringIntegration:
    """Test noise layering integration scenarios."""

    def _create_finding(self, **kwargs) -> Finding:
        """Helper to create a Finding for testing."""
        defaults = {
            "id": "test-001",
            "severity": SeverityLevel.HIGH,
            "title": "Test vulnerability",
            "description": "Test description",
            "location": CodeLocation(file="test.py", line=1),
            "source": "agent",
        }
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_exploitable_finding_no_subtype(self):
        """Test exploitable findings don't need subtypes."""
        finding = self._create_finding(
            report_status="exploitable",
            exploitability="exploitable",
            final_status="confirmed",
        )
        assert finding.report_status == "exploitable"
        assert finding.conditional_subtype is None
        assert finding.informational_subtype is None

    def test_conditional_finding_classification_chain(self):
        """Test conditional finding with full classification chain."""
        finding = self._create_finding(
            report_status="conditional",
            conditional_subtype=ConditionalSubtype.STRONG,
            exploitability="likely",
            confidence=0.85,
            evidence_strength="strong",
            taint_analysis={
                "source": "HTTP_PARAM",
                "sink": "SQL_EXEC",
                "has_sanitizer": False,
                "dataflow_traced": True,
            },
        )
        assert finding.report_status == "conditional"
        assert finding.conditional_subtype == ConditionalSubtype.STRONG
        assert finding.confidence >= 0.8

    def test_informational_not_exploitable_chain(self):
        """Test informational not_exploitable classification chain."""
        finding = self._create_finding(
            report_status="informational",
            informational_subtype=InformationalSubtype.NOT_EXPLOITABLE,
            exploitability="not_exploitable",
            taint_analysis={
                "has_sanitizer": True,
                "sanitizer_type": "parameterized_query",
            },
        )
        assert finding.report_status == "informational"
        assert finding.informational_subtype == InformationalSubtype.NOT_EXPLOITABLE

    def test_environmental_risk_with_conditions(self):
        """Test environmental_risk with specific conditions."""
        finding = self._create_finding(
            report_status="informational",
            informational_subtype=InformationalSubtype.ENVIRONMENTAL_RISK,
            metadata={
                "required_conditions": ["debug_mode_enabled", "admin_access"],
            },
        )
        assert finding.informational_subtype == InformationalSubtype.ENVIRONMENTAL_RISK
        assert "debug_mode_enabled" in finding.metadata.get("required_conditions", [])

    def test_confidence_score_integration(self):
        """Test confidence_score field integration."""
        finding = self._create_finding(
            conditional_subtype=ConditionalSubtype.STRONG,
            confidence_score=85,
            confidence_factors=[
                ("multi_engine_validation", 30),
                ("dataflow_traced", 25),
                ("high_confidence_llm", 30),
            ],
        )
        assert finding.confidence_score == 85
        assert len(finding.confidence_factors) == 3
