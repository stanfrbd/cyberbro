import logging

import pytest
import responses
from responses import matchers

from engines.ioc_one import IOCOneHTMLEngine, IOCOnePDFEngine
from models.observable import ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets():
    return Secrets()


@pytest.fixture
def observable_value():
    return "8.8.8.8"


@pytest.fixture
def special_observable():
    return "test@example.com"


@pytest.fixture
def html_success_5_cards():
    """Mock HTML response with 5 complete cards."""
    return """
    <html>
    <body>
        <div class="card box-shadow my-1">
            <div class="card-header">Header 1</div>
            <h5 class="card-title">Title 1</h5>
            <a class="btn border btn-primary m-1" target="_blank" href="https://source1.com">Link</a>
        </div>
        <div class="card box-shadow my-1">
            <div class="card-header">Header 2</div>
            <h5 class="card-title">Title 2</h5>
            <a class="btn border btn-primary m-1" target="_blank" href="https://source2.com">Link</a>
        </div>
        <div class="card box-shadow my-1">
            <div class="card-header">Header 3</div>
            <h5 class="card-title">Title 3</h5>
            <a class="btn border btn-primary m-1" target="_blank" href="https://source3.com">Link</a>
        </div>
        <div class="card box-shadow my-1">
            <div class="card-header">Header 4</div>
            <h5 class="card-title">Title 4</h5>
            <a class="btn border btn-primary m-1" target="_blank" href="https://source4.com">Link</a>
        </div>
        <div class="card box-shadow my-1">
            <div class="card-header">Header 5</div>
            <h5 class="card-title">Title 5</h5>
            <a class="btn border btn-primary m-1" target="_blank" href="https://source5.com">Link</a>
        </div>
    </body>
    </html>
    """


@pytest.fixture
def html_success_1_card():
    """Mock HTML response with 1 complete card."""
    return """
    <html>
    <body>
        <div class="card box-shadow my-1">
            <div class="card-header">Header Only</div>
            <h5 class="card-title">Title Only</h5>
            <a class="btn border btn-primary m-1" target="_blank" href="https://single-source.com">Link</a>
        </div>
    </body>
    </html>
    """


@pytest.fixture
def html_empty_results():
    """Mock HTML response with valid structure but no cards."""
    return """
    <html>
    <body>
        <div class="container">
            <p>No results found</p>
        </div>
    </body>
    </html>
    """


@pytest.fixture
def html_9_cards():
    """Mock HTML response with 9 cards (tests truncation to 5)."""
    cards = ""
    for i in range(1, 10):
        cards += f"""
        <div class="card box-shadow my-1">
            <div class="card-header">Header {i}</div>
            <h5 class="card-title">Title {i}</h5>
            <a class="btn border btn-primary m-1" target="_blank" href="https://source{i}.com">Link</a>
        </div>
        """
    return f"<html><body>{cards}</body></html>"


@pytest.fixture
def html_missing_card_header():
    """Mock HTML with card missing header div."""
    return """
    <html>
    <body>
        <div class="card box-shadow my-1">
            <h5 class="card-title">Title Without Header</h5>
            <a class="btn border btn-primary m-1" target="_blank" href="https://source.com">Link</a>
        </div>
    </body>
    </html>
    """


@pytest.fixture
def html_missing_card_title():
    """Mock HTML with card missing h5 title."""
    return """
    <html>
    <body>
        <div class="card box-shadow my-1">
            <div class="card-header">Header Without Title</div>
            <a class="btn border btn-primary m-1" target="_blank" href="https://source.com">Link</a>
        </div>
    </body>
    </html>
    """


@pytest.fixture
def html_missing_source_link():
    """Mock HTML with card missing source link."""
    return """
    <html>
    <body>
        <div class="card box-shadow my-1">
            <div class="card-header">Header</div>
            <h5 class="card-title">Title</h5>
        </div>
    </body>
    </html>
    """


@pytest.fixture
def html_no_cards():
    """Mock HTML with no div.card elements."""
    return """
    <html>
    <body>
        <div class="other-container">
            <h1>Some other content</h1>
        </div>
    </body>
    </html>
    """


@pytest.fixture
def html_empty_body():
    """Mock HTML with empty body."""
    return "<html><body></body></html>"


@pytest.fixture
def html_whitespace_content():
    """Mock HTML with whitespace-only content."""
    return """
    <html>
    <body>
        <div class="card box-shadow my-1">
            <div class="card-header">   </div>
            <h5 class="card-title">   </h5>
            <a class="btn border btn-primary m-1" target="_blank" href="https://source.com">Link</a>
        </div>
    </body>
    </html>
    """


# ============================================================================
# High Priority: Critical Paths & Core Functionality
# ============================================================================


class TestIOCOneHTMLEngineSuccess:
    """Success path tests for IOCOneHTMLEngine."""

    @responses.activate
    def test_analyze_html_success_5_cards(self, secrets, observable_value, html_success_5_cards):
        """Test successful analysis with 5 cards returns correct structure."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search?search={observable_value}"
        responses.add(responses.GET, url, body=html_success_5_cards, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert "results" in result
        assert "link" in result
        assert "count" in result
        assert len(result["results"]) == 5
        assert result["count"] == 5

    @responses.activate
    def test_analyze_html_success_1_card(self, secrets, observable_value, html_success_1_card):
        """Test successful analysis with 1 card."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search?search={observable_value}"
        responses.add(responses.GET, url, body=html_success_1_card, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert len(result["results"]) == 1
        assert result["count"] == 1

    @responses.activate
    def test_analyze_html_empty_results(self, secrets, observable_value, html_empty_results):
        """Test analysis with no cards returns empty list."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search?search={observable_value}"
        responses.add(responses.GET, url, body=html_empty_results, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert result["results"] == []
        assert result["count"] == 0

    @responses.activate
    def test_analyze_html_9_cards_truncates_to_5(self, secrets, observable_value, html_9_cards):
        """Test that 9 cards are truncated to maximum of 5."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search?search={observable_value}"
        responses.add(responses.GET, url, body=html_9_cards, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert len(result["results"]) == 5
        assert result["count"] == 5

    @responses.activate
    def test_analyze_html_card_structure(self, secrets, observable_value, html_success_1_card):
        """Test each card has header, title, and source fields."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search?search={observable_value}"
        responses.add(responses.GET, url, body=html_success_1_card, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        card = result["results"][0]
        assert "header" in card
        assert "title" in card
        assert "source" in card
        assert card["header"] == "Header Only"
        assert card["title"] == "Title Only"
        assert card["source"] == "https://single-source.com"

    @responses.activate
    def test_analyze_html_link_field_contains_url(
        self, secrets, observable_value, html_success_1_card
    ):
        """Test link field contains constructed search URL."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        expected_url = f"https://ioc.one/auth/deep_search?search={observable_value}"
        responses.add(responses.GET, expected_url, body=html_success_1_card, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result["link"] == expected_url


class TestIOCOnePDFEngineSuccess:
    """Success path tests for IOCOnePDFEngine."""

    @responses.activate
    def test_analyze_pdf_success_5_cards(self, secrets, observable_value, html_success_5_cards):
        """Test successful analysis with 5 cards returns correct structure."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)
        # PDF engine uses different CSS class for source link (mx-1 instead of m-1)
        html = html_success_5_cards.replace("btn-primary m-1", "btn-primary mx-1")
        url = f"https://ioc.one/auth/deep_search/pdf?search={observable_value}"
        responses.add(responses.GET, url, body=html, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert len(result["results"]) == 5
        assert result["count"] == 5

    @responses.activate
    def test_analyze_pdf_success_1_card(self, secrets, observable_value, html_success_1_card):
        """Test successful analysis with 1 card."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)
        html = html_success_1_card.replace("btn-primary m-1", "btn-primary mx-1")
        url = f"https://ioc.one/auth/deep_search/pdf?search={observable_value}"
        responses.add(responses.GET, url, body=html, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert len(result["results"]) == 1
        assert result["count"] == 1

    @responses.activate
    def test_analyze_pdf_empty_results(self, secrets, observable_value, html_empty_results):
        """Test analysis with no cards returns empty list."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search/pdf?search={observable_value}"
        responses.add(responses.GET, url, body=html_empty_results, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert result["results"] == []
        assert result["count"] == 0

    @responses.activate
    def test_analyze_pdf_9_cards_truncates_to_5(self, secrets, observable_value, html_9_cards):
        """Test that 9 cards are truncated to maximum of 5."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)
        html = html_9_cards.replace("btn-primary m-1", "btn-primary mx-1")
        url = f"https://ioc.one/auth/deep_search/pdf?search={observable_value}"
        responses.add(responses.GET, url, body=html, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert len(result["results"]) == 5
        assert result["count"] == 5


class TestObservableTypeRouting:
    """Test observable type URL construction for both engines."""

    @pytest.mark.parametrize(
        "engine_class,endpoint,observable_type",
        [
            (IOCOneHTMLEngine, "https://ioc.one/auth/deep_search", ObservableType.CHROME_EXTENSION),
            (IOCOneHTMLEngine, "https://ioc.one/auth/deep_search", ObservableType.FQDN),
            (IOCOneHTMLEngine, "https://ioc.one/auth/deep_search", ObservableType.IPV4),
            (IOCOneHTMLEngine, "https://ioc.one/auth/deep_search", ObservableType.IPV6),
            (IOCOneHTMLEngine, "https://ioc.one/auth/deep_search", ObservableType.MD5),
            (IOCOneHTMLEngine, "https://ioc.one/auth/deep_search", ObservableType.SHA1),
            (IOCOneHTMLEngine, "https://ioc.one/auth/deep_search", ObservableType.SHA256),
            (IOCOneHTMLEngine, "https://ioc.one/auth/deep_search", ObservableType.URL),
            (IOCOnePDFEngine, "https://ioc.one/auth/deep_search/pdf", ObservableType.IPV4),
            (IOCOnePDFEngine, "https://ioc.one/auth/deep_search/pdf", ObservableType.SHA256),
        ],
    )
    @responses.activate
    def test_analyze_url_construction(
        self, secrets, observable_value, html_empty_results, engine_class, endpoint, observable_type
    ):
        """Test correct URL is constructed for all observable types."""
        engine = engine_class(secrets, proxies={}, ssl_verify=True)
        url = f"{endpoint}?search={observable_value}"
        responses.add(responses.GET, url, body=html_empty_results, status=200)

        engine.analyze(observable_value, observable_type)

        assert len(responses.calls) == 1
        assert responses.calls[0].request.url == url


class TestExportRow:
    """Test export row formatting for both engines."""

    def test_create_export_row_html_success(self, secrets):
        """Test IOCOneHTMLEngine export row with successful result."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        analysis_result = {
            "results": [{"header": "Test", "title": "Test", "source": "http://test.com"}],
            "link": "http://test.com",
            "count": 1,
        }

        export_row = engine.create_export_row(analysis_result)

        assert export_row == {"ioc_one_html_count": 1}

    def test_create_export_row_html_none(self, secrets):
        """Test IOCOneHTMLEngine export row with None result."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)

        export_row = engine.create_export_row(None)

        assert export_row == {"ioc_one_html_count": None}

    def test_create_export_row_pdf_success(self, secrets):
        """Test IOCOnePDFEngine export row with successful result."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)
        analysis_result = {
            "results": [{"header": "Test", "title": "Test", "source": "http://test.com"}],
            "link": "http://test.com",
            "count": 1,
        }

        export_row = engine.create_export_row(analysis_result)

        assert export_row == {"ioc_one_pdf_count": 1}

    def test_create_export_row_pdf_none(self, secrets):
        """Test IOCOnePDFEngine export row with None result."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)

        export_row = engine.create_export_row(None)

        assert export_row == {"ioc_one_pdf_count": None}


# ============================================================================
# Medium Priority: Error Handling & Robustness
# ============================================================================


class TestErrorHandling:
    """Test error handling for HTTP and network failures."""

    @pytest.mark.parametrize(
        "engine_class,endpoint,status_code",
        [
            (IOCOneHTMLEngine, "https://ioc.one/auth/deep_search", 400),
            (IOCOneHTMLEngine, "https://ioc.one/auth/deep_search", 401),
            (IOCOneHTMLEngine, "https://ioc.one/auth/deep_search", 403),
            (IOCOneHTMLEngine, "https://ioc.one/auth/deep_search", 500),
            (IOCOnePDFEngine, "https://ioc.one/auth/deep_search/pdf", 404),
            (IOCOnePDFEngine, "https://ioc.one/auth/deep_search/pdf", 500),
        ],
    )
    @responses.activate
    def test_analyze_http_error_returns_none(
        self, secrets, observable_value, engine_class, endpoint, status_code
    ):
        """Test HTTP errors return None."""
        engine = engine_class(secrets, proxies={}, ssl_verify=True)
        url = f"{endpoint}?search={observable_value}"
        responses.add(responses.GET, url, status=status_code)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is None

    @responses.activate
    def test_analyze_html_timeout_error(self, secrets, observable_value):
        """Test timeout exception returns None."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search?search={observable_value}"
        responses.add(responses.GET, url, body=TimeoutError("Connection timeout"))

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is None

    @responses.activate
    def test_analyze_pdf_connection_error(self, secrets, observable_value):
        """Test connection error exception returns None."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search/pdf?search={observable_value}"
        responses.add(responses.GET, url, body=ConnectionError("Failed to connect"))

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is None


class TestMalformedHTML:
    """Test handling of malformed or incomplete HTML responses."""

    @responses.activate
    def test_analyze_html_missing_card_header(
        self, secrets, observable_value, html_missing_card_header
    ):
        """Test card without header div causes analysis to fail."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search?search={observable_value}"
        responses.add(responses.GET, url, body=html_missing_card_header, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is None

    @responses.activate
    def test_analyze_html_missing_card_title(
        self, secrets, observable_value, html_missing_card_title
    ):
        """Test card without title h5 causes analysis to fail."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search?search={observable_value}"
        responses.add(responses.GET, url, body=html_missing_card_title, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is None

    @responses.activate
    def test_analyze_pdf_missing_source_link(
        self, secrets, observable_value, html_missing_source_link
    ):
        """Test card without source link causes analysis to fail."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)
        html = html_missing_source_link.replace("btn-primary m-1", "btn-primary mx-1")
        url = f"https://ioc.one/auth/deep_search/pdf?search={observable_value}"
        responses.add(responses.GET, url, body=html, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is None

    @responses.activate
    def test_analyze_html_no_cards_returns_empty(self, secrets, observable_value, html_no_cards):
        """Test HTML with no card elements returns empty results."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        url = "https://ioc.one/auth/deep_search"
        params: dict = {"search": observable_value}
        responses.add(
            responses.GET,
            url=url,
            match=[matchers.query_param_matcher(params)],
            body=html_no_cards,
            status=200,
        )

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert result["results"] == []
        assert result["count"] == 0

    @responses.activate
    def test_analyze_html_empty_body_returns_empty(
        self, secrets, observable_value, html_empty_body
    ):
        """Test empty HTML body returns empty results."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search?search={observable_value}"
        responses.add(responses.GET, url, body=html_empty_body, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert result["results"] == []
        assert result["count"] == 0


class TestCSSClassDifference:
    """Test the CSS class difference between HTML and PDF engines."""

    @responses.activate
    def test_analyze_html_uses_correct_css_class(self, secrets, observable_value):
        """Test IOCOneHTMLEngine uses correct CSS class (m-1) for source link."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search?search={observable_value}"
        # HTML with correct m-1 class should work
        html = """
        <html><body>
            <div class="card box-shadow my-1">
                <div class="card-header">Header</div>
                <h5 class="card-title">Title</h5>
                <a class="btn border btn-primary m-1" target="_blank" href="https://test.com">Link</a>
            </div>
        </body></html>
        """
        responses.add(responses.GET, url, body=html, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert len(result["results"]) == 1

    @responses.activate
    def test_analyze_pdf_uses_correct_css_class(self, secrets, observable_value):
        """Test IOCOnePDFEngine uses correct CSS class (mx-1) for source link."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search/pdf?search={observable_value}"
        # PDF with correct mx-1 class should work
        html = """
        <html><body>
            <div class="card box-shadow my-1">
                <div class="card-header">Header</div>
                <h5 class="card-title">Title</h5>
                <a class="btn border btn-primary mx-1" target="_blank" href="https://test.com">Link</a>
            </div>
        </body></html>
        """
        responses.add(responses.GET, url, body=html, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert len(result["results"]) == 1


# ============================================================================
# Low Priority: Edge Cases & Special Scenarios
# ============================================================================


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    @responses.activate
    def test_analyze_html_special_chars_in_observable(self, secrets, special_observable):
        """Test observable with special characters in URL."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search?search={special_observable}"
        responses.add(responses.GET, url, body="<html><body></body></html>", status=200)

        result = engine.analyze(special_observable, ObservableType.CHROME_EXTENSION)

        assert result is not None
        assert result["link"] == url

    @responses.activate
    def test_analyze_pdf_special_chars_in_values(self, secrets, observable_value):
        """Test special characters in HTML values are preserved."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)
        url = f"https://ioc.one/auth/deep_search/pdf?search={observable_value}"
        html = """
        <html><body>
            <div class="card box-shadow my-1">
                <div class="card-header">Header & Special < Chars ></div>
                <h5 class="card-title">Title "Quoted"</h5>
                <a class="btn border btn-primary mx-1" target="_blank" href="https://test.com">Link</a>
            </div>
        </body></html>
        """
        responses.add(responses.GET, url, body=html, status=200)

        result = engine.analyze(observable_value, ObservableType.IPV4)

        assert result is not None
        assert len(result["results"]) == 1

    @responses.activate
    def test_analyze_html_very_long_observable(self, secrets):
        """Test very long observable value in URL."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        long_value = "a" * 500
        url = f"https://ioc.one/auth/deep_search?search={long_value}"
        responses.add(responses.GET, url, body="<html><body></body></html>", status=200)

        result = engine.analyze(long_value, ObservableType.URL)

        assert result is not None

    def test_create_export_row_html_empty_result_dict(self, secrets):
        """Test create_export_row with empty result dict."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        analysis_result = {}

        export_row = engine.create_export_row(analysis_result)

        assert export_row == {"ioc_one_html_count": None}

    def test_create_export_row_pdf_empty_result_dict(self, secrets):
        """Test create_export_row with empty result dict."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)
        analysis_result = {}

        export_row = engine.create_export_row(analysis_result)

        assert export_row == {"ioc_one_pdf_count": None}


class TestEngineProperties:
    """Test engine properties and metadata."""

    def test_html_engine_name(self, secrets):
        """Test IOCOneHTMLEngine name property."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)

        assert engine.name == "ioc_one_html"

    def test_pdf_engine_name(self, secrets):
        """Test IOCOnePDFEngine name property."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)

        assert engine.name == "ioc_one_pdf"

    def test_html_engine_supported_types(self, secrets):
        """Test IOCOneHTMLEngine supported_types property."""
        engine = IOCOneHTMLEngine(secrets, proxies={}, ssl_verify=True)
        expected_types = ObservableType(
            ObservableType.CHROME_EXTENSION
            | ObservableType.FQDN
            | ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.URL
        )

        assert engine.supported_types is expected_types

    def test_pdf_engine_supported_types(self, secrets):
        """Test IOCOnePDFEngine supported_types property."""
        engine = IOCOnePDFEngine(secrets, proxies={}, ssl_verify=True)
        expected_types = ObservableType(
            ObservableType.CHROME_EXTENSION
            | ObservableType.FQDN
            | ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.URL
        )

        assert engine.supported_types == expected_types
