import unittest

from app.scanner.crawler import crawl_site
from app.scanner.http_client import ScannerHttpResponse
from app.security.target_url import normalize_target_url


class FakeClient:
    def __init__(self) -> None:
        self.requests: list[str] = []

    def get(self, raw_url: str) -> ScannerHttpResponse:
        self.requests.append(raw_url)
        url = normalize_target_url(raw_url)
        body = "<a href='/one'>one</a><a href='http://example.com/out'>out</a>"
        if url.path == "/one":
            body = "<form action='/login' method='post'><input type='password'></form>"
        return ScannerHttpResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/html"},
            body=body,
            redirect_chain=(),
        )


class CrawlerTests(unittest.TestCase):
    def test_crawler_respects_depth_and_ignores_external_links(self) -> None:
        client = FakeClient()

        result = crawl_site(start_url="http://juice-shop:3000/", client=client, max_depth=1, page_cap=10)

        self.assertEqual(len(result.pages), 2)
        self.assertEqual(result.errors, ())
        self.assertTrue(any(page.forms for page in result.pages))
        self.assertNotIn("http://example.com/out", client.requests)

    def test_crawler_respects_page_cap(self) -> None:
        result = crawl_site(start_url="http://juice-shop:3000/", client=FakeClient(), max_depth=2, page_cap=1)

        self.assertEqual(len(result.pages), 1)


if __name__ == "__main__":
    unittest.main()
