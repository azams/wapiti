#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2021-2023 Nicolas Surribas
# Copyright (C) 2021-2024 Cyberwatch
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
from typing import Generator, Any

from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response
from wapitiCore.definitions.rate_limit import RateLimitFinding
from wapitiCore.main.log import log_blue, log_red
from wapitiCore.language.vulnerability import INFO_LEVEL


INFO_RATE_LIMIT = "Endpoint '{0}' is missing rate limiting headers"


class ModuleRateLimit:
    """
    Passively detects missing rate limiting headers in HTTP responses.
    """

    name = "rate_limit"

    def __init__(self):
        # Track reported URLs to avoid duplicate findings
        self._reported_urls: set[str] = set()

    def analyze(
        self, request: Request, response: Response
    ) -> Generator[VulnerabilityInstance, Any, None]:
        """
        Analyzes an HTTP response for rate limiting headers.
        """
        # Avoid duplicate reports for the same URL
        if request.url in self._reported_urls:
            return

        # Check for rate limiting headers
        found_ratelimit_header = False
        headers_found = []

        # Common Rate Limit Headers:
        # - X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
        # - Retry-After
        # - RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset (IETF Draft Standard)

        for h_name in response.headers:
            h = h_name.lower()
            if h == "retry-after":
                found_ratelimit_header = True
                headers_found.append(h_name)
            elif h.startswith("x-ratelimit") or h.startswith("ratelimit"):
                found_ratelimit_header = True
                headers_found.append(h_name)

        if found_ratelimit_header:
            log_blue(f"[RateLimit] Found rate limit headers on {request.url}: {headers_found}")
        else:
            # No rate limiting headers found - report as finding
            self._reported_urls.add(request.url)
            log_red(f"[RateLimit] Missing rate limit headers on {request.url}")

            yield VulnerabilityInstance(
                finding_class=RateLimitFinding,
                request=request,
                response=response,
                info=INFO_RATE_LIMIT.format(request.url),
                severity=INFO_LEVEL,
            )
