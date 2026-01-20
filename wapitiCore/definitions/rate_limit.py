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
from typing import List

from wapitiCore.definitions.base import FindingBase


class RateLimitFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Missing Rate Limiting"

    @classmethod
    def description(cls) -> str:
        return (
            "Rate limiting is a security mechanism that controls the number of requests a user can make to an API "
            "or web application within a given time period. Without proper rate limiting, applications are vulnerable "
            "to abuse through automated attacks, brute force attempts, denial of service, and resource exhaustion. "
            "The absence of rate limiting headers (such as X-RateLimit-*, RateLimit-*, or Retry-After) indicates "
            "that the endpoint may not be implementing proper request throttling."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Denial of Service",
                "url": "https://owasp.org/www-community/attacks/Denial_of_Service"
            },
            {
                "title": "OWASP API Security: API4:2023 Unrestricted Resource Consumption",
                "url": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
            },
            {
                "title": "MDN: HTTP Headers - RateLimit",
                "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/RateLimit"
            },
            {
                "title": "IETF Draft: RateLimit Header Fields for HTTP",
                "url": "https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers"
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Implement rate limiting on all API endpoints and sensitive operations. "
            "Use standard rate limiting headers to communicate limits to clients:\n"
            "- X-RateLimit-Limit: Maximum number of requests allowed\n"
            "- X-RateLimit-Remaining: Number of requests remaining\n"
            "- X-RateLimit-Reset: Time when the rate limit resets\n"
            "- Retry-After: Time to wait before making another request\n"
            "Consider implementing different rate limits for authenticated vs unauthenticated users, "
            "and apply stricter limits on sensitive operations like login, password reset, and data modification."
        )

    @classmethod
    def short_name(cls) -> str:
        return "Rate Limiting"

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CONF-11"]
