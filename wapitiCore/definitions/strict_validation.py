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


class StrictValidationFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Strict Input Validation Detected"

    @classmethod
    def description(cls) -> str:
        return (
            "This finding indicates that the application implements strict input validation mechanisms. "
            "The application actively rejects malformed inputs, special characters, type mismatches, "
            "or excessively long values. This is a positive security practice that helps prevent "
            "injection attacks, buffer overflows, and other input-based vulnerabilities. "
            "The detection is performed through behavioral analysis by sending various malformed inputs "
            "and observing rejection patterns."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Input Validation Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
            },
            {
                "title": "OWASP: Data Validation",
                "url": "https://owasp.org/www-project-proactive-controls/v3/en/c5-validate-inputs"
            },
            {
                "title": "CWE-20: Improper Input Validation",
                "url": "https://cwe.mitre.org/data/definitions/20.html"
            },
            {
                "title": "OWASP Testing Guide: Testing for Input Validation",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/07-Input_Validation_Testing/"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "The application is already implementing good input validation practices. "
            "To maintain this security posture:\n"
            "- Continue validating all user inputs on the server side\n"
            "- Use allowlists (whitelists) rather than denylists (blacklists) when possible\n"
            "- Validate data type, length, format, and range\n"
            "- Reject invalid input rather than attempting to sanitize it\n"
            "- Provide clear error messages to legitimate users while avoiding information disclosure\n"
            "- Regularly review and update validation rules as application requirements change"
        )

    @classmethod
    def short_name(cls) -> str:
        return "Strict Validation"

    @classmethod
    def type(cls) -> str:
        return "additional"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INPV-01"]
