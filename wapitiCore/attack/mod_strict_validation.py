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

import time
import re
import json
import asyncio
from typing import Optional, Iterator, List, Tuple, Dict, Any, Union
from dataclasses import dataclass, field

from wapitiCore.attack.attack import Attack, Mutator, ParameterSituation, Parameter
from wapitiCore.net import Request, Response
from wapitiCore.model import PayloadInfo
from wapitiCore.main.log import log_blue, log_green, log_red, log_orange, log_verbose
from wapitiCore.definitions import FindingBase
from wapitiCore.language.vulnerability import HIGH_LEVEL, MEDIUM_LEVEL, LOW_LEVEL, INFO_LEVEL

from wapitiCore.definitions.strict_validation import StrictValidationFinding


# --- Constants & Config ---
SYMBOLS = list("~!@$^*()-=_/,.?<>:;'\"[]{}|%+") # Removed duplicates if any, standard set
SLEEP_TIME = 1.0

@dataclass
class ValidationResult:
    parameter: str
    location: str
    detected_type: str
    symbol_rejection_ratio: Optional[float] = None
    negative_number_rejected: Optional[bool] = None
    type_mismatch_rejected: Optional[bool] = None
    length_rejected: Optional[bool] = None
    classification: str = "NONE"
    confidence: str = "low"
    evidence: List[str] = field(default_factory=list)

class ModuleStrictValidation(Attack):
    """Detects strict input validation mechanisms using behavioral analysis."""
    name = "strict_validation"
    
    # Priority can be adjusted. existing modules are usually around 5.
    PRIORITY = 6
    
    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        super().__init__(crawler, persister, attack_options, crawler_configuration)
        self.validation_depth = int(attack_options.get("validation_depth", 1))
        # Support user override for sleep if needed (though requirement says mandatory 1s)
        self.sleep_seconds = float(attack_options.get("sleep_seconds", SLEEP_TIME))
        
    # --- Helper: Safe Request Sender ---
    async def safe_send(self, request: Request) -> Optional[Response]:
        """
        Sends a request and enforces the mandatory sleep AFTER the request.
        Ignores status codes (doesn't raise on 4xx/5xx usually, but we catch exceptions).
        """
        response = None
        try:
            # We use crawler.async_send. Wapiti might timeout.
            response = await self.crawler.async_send(request)
        except Exception as e:
            log_verbose(f"[StrictValidation] Request failed: {e}")
            # Network error is ambiguous, treated as potential rejection or just error.
            # For this module, NULL response usually means we can't analyze.
            response = None
        finally:
            # MANDATORY SLEEP
            await asyncio.sleep(self.sleep_seconds)
            
        return response

    # --- Helper: Signature Extraction ---
    def get_success_signature(self, response: Response) -> Dict[str, Any]:
        """
        Extracts a signature from the response to determine 'success'.
        Ignores HTTP status code.
        Focuses on:
        - Structure (simplified hash of tag names/keys)
        - Specific success keywords (success=true, status=ok, etc.)
        - Content length (approximate)
        """
        if not response:
            return {}

        content = response.content
        
        # 1. Keyword check (naive but effective for many APIs)
        success_keywords = ["success", "ok", "confirm", "done", "created"]
        # Basic check in first 500 chars or json keys
        
        signature = {
            "len": len(content),
            "hash": hash(content), # simplified content hash
            # "structure": ... (would be better with HTML parser or JSON keys)
        }
        
        # If JSON, capture keys
        try:
            if response.is_json:
                data = json.loads(content)
                signature["json_keys"] = sorted(list(data.keys())) if isinstance(data, dict) else "list"
                # Check for common success fields
                if isinstance(data, dict):
                    for k in ["success", "status", "code", "ok"]:
                        if k in data:
                            signature[f"field_{k}"] = data[k]
        except:
            pass
            
        return signature

    def is_rejected(self, baseline_sig: Dict[str, Any], attempt_response: Optional[Response]) -> bool:
        """
        Determines if the attempt was rejected based on signature mismatch.
        """
        if not attempt_response:
            return True # No response often means blocked/dropped
            
        attempt_sig = self.get_success_signature(attempt_response)
        
        # Compare signatures
        # 1. If JSON keys changed significantly -> Rejected (likely error object)
        if "json_keys" in baseline_sig and "json_keys" in attempt_sig:
            if baseline_sig["json_keys"] != attempt_sig["json_keys"]:
                return True
                
        # 2. If 'success' field changed (e.g. True -> False) -> Rejected
        for k in baseline_sig:
            if k.startswith("field_"):
                if k not in attempt_sig or attempt_sig[k] != baseline_sig[k]:
                    return True

        # 3. Fallback: Content hash mismatch (for exact stability)
        # If the page is dynamic, this is flaky. We try to be lenient.
        # Strict validation usually returns an error page which is VERY different.
        
        # Simple heuristic: If length differs by > 20% and we didn't match specific fields, assume difference.
        if abs(baseline_sig["len"] - attempt_sig["len"]) / (baseline_sig["len"] + 1) > 0.2:
             return True
             
        return False

    # --- Heuristic: Type Inference ---
    def infer_type(self, value: str) -> str:
        if re.match(r'^-?\d+(\.\d+)?$', value):
            return "number"
        if value.lower() in ['true', 'false', '0', '1']:
            # 0/1 are ambiguous, but often bool. Treated as number checks usually cover it.
            # Let's verify context? For now simple inference.
            return "boolean"
        if value.strip().startswith('{') or value.strip().startswith('['):
            try:
                json.loads(value)
                return "object"
            except:
                pass
        return "string"

    # --- Main Attack Logic ---
    async def attack(self, request: Request, response: Optional[Response] = None):
        # 1. Baseline
        # We need a fresh baseline request to be sure of stability
        # But we can use the 'response' passed if it corresponds to the request?
        # Typically 'response' is the one from the crawler found during exploration.
        
        baseline_resp = await self.safe_send(request)
        if not baseline_resp:
            return # specific error handling?

        baseline_sig = self.get_success_signature(baseline_resp)
        
        # We define a generator payload that yields ONE generic payload just to trigger the mutator loop
        # and then we hijack the loop logic to perform our specific tests per parameter.
        # Actually, Mutator iterates over parameters. We want to test each parameter.
        
        # Wapiti's Mutator is designed to yield (request, param, payload) tuples.
        # We can implement a custom logic here:
        
        # Iterate over all parameters in the request
        all_params = request.get_params + request.post_params # + file_params?
        # Note: request.get_params is a list of [name, value]
        
        params_to_test = []
        if self.do_get:
            params_to_test.extend([(p[0], p[1], "GET") for p in request.get_params])
        if self.do_post:
            params_to_test.extend([(p[0], p[1], "POST") for p in request.post_params])

        # Filter duplicates or annoying params
        # (Naive, should use Mutator helpers if possible, but manual is fine for custom logic)
        
        for name, value, method_type in params_to_test:
            if not name: continue
            
            # --- Type Inference ---
            detected_type = self.infer_type(value)
            
            # --- Tests ---
            # We create specific requests for this parameter
            
            classification = "NONE"
            evidence = []
            
            # 1. Type Mismatch (All)
            # 2. Length (All)
            # 3. Symbol (String)
            # 4. Number (Number)
            
            # --- Type Mismatch Test ---
            # Send incompatible type
            mismatch_val = "wrong_type_123" if detected_type == "number" else "0"
            if detected_type == "object": mismatch_val = "not_an_object"
            
            # Construct Request
            # We need a helper to clone request and replace param.
            # Wapiti Request object is immutable-ish?, we construct new one.
            
            # Helper to create modified request
            def create_req(new_val):
                # This is tedious to do manually for GET/POST/JSON etc.
                # Let's try to utilize Mutator logic or just do simple replacement if simple.
                # For robustness, we will try to use the Mutator with a single payload.
                pass 
                
            # Actually, reusing Mutator is cleaner.
            
        # RE-STRATEGY: Use Mutator with specific payloads?
        # The problem is Mutator mixes everything.
        # Easier: Use Mutator to identify parameters, but execute CUSTOM logic inside the loop.
        
        # We define a dummy payload generator that yields nothing, just so we can access parameters?
        # No, Mutator yields modified requests.
        
        # Better: iterate parameters manually using the lists, as we did above.
        # We just need a robust way to create the request with modified parameter.
        
        # Let's assign 'params_to_test' and process them.
        
        processed_params = set()
        
        # Utilizing Mutator to handle parameter replacement correctly (including JSON, Multipart)
        # We create a mutator that yields parameters.
        
        def dummy_payload_gen(req, param):
            yield PayloadInfo(payload="__CHECK__")

        mutator = Mutator(methods="GP" if self.do_post else "G") # simplify
        
        for mutated_req, param, info in mutator.mutate(request, dummy_payload_gen):
            if param.name in processed_params:
                continue
            processed_params.add(param.name)
            
            # original value?
            # 'mutated_req' has the param replaced by '__CHECK__'
            # We can't easily get the original value from here without parsing 'request' again 
            # or looking at 'request' finding param.name.
            # But 'param' object usually just has name.
            
            # We will use 'request' to find the value of 'param.name'
            # This handles JSON paths too if they are flattened? Wapiti handles flattened names.
            
            # Find original value
            original_value = ""
            # This is tricky with JSON/nested.
            # Simplified: scan standard params.
            found = False
            for p_list in [request.get_params, request.post_params]:
                 for p_name, p_val in p_list:
                     if p_name == param.name:
                         original_value = p_val
                         found = True
                         break
                 if found: break
            
            if not found and request.is_json:
                # Handle JSON parameter lookup if possible, or skip complex path lookups for now
                continue

            detected_type = self.infer_type(original_value)
            print(f"[StrictValidation] Parameter '{param.name}' detected as '{detected_type}' (Value: '{original_value}')", flush=True)
            
            # Initialize results
            res_symbol_ratio = 0.0
            res_neg_rej = False
            res_mismatch_rej = False
            res_len_rej = False
            
            # --- Symbol Test (Strings & Numbers) ---
            # User requested to check symbols first, even for numbers.
            if detected_type in ["string", "number"]:
                print(f"[StrictValidation] Running Symbol Test on '{param.name}'...", flush=True)
                rejected_count = 0
                total_tested = 0
                for sym in SYMBOLS:
                    if sym in original_value: continue # Skip existing
                    
                    val_with_sym = original_value + sym
                    # CREATE REQUEST
                    req_test = self._create_test_request(request, param.name, val_with_sym)
                    if not req_test: continue
                    
                    resp_test = await self.safe_send(req_test)
                    is_rej = self.is_rejected(baseline_sig, resp_test)
                    # print(f"  [>] Symbol '{sym}' -> Rejected: {is_rej}", flush=True) # Optional very verbose
                    if is_rej:
                        rejected_count += 1
                    total_tested += 1
                
                if total_tested > 0:
                    res_symbol_ratio = rejected_count / total_tested
                    print(f"[StrictValidation] Symbol Ratio: {res_symbol_ratio:.2f} ({rejected_count}/{total_tested})", flush=True)
                    
            # --- Number Test ---
            # if detected_type == "number":
                # print(f"[StrictValidation] Running Numeric Test on '{param.name}'...", flush=True)
                # # Negative
                # try:
                #     num_val = float(original_value)
                #     neg_val = str(-abs(num_val) if num_val != 0 else -1)
                #     
                #     req_neg = self._create_test_request(request, param.name, neg_val)
                #     resp_neg = await self.safe_send(req_neg)
                #     res_neg_rej = self.is_rejected(baseline_sig, resp_neg)
                #     print(f"[StrictValidation] Negative Value '{neg_val}' Rejected: {res_neg_rej}", flush=True)
                # except:
                #     pass

            # --- Type Mismatch & Length (All) ---
            print(f"[StrictValidation] Running Mismatch/Length checks...", flush=True)
            # Mismatch
            bad_val = "not_number" if detected_type == "number" else "0" # simplistic
            if detected_type == "string": bad_val = '{"obj":1}' # try inject json syntax?
            
            req_type = self._create_test_request(request, param.name, bad_val)
            resp_type = await self.safe_send(req_type)
            if self.is_rejected(baseline_sig, resp_type):
                res_mismatch_rej = True
                
            # Length
            long_val = original_value + ("A" * 4096)
            req_len = self._create_test_request(request, param.name, long_val)
            resp_len = await self.safe_send(req_len)
            if self.is_rejected(baseline_sig, resp_len):
                res_len_rej = True
                
            # --- Classification ---
            final_status = "NONE"
            if detected_type == "string":
                if res_symbol_ratio >= 0.85 and res_mismatch_rej and res_len_rej:
                    final_status = "STRICT"
                elif res_symbol_ratio >= 0.30:
                    final_status = "WEAK"
            elif detected_type == "number":
                if res_neg_rej and res_mismatch_rej:
                    final_status = "STRICT"
                elif res_mismatch_rej: # but neg accepted
                    final_status = "WEAK"
                    
            if final_status != "NONE":
                 # REPORT
                 msg = (
                     f"Detected {final_status} input validation on parameter '{param.name}' ({detected_type}).\n"
                     f"Symbol Rejection: {res_symbol_ratio:.2f}\n"
                     f"Type Mismatch Rejected: {res_mismatch_rej}\n"
                     f"Length Rejected: {res_len_rej}"
                 )
                 
                 # JSON extra data
                 extras = {
                     "parameter": param.name,
                     "detected_type": detected_type,
                     "classification": final_status,
                     "metrics": {
                        "symbol_ratio": res_symbol_ratio,
                        "negative_rejected": res_neg_rej,
                        "type_rejected": res_mismatch_rej
                     }
                 }

                 await self.add_info(
                     finding_class=StrictValidationFinding,
                     request=request, # Blame the original request
                     parameter=param.name,
                     info=msg,
                     response=baseline_resp
                 )
                 # Add extra data to finding if possible? Wapiti findings usually just have 'info'.
                 # We put JSON in info or separate logging.
                 
                 log_blue(f"[StrictValidation] Found {final_status} for {param.name}")

    def _create_test_request(self, original: Request, param_name: str, new_value: str) -> Optional[Request]:
        # Simple cloning and replacement for flat parameters.
        # This ignores complex JSON paths for brevity, could be improved.
        # We rely on simple list copy.
        
        # Deep copy params
        get_p = [list(x) for x in original.get_params]
        post_p = [list(x) for x in original.post_params]
        
        replaced = False
        for p in get_p:
            if p[0] == param_name:
                p[1] = new_value
                replaced = True
        
        if not replaced:
            for p in post_p:
                if p[0] == param_name:
                    p[1] = new_value
                    replaced = True
                    
        if not replaced:
            return None # Couldn't find param (maybe it was in JSON body handling which we skipped for simple implementation)
            
        return Request(
            path=original.path,
            method=original.method,
            get_params=get_p,
            post_params=post_p,
            file_params=original.file_params, # ignore mostly
            referer=original.referer,
            link_depth=original.link_depth,
            enctype=original.enctype
        )

