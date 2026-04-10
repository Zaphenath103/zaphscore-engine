from __future__ import annotations
    import logging, re
    from pathlib import Path
    from typing import Any, Optional
    from pydantic import BaseModel, Field, field_validator

    logger = logging.getLogger(__name__)
    VALID_LANGUAGES = frozenset(["python","javascript","typescript","java","go","ruby","php",
        "csharp","c","cpp","kotlin","swift","scala","rust","bash","yaml","json",
        "terraform","dockerfile","generic"])
    VALID_SEVERITIES = frozenset(["ERROR","WARNING","INFO"])

    class CustomRule(BaseModel):
        id: str = Field(..., min_length=1, max_length=200)
        pattern: Optional[str] = None
        message: str = Field(..., min_length=1, max_length=2000)
        severity: str = "WARNING"
        languages: list[str] = Field(...)
        metadata: dict[str, Any] = Field(default_factory=dict)
        pattern_either: Optional[list[str]] = None
        pattern_not: Optional[str] = None
        fix: Optional[str] = None

        @field_validator("severity")
        @classmethod
        def validate_severity(cls, v):
            vu = v.upper()
            if vu not in VALID_SEVERITIES:
                raise ValueError(f"severity must be one of {VALID_SEVERITIES}")
            return vu

        @field_validator("languages")
        @classmethod
        def validate_languages(cls, v):
            norm = [x.lower() for x in v]
            bad = [x for x in norm if x not in VALID_LANGUAGES]
            if bad: raise ValueError(f"Invalid languages: {bad}")
            return norm

        @field_validator("id")
        @classmethod
        def validate_id(cls, v):
            if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$", v):
                raise ValueError("Rule id must be alphanumeric.")
            return v

    class CustomRuleValidationError(Exception):
        pass

    def validate_custom_rule(rule_dict):
        req = {"id","message","languages"}
        missing = req - set(rule_dict.keys())
        if missing: raise CustomRuleValidationError(f"Missing: {missing}")
        if not rule_dict.get("pattern") and not rule_dict.get("pattern_either") and not rule_dict.get("pattern-either"):
            raise CustomRuleValidationError("Either pattern or pattern_either required.")
        d = dict(rule_dict)
        if "pattern-either" in d: d["pattern_either"] = d.pop("pattern-either")
        try: return CustomRule.model_validate(d)
        except Exception as exc: raise CustomRuleValidationError(str(exc)) from exc

    def load_custom_rules(rules_dir):
        import json
        p = Path(rules_dir)
        if not p.is_dir(): return []
        rules = []
        for yf in sorted(list(p.glob("*.yaml")) + list(p.glob("*.yml"))):
            try:
                content = yf.read_text(encoding="utf-8", errors="ignore")
                try:
                    data = json.loads(content)
                    dicts = data.get("rules", [data]) if isinstance(data,dict) else data
                except Exception: dicts = []
                for d in dicts:
                    try: rules.append(validate_custom_rule(d))
                    except CustomRuleValidationError as e: logger.warning("Skip %s: %s", yf.name, e)
            except Exception as e: logger.warning("Parse fail %s: %s", yf.name, e)
        return rules

    def export_semgrep_config(rules):
        if not rules: return "rules: []
"
        lines = ["rules:"]
        for r in rules:
            lines += [f"  - id: {r.id}", "    message: >-", f"      {r.message.replace(chr(10), chr(32))}",
                      f"    severity: {r.severity}", "    languages:"]
            for lang in r.languages: lines.append(f"      - {lang}")
            if r.pattern_either:
                lines.append("    pattern-either:")
                for pat in r.pattern_either: lines.append(f"      - pattern: '{pat.replace(chr(39), chr(39)*2)}'")
            elif r.pattern: lines.append(f"    pattern: '{r.pattern.replace(chr(39), chr(39)*2)}'")
            if r.pattern_not: lines.append(f"    pattern-not: '{r.pattern_not}'")
            if r.fix: lines.append(f"    fix: '{r.fix}'")
            if r.metadata:
                lines.append("    metadata:")
                for k,v in r.metadata.items():
                    if isinstance(v,str): lines.append(f"      {k}: {v}")
                    elif isinstance(v,list):
                        lines.append(f"      {k}:")
                        for item in v: lines.append(f"        - {item}")
                    else: lines.append(f"      {k}: {v}")
        return "
".join(lines) + "
"
