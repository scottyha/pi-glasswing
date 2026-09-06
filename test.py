def parse(stripped):
    intel_summary = {}
    import re
    if "CRITICAL" in stripped and "(" in stripped and ")" in stripped and any(c.isdigit() for c in stripped.split("(")[1]):
        if "CRITICAL" in stripped:
            match = re.search(r'CRITICAL\s+\((\d+)\)', stripped)
            if match:
                intel_summary["critical_cves"] = int(match.group(1))
        elif "HIGH" in stripped and "(" in stripped:
            match = re.search(r'HIGH\s+\((\d+)\)', stripped)
            if match:
                intel_summary["high_cves"] = int(match.group(1))
    return intel_summary

print(parse("- HIGH (5)"))
print(parse("- CRITICAL (2) and HIGH (3)"))
