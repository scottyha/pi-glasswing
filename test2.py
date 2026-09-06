def test_func():
    lines = ["## npm Registry Advisories (5)"]
    for line in lines:
        stripped = line.strip()
        if "Known Vulnerabilities" in stripped:
            import re as _re
            print("imported")
        elif stripped.startswith("## npm"):
            match = _re.search(r'\((\d+)\)', stripped)
            print(match.group(1))

test_func()
