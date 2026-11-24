"""Log parsing and detection rules.

Pipeline:  raw lines --parser--> LogEvent objects --rules--> Detection objects --> Alerts

Parsers turn each supported log format into the same normalised LogEvent
shape, so every rule works on every format.
"""
