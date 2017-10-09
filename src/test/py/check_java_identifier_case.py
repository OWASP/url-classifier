"""
Enforces case conventions in
https://google.github.io/styleguide/jsguide.html#naming-camel-case-defined
"""

import os
import os.path
import re
import sys

_java_char_pass = re.compile(r'\\(?:[^u]|u[0-9a-f]{4})')
_java_token = re.compile(
    '(?su)%s' %
    '|'.join((
        r'[\x00-\x20]+',
        r'//[^\r\n]*',
        r'/[*](?:[^*]|[*]+(?!/))*[*]/',
        r'[~!%^&*()\[\]{}\-+|:;,.<>?/]+',  # Run of punctuation
        r'"(?:[^"\\]|\\.)*"',
        r"'(?:[^'\\]|\\.)*'",
        r'[_$\w\d]+',  # Matches parts of numbers as identifier
        )))
_dodgy_case_token = re.compile(r'[A-Z]{3,}')
_ident_token = re.compile(r'(?u)^\w')
_const_token = re.compile(r'^[A-Z_0-9]+\Z')

def run():
    linenum = 1
    dodgy = False
    for dir_path, _, filenames in os.walk("src/main/java"):
        for filename in filenames:
            if filename.endswith(".java"):
                java_path = os.path.join(dir_path, filename)
                for token_match in _java_token.finditer(
                        file(java_path).read()):
                    token = token_match.group()
                    if (_ident_token.match(token)
                        and not _const_token.match(token)):
                        acronyms = _dodgy_case_token.findall(token)
                        if acronyms:
                            print "%s:%d: %s has %s" % (
                                java_path,
                                linenum,
                                token,
                                ','.join(acronyms)
                            )
                            if not dodgy:
                                print '\n'.join((
                                    "Detected violations of camel case conventions",
                                    "See https://google.github.io/styleguide/jsguide.html#naming-camel-case-defined",
                                    ))
                            dodgy = True
                    linenum += len(token.split('\n')) - 1
    return dodgy

if __name__ == "__main__":
    if run():
        sys.exit(-1)
    else:
        sys.exit(0)
