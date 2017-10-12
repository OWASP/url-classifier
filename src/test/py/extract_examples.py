#!/usr/bin/env python

"""
Extracts ```java...``` sections from markdown files and
assembles them into a Java file so that we can test that
it compiles.
"""

import re
import sys

# Pattern that identifies the code sections in the markdown file
_JAVA_CODE_SECTION = re.compile(r'(?ms)```java\s*$(.*?)^```\s*$')
# Pattern that identifies imports in a Java code snippet.
_IMPORT = re.compile(r'^(?ms)import\s([^;]*);\s*$')
# Turn top level classes into static inner classes so that we can
# bundle everything in one Java class declaration.
_TOP_LEVEL_CLASSES = re.compile(r'(?m)(^(?:(?:public|final|abstract)\s+)*class\b)')

class CodeSection:
    def __init__(self, file_name, line_num, code):
        self.file_name = file_name
        self.line_num = line_num
        self.code = code

class MarkdownFile:
    def __init__(self, md_path):
        self.md_path = md_path
        md_file = file(md_path)
        markdown = md_file.read()
        self.code_sections = []
        imports = set()
        def extract_imports(m):
            imports.add(m.group(1))
            return ""
        for match in _JAVA_CODE_SECTION.finditer(markdown):
            code = match.group(1)
            line_num = len(markdown[:match.start()].split('\n'))
            code = _IMPORT.sub(extract_imports, code)
            code = _TOP_LEVEL_CLASSES.sub(r'static \1', code)
            self.code_sections.append(CodeSection(md_path, line_num, code))
        self.imports = imports

def _indent(s, prefix):
    return '\n'.join(
        ['%s%s' % (prefix, line) for line in s.split('\n')]
    )

def _assemble_java_file(paths):
    markdown_files = [MarkdownFile(path) for path in paths]

    all_imports = set()
    all_code_sections = []
    for mdf in markdown_files:
        all_imports.update(mdf.imports)
        all_code_sections.extend(mdf.code_sections)

    all_imports = list(all_imports)
    all_imports.sort()

    return """
package com.example;

%(imports)s

class Snippets {
%(snippets)s
}
""" % {
    "imports": "\n".join([
        "import %s;" % imp for imp in all_imports]),
    "snippets": "\n\n".join([
        "  // %s:%s\n%s" % (
            cs.file_name,
            cs.line_num,
            _indent(cs.code, '  '))
        for cs in all_code_sections])
}

if __name__ == "__main__":
    print _assemble_java_file(sys.argv[1:])
