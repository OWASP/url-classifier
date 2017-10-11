// Copyright (c) 2017, Mike Samuel
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// Neither the name of the OWASP nor the names of its contributors may
// be used to endorse or promote products derived from this software
// without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package org.owasp.url;

import java.io.File;
import java.io.IOException;

import com.google.common.base.Charsets;
import com.google.common.io.ByteSource;
import com.google.common.io.CharSource;
import com.google.common.io.Files;

/**
 * Reads URLs and tries to parse them.
 */
public final class FuzzUrlValue {
  /**
   * @param testFilePaths paths to files containing testcases.
   */
  public static void main(String... testFilePaths) throws IOException {
    int testCount = 0;
    for (String testFilePath : testFilePaths) {
      File testFile = new File(testFilePath);
      ByteSource bytes = Files.asByteSource(testFile);
      // Just read bytes as chars since the URL grammar is an octet-based grammar.
      CharSource chars = bytes.asCharSource(Charsets.ISO_8859_1);

      String input = chars.read();
      boolean ok = false;
      try {
        UrlValue url = UrlValue.from(input);
        url.getAuthority(Diagnostic.Receiver.NULL);
        url.getContentMediaType();
        url.getContentMetadata();
        url.getDecodedContent();
        url.getFragment();
        url.getQuery();
        url.getRawAuthority();
        url.getRawContent();
        url.getRawPath();
        ok = true;
      } finally {
        if (!ok) {
          System.err.println("Failed on `" + input + "` from " + testFilePath);
        }
      }
      testCount += 1;
    }
    System.out.println("Ran " + testCount + " tests");
    if (testCount == 0) {
      throw new Error("No tests read");
    }
  }
}
