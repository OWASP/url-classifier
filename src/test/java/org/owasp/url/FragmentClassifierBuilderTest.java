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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.base.Predicates;

@SuppressWarnings({ "javadoc", "static-method" })
public final class FragmentClassifierBuilderTest {

  private static void assertFragmentClassification(
      Classification want, String inputUrl, FragmentClassifier p) {
    Diagnostic.CollectingReceiver<UrlValue> receiver = Diagnostic.collecting(
        TestUtil.STDERR_RECEIVER);
    Classification got = p.apply(
        UrlValue.from(UrlContext.DEFAULT, inputUrl),
        receiver);
    if (!want.equals(got)) {
      receiver.flush();
    }
    assertEquals(inputUrl, want, got);
  }

  @Test
  public void testNoFragment() {
    for (String inputUrl
         : new String[] { "", "/foo", "mailto:you@example.com" }) {
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentClassifier.builder().build());
      assertFragmentClassification(
          Classification.MATCH,
          inputUrl,
          FragmentClassifier.builder()
              .match(Predicates.equalTo(Optional.<String>absent()))
              .build());
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentClassifier.builder()
              .match(Predicates.equalTo(Optional.of("#foo")))
              .build());
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentClassifier.builder()
              .matchAsUrl(
                  new UrlClassifier() {

                    @Override
                    public Classification apply(
                        UrlValue x,
                        Diagnostic.Receiver<? super UrlValue> r) {
                      return Classification.MATCH;
                    }

                  })
              .build());
    }
  }

  @Test
  public void testSimpleFragment() {
    for (String inputUrl
         : new String[] { "#foo", "/bar#foo", "mailto:you@example.com#foo" }) {
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentClassifier.builder().build());
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentClassifier.builder()
              .match(Predicates.equalTo(Optional.<String>absent()))
              .build());
      assertFragmentClassification(
          Classification.MATCH,
          inputUrl,
          FragmentClassifier.builder()
              .match(Predicates.equalTo(Optional.of("#foo")))
              .build());
      assertFragmentClassification(
          Classification.MATCH,
          inputUrl,
          FragmentClassifier.builder()
              .matchAsUrl(
                  new UrlClassifier() {

                    @Override
                    public Classification apply(
                        UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
                      assertEquals(
                          "http://example.org./foo", x.urlText);
                      assertTrue(x.inheritsPlaceholderAuthority);
                      return Classification.MATCH;
                    }

                  })
              .build());
    }
  }

  @Test
  public void testComplexFragment() {
    for (String inputUrl : new String[] {
            "#foo/../bar/baz",
            "/boo#foo/../bar/baz",
            "mailto:you@example.com#foo/../bar/baz",
         }) {
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentClassifier.builder().build());
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentClassifier.builder()
              .match(Predicates.equalTo(Optional.<String>absent()))
              .build());
      assertFragmentClassification(
          Classification.MATCH,
          inputUrl,
          FragmentClassifier.builder()
              .match(Predicates.equalTo(Optional.of("#foo/../bar/baz")))
              .build());
      assertFragmentClassification(
          Classification.MATCH,
          inputUrl,
          FragmentClassifier.builder()
              .matchAsUrl(
                  new UrlClassifier() {

                    @Override
                    public Classification apply(
                        UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
                      return x.getRawPath().equals("/bar/baz")
                          ? Classification.MATCH
                          : Classification.NOT_A_MATCH;
                    }

                  })
              .build());
    }
  }
}
