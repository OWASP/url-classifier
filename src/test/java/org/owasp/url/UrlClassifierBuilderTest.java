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

import java.util.Arrays;

import org.junit.Test;

import com.google.common.collect.ImmutableList;

@SuppressWarnings({"javadoc", "static-method"})
public final class UrlClassifierBuilderTest {

  static final class TestBuilder {
    private final UrlClassifier c;
    private final ImmutableList.Builder<UrlValue> expectInvalid
        = ImmutableList.builder();
    private final ImmutableList.Builder<UrlValue> expectMatches
        = ImmutableList.builder();
    private final ImmutableList.Builder<UrlValue> expectDoesNotMatch
        = ImmutableList.builder();
    private UrlContext context = UrlContext.DEFAULT;

    TestBuilder(UrlClassifier c) {
      this.c = c;
    }

    TestBuilder expectInvalid(String... urlTexts) {
      for (String urlText : urlTexts) {
        expectInvalid.add(UrlValue.from(context, urlText));
      }
      return this;
    }

    TestBuilder expectInvalid(UrlValue... urlValues) {
      expectInvalid.addAll(Arrays.asList(urlValues));
      return this;
    }

    TestBuilder expectMatches(String... urlTexts) {
      for (String urlText : urlTexts) {
        expectMatches.add(UrlValue.from(context, urlText));
      }
      return this;
    }

    TestBuilder expectMatches(UrlValue... urlValues) {
      expectMatches.addAll(Arrays.asList(urlValues));
      return this;
    }

    TestBuilder expectDoesNotMatch(String... urlTexts) {
      for (String urlText : urlTexts) {
        expectDoesNotMatch.add(UrlValue.from(context, urlText));
      }
      return this;
    }

    TestBuilder expectDoesNotMatch(UrlValue... urlValues) {
      expectDoesNotMatch.addAll(Arrays.asList(urlValues));
      return this;
    }

    TestBuilder useContext(UrlContext newContext) {
      this.context = newContext;
      return this;
    }

    TestBuilder useContext(String contextUrl) {
      return this.useContext(new UrlContext(
          new Absolutizer(UrlContext.DEFAULT.absolutizer.schemes, contextUrl)));
    }

    void run() {
      Diagnostic.CollectingReceiver<UrlValue> cr = Diagnostic.CollectingReceiver.from(
          TestUtil.STDERR_RECEIVER);
      try {
        for (UrlValue x : expectInvalid.build()) {
          cr.clear();
          assertEquals(debug(x), Classification.INVALID, c.apply(x, cr));
        }
        for (UrlValue x : expectMatches.build()) {
          cr.clear();
          assertEquals(debug(x), Classification.MATCH, c.apply(x, cr));
        }
        for (UrlValue x : expectDoesNotMatch.build()) {
          cr.clear();
          assertEquals(debug(x), Classification.NOT_A_MATCH, c.apply(x, cr));
        }
        cr.clear();
      } finally {
        cr.flush();
      }
    }
  }

  @Test
  public void testUnconfiguredClassifier() {
    new TestBuilder(UrlClassifiers.builder().build())
        .expectInvalid(
            "\0",
            "..",
            "%2e%2E/%2e%2E/%2e%2E/etc/passwd",
            "file://a\nb@example.com/",
            "file://a\rb@example.com/",
            "file://a\r\nb@example.com/",
            "file://a\\b@example.com/",
            "file:/a\nbb/",
            "file:/a\rbb/",
            "file:/a\r\nbb/",
            "file:/a%0abb/",
            "file:/a%0dbb/",
            "file:/a%0a%0dbb/"
            )
        .expectDoesNotMatch(
            "",
            "/",
            "/foo/",
            "%",
            "data:foo/bar,",
            "https://www.example.net./",
            "mailto:user@domain.org")
        .run();
  }

  @Test
  public void testAllowHttpHttps() {
    new TestBuilder(
        UrlClassifiers.builder()
            .scheme(BuiltinScheme.HTTP, BuiltinScheme.HTTPS)
            .build())
        .expectInvalid(
            "%2e%2E/%2e%2E/%2e%2E/etc/passwd",  // spec corner case
            "%",  // malformed escape sequence
            "\0",
            "data:foo",
            "%c0%80")  // non-minimal encoding
        .expectMatches(
            "",
            "/",
            "/foo/",
            "https://www.example.net./"
            )
        .expectDoesNotMatch(
            "data:foo/bar,",
            "mailto:user@domain.org")
        .expectInvalid("..")
        .run();
  }

  @Test
  public void testFilterAuthorities() {
    new TestBuilder(
        UrlClassifiers.builder()
            .scheme(BuiltinScheme.HTTP, BuiltinScheme.HTTPS)
            .authority(
                AuthorityClassifiers.builder()
                    .hostGlob("*.example.net")
                    .build())
            .build())
        .expectInvalid(
            "..",
            "%2e%2E/%2e%2E/%2e%2E/etc/passwd")  // spec corner cases
        .expectMatches(
            "https://www.example.net./")
        .expectDoesNotMatch(
            "",
            "%",
            "%c0%80",
            "/",
            "/foo/",
            "file:///foo",
            "data:text/plain,Hello%20World!",
            "mailto:user@domain.org")
        .useContext("http://foo.example.net/")
        .expectMatches(
            "",
            "/",
            "/foo/")
        .expectDoesNotMatch("file://foo.example.net/")
        .expectInvalid(
            "%",
            "%c0%80")
        .run();
  }

  @Test
  public void testFilterPaths() {
    new TestBuilder(
        UrlClassifiers.builder()
            .scheme(BuiltinScheme.HTTP, BuiltinScheme.HTTPS)
            .pathGlob("**.html", "/foo/*", "/app/?")
            .notPathGlob("/foo/error")
            .build())
        .expectInvalid(
            "%2e%2E/%2e%2E/%2e%2E/etc/passwd")  // spec corner case
        .expectMatches(
            "/foo/bar.html",
            "/bar/baz.html",
            "/boo.html",
            "/foo/../bar/baz/boo//far.html",
            "/foo/image.png",
            "/app",
            "/app/",
            "/app/foo/bar/baz/boo.html",
            "https://other.com/app/")
        .expectDoesNotMatch(
            "mailto:/foo.html",
            "/foo.html.js",
            "/foo/bar/baz",
            "/app/foo/",
            "/boo.HTML",
            "/Foo/bar",
            "/foo/error")
        .expectInvalid(
            "%",
            "%c0%80")
        .useContext("http://foo.example.net/foo/")
        .expectMatches(
            "",
            "bar.html",
            "bar.png",
            "/bar.html",
            "/app/"
            )
        .expectDoesNotMatch(
            "app/",
            "/bar.png",
            "error",
            "./error")
        .run();
  }

  @Test
  public void testPathEscapingConventions() {
    // Escaping '?'
    new TestBuilder(
        UrlClassifiers.builder()
            .scheme(BuiltinScheme.FILE)
            .pathGlob("/foo/%3f")
            .build())
         .useContext("file:/")
        .expectMatches("/foo/%3f", "/foo/%3F")
        .expectDoesNotMatch("/foo/", "/foo")
        .run();
    // Escaping '%'
    new TestBuilder(
        UrlClassifiers.builder()
            .scheme(BuiltinScheme.FILE)
            .pathGlob("/foo/%253f")
            .build())
        .useContext("file:/")
        .expectMatches("/foo/%253f")
        .expectDoesNotMatch(
            "/foo/%253F", "/foo/", "/foo",
            "/foo/%3f", "/foo/%3F")
        .run();
    // Escaping '*'
    new TestBuilder(
        UrlClassifiers.builder()
            .scheme(BuiltinScheme.FILE)
            .pathGlob("/foo/%2A")
            .pathGlob("/bar/%2A%2A")
            .build())
        .useContext("file:/")
        .expectMatches("/foo/*", "/bar/**")
        .expectDoesNotMatch(
            "/foo/", "/foo/bar", "/bar", "/bar/", "/bar/baz", "/boo")
        .run();
    // Escaping 'a' and 'A'
    new TestBuilder(
        UrlClassifiers.builder()
            .scheme(BuiltinScheme.FILE)
            .pathGlob("/b%61r")
            .pathGlob("/B%41R")
            .build())
        .useContext("file:/")
        .expectMatches("/bar", "/BAR", "/b%61r", "/%62%61r", "/%42%41R")
        .expectDoesNotMatch(
            "/b%2561r", "/Bar", "/foo")
        .run();
  }

  @Test
  public final void testQueryClassifying() {
    new TestBuilder(
        UrlClassifiers.builder()
            .scheme(BuiltinScheme.HTTP, BuiltinScheme.MAILTO)
            .schemeData(MediaTypeClassifiers.any())  // Data don't naturally have queries
            .query(QueryClassifiers.builder()
                .mayHaveKeys("a", "b", "c")
                .mustHaveKeys("x")
                .build())
            .build())
        .useContext("about:invalid")  // Admits query but scheme not whitelisted
        .expectMatches(
            "http://foo/?x=1&a=b",
            "http://foo/?a=b&x",
            "mailto:foo@example.com?x",
            // This is not actually a query, so the fact that
            // mayHaveKeys("d") was not specified doesn't matter.
            // We also don't require query classifiers to match when
            // the scheme doesn't allow a query.
            "data:text/plain,?d=v"
            )
        .expectDoesNotMatch(
            "",
            "http://foo/",
            "http://foo/?x&d",
            "mailto:foo@example.com",
            "mailto:foo@example.com?d"
            )
        .run();
  }

  @Test
  public final void testFragment() {
    new TestBuilder(
        UrlClassifiers.builder()
            .scheme(BuiltinScheme.HTTP, BuiltinScheme.MAILTO)
            .schemeData(MediaTypeClassifiers.any())  // Data don't naturally have queries
            .query(QueryClassifiers.builder()
                .mayHaveKeys("a", "b", "c")
                .mustHaveKeys("x")
                .build())
            .build())
        .useContext("about:invalid")  // Admits query but scheme not whitelisted
        .expectMatches(
            "http://foo/?x=1&a=b",
            "http://foo/?a=b&x",
            "mailto:foo@example.com?x",
            // This is not actually a query, so the fact that
            // mayHaveKeys("d") was not specified doesn't matter.
            // We also don't require query classifiers to match when
            // the scheme doesn't allow a query.
            "data:text/plain,?d=v"
            )
        .expectDoesNotMatch(
            "",
            "http://foo/",
            "http://foo/?x&d",
            "mailto:foo@example.com",
            "mailto:foo@example.com?d"
            )
        .run();
  }

  @Test
  public final void testBrokenInputs() {
    new TestBuilder(
        UrlClassifiers.builder()
        .schemeData(MediaTypeClassifiers.any())
        .content(ContentClassifiers.any())
        .build())
    .expectInvalid("data:text/plain;base64")
    .run();
  }

  @Test
  public final void testMediaTypes() {
    new TestBuilder(
        UrlClassifiers.builder()
        .schemeData(
            MediaTypeClassifiers.builder()
            .type("image", "png")
            .build())
        .build())
    .expectMatches("data:image/png;base64,...")
    .expectDoesNotMatch(
        "data:text/html;charset=utf-8,...",
        "data:image/gif;base64,...")
    .expectInvalid("data:image/svg;")
    .run();
  }


  @Test
  public void testIDNAAbuse() {
    // Tests courtesy "Abusing IDNA Standard" section of
    // https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
    new TestBuilder(
        UrlClassifiers.builder()
        .scheme(BuiltinScheme.HTTP, BuiltinScheme.HTTPS)
        .authority(
            AuthorityClassifiers.builder()
            .host("google.com", "bass.de")
            .build())
        .build())
    .expectMatches(
        "http://google.com/", "http://GOOGLE.COM/",
        "http://bass.de/", "http://bass.DE/")
    .expectDoesNotMatch(
        "http://ⓖⓞⓞⓖⓛⓔ.com/")
    .expectInvalid(
        // IDNA deviant character abuses
        "http://g\\u200Doogle.com/",
        "http://g\u200Doogle.com/",
        "http://baß.de/")
    .run();
  }


  // TODO: simple content predicate with magic number check for gif

  static String debug(UrlValue x) {
    String escapedUrl = x.urlText
        .replace("\\", "\\\\")
        .replace("\0", "\\0")
        .replace("\n", "\\n")
        .replace("\r", "\\r");
    StringBuilder sb = new StringBuilder()
        .append("(URLValue `")
        .append(escapedUrl)
        .append('`');
    if (!x.cornerCases.isEmpty()) {
      sb.append(' ').append(x.cornerCases);
    }
    if (x.inheritsPlaceholderAuthority) {
      sb.append(" placeholder");
    }
    return sb.append(')').toString();
  }
}
