package com.mikesamuel.url;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Test;

import com.google.common.collect.ImmutableList;

@SuppressWarnings({"javadoc", "static-method"})
public final class URLClassifierBuilderTest {

  static final class TestBuilder {
    private final URLClassifier c;
    private final ImmutableList.Builder<URLValue> expectInvalid
        = ImmutableList.builder();
    private final ImmutableList.Builder<URLValue> expectMatches
        = ImmutableList.builder();
    private final ImmutableList.Builder<URLValue> expectDoesNotMatch
        = ImmutableList.builder();
    private URLContext context = URLContext.DEFAULT;

    TestBuilder(URLClassifier c) {
      this.c = c;
    }

    TestBuilder expectInvalid(String... urlTexts) {
      for (String urlText : urlTexts) {
        expectInvalid.add(URLValue.from(context, urlText));
      }
      return this;
    }

    TestBuilder expectInvalid(URLValue... urlValues) {
      expectInvalid.addAll(Arrays.asList(urlValues));
      return this;
    }

    TestBuilder expectMatches(String... urlTexts) {
      for (String urlText : urlTexts) {
        expectMatches.add(URLValue.from(context, urlText));
      }
      return this;
    }

    TestBuilder expectMatches(URLValue... urlValues) {
      expectMatches.addAll(Arrays.asList(urlValues));
      return this;
    }

    TestBuilder expectDoesNotMatch(String... urlTexts) {
      for (String urlText : urlTexts) {
        expectDoesNotMatch.add(URLValue.from(context, urlText));
      }
      return this;
    }

    TestBuilder expectDoesNotMatch(URLValue... urlValues) {
      expectDoesNotMatch.addAll(Arrays.asList(urlValues));
      return this;
    }

    TestBuilder useContext(URLContext newContext) {
      this.context = newContext;
      return this;
    }

    TestBuilder useContext(String contextUrl) {
      return this.useContext(new URLContext(
          new Absolutizer(URLContext.DEFAULT.absolutizer.schemes, contextUrl)));
    }

    void run() {
      Diagnostic.CollectingReceiver<URLValue> cr = Diagnostic.collecting(
          TestUtil.STDERR_RECEIVER);
      try {
        for (URLValue x : expectInvalid.build()) {
          cr.clear();
          assertEquals(debug(x), Classification.INVALID, c.apply(x, cr));
        }
        for (URLValue x : expectMatches.build()) {
          cr.clear();
          assertEquals(debug(x), Classification.MATCH, c.apply(x, cr));
        }
        for (URLValue x : expectDoesNotMatch.build()) {
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
    new TestBuilder(URLClassifier.builder().build())
        .expectInvalid(
            "\0",
            "%2e%2E/%2e%2E/%2e%2E/etc/passwd"  // corner case
            )
        .expectDoesNotMatch(
            "",
            "/",
            "/foo/",
            "..",
            "%",
            "data:foo/bar,",
            "https://www.example.net./",
            "mailto:user@domain.org")
        .run();
  }

  @Test
  public void testAllowHttpHttps() {
    new TestBuilder(
        URLClassifier.builder()
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
            "..",
            "data:foo/bar,",
            "mailto:user@domain.org")
        .run();
  }

  @Test
  public void testFilterAuthorities() {
    new TestBuilder(
        URLClassifier.builder()
            .scheme(BuiltinScheme.HTTP, BuiltinScheme.HTTPS)
            .authority(
                AuthorityClassifier.builder()
                    .hostGlob("*.example.net")
                    .build())
            .build())
        .expectInvalid(
            "%2e%2E/%2e%2E/%2e%2E/etc/passwd")  // spec corner case
        .expectMatches(
            "https://www.example.net./")
        .expectDoesNotMatch(
            "",
            "%",
            "%c0%80",
            "/",
            "/foo/",
            "..",
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
        URLClassifier.builder()
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
        URLClassifier.builder()
            .scheme(BuiltinScheme.FILE)
            .pathGlob("/foo/%3f")
            .build())
         .useContext("file:/")
        .expectMatches("/foo/%3f", "/foo/%3F")
        .expectDoesNotMatch("/foo/", "/foo")
        .run();
    // Escaping '%'
    new TestBuilder(
        URLClassifier.builder()
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
        URLClassifier.builder()
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
        URLClassifier.builder()
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
        URLClassifier.builder()
            .scheme(BuiltinScheme.HTTP, BuiltinScheme.MAILTO)
            .schemeData(MediaTypeClassifier.any())  // Data don't naturally have queries
            .query(QueryClassifier.builder()
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
        URLClassifier.builder()
            .scheme(BuiltinScheme.HTTP, BuiltinScheme.MAILTO)
            .schemeData(MediaTypeClassifier.any())  // Data don't naturally have queries
            .query(QueryClassifier.builder()
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
        URLClassifier.builder()
        .schemeData(MediaTypeClassifier.any())
        .content(ContentClassifier.any())
        .build())
    .expectInvalid("data:text/plain;base64")
    .run();
  }

  // TODO: simple content predicate with magic number check for gif

  static String debug(URLValue x) {
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
