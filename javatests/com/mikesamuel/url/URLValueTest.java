package com.mikesamuel.url;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.common.collect.ImmutableSet;
import com.google.common.net.MediaType;

@SuppressWarnings({"javadoc", "static-method"})
public final class URLValueTest {

  @Test
  public void testInheritsPlaceholderAuthority() {
    final String PH = URLContext.PLACEHOLDER_AUTHORITY;

    assertTrue(URLValue.from("").inheritsPlaceholderAuthority);
    assertTrue(URLValue.from("#").inheritsPlaceholderAuthority);
    assertTrue(URLValue.from("?query").inheritsPlaceholderAuthority);
    assertTrue(URLValue.from("/").inheritsPlaceholderAuthority);
    assertTrue(URLValue.from("/foo").inheritsPlaceholderAuthority);
    assertTrue(URLValue.from("/foo/./").inheritsPlaceholderAuthority);
    assertTrue(URLValue.from("/foo/./").inheritsPlaceholderAuthority);
    assertTrue(URLValue.from("/foo?q#f").inheritsPlaceholderAuthority);
    assertFalse(URLValue.from("//localhost/").inheritsPlaceholderAuthority);
    assertFalse(URLValue.from("//localhost").inheritsPlaceholderAuthority);
    assertFalse(URLValue.from("http://" + PH).inheritsPlaceholderAuthority);
    assertFalse(URLValue.from("http://" + PH + "/").inheritsPlaceholderAuthority);
    assertFalse(URLValue.from("http://foo.com/").inheritsPlaceholderAuthority);
    assertFalse(URLValue.from("https://" + PH).inheritsPlaceholderAuthority);
    assertFalse(URLValue.from("https://" + PH + "/foo/").inheritsPlaceholderAuthority);
    assertFalse(URLValue.from("https://" + PH + ":443/foo/").inheritsPlaceholderAuthority);
  }

  @Test
  public void testPastFileRoot() {
    // Path simplification does not reach root parent.
    for (String url :
         new String[] {
             "",
             "/",
             "foo/./bar",
             "foo/../bar",
             "foo/..",
             "foo/../",
             "f/..",
             "./foo/bar",
             ".",
             "http://foo.com/",
             "http://foo.com/.",
             "about:../../..",
             "mailto:../@foo.com",
             "javascript:/../.test(/../)",
             "foo/bar/baz/../../boo/../..",
             "foo/./bar/./baz/../../boo/../../",
         }) {
      URLValue v = URLValue.from(url);
      assertFalse(url, v.pathSimplificationReachedRootsParent);
    }
    // Path simplification does reach root parent
    for (String url :
         new String[] {
             "..",
             "../",
             "./..",
             "../.",
             "./../",
             ".././",
             "../..",
             "/..",
             "/../",
             "/./..",
             "/../.",
             "file:..",
             "file:/..",
             "foo/bar/baz/../../boo/../../..",
             "foo/./bar/./baz/../../boo/../../..",
             "file:///..",
             "http://foo.com/../",
             "http://foo.com/bar/../baz/../..",
         }) {
      URLValue v = URLValue.from(url);
      assertTrue(url, v.pathSimplificationReachedRootsParent);
    }
  }

  @Test
  public void testGetContentMediaType() {
    assertEquals(
        MediaType.parse("text/plain"),
        URLValue.from("data:text/plain,").getContentMediaType());
    assertEquals(
        MediaType.parse("text/plain;charset=UTF-8"),
        URLValue.from("data:text/plain;charset=UTF-8,").getContentMediaType());
    assertEquals(
        MediaType.parse("text/plain;charset=UTF-8"),
        URLValue.from("data:text/plain;charset=\"UTF\\-8\",").getContentMediaType());
    assertEquals(
        MediaType.parse("image/gif; desc=\"a logo\""),
        URLValue.from("data:image/gif;desc=a logo,").getContentMediaType());
    assertEquals(
        MediaType.parse("image/png"),
        URLValue.from("data:ima%67e/pn%67,f%6f%6F=b%61r").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        URLValue.from("data:ima%67e/sv%67;f%6f%6F=b%61r,").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        URLValue.from("data:ima%67e/sv%67;f%6f%6F=\"b%61r\",").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        URLValue.from("data:ima%67e/sv%67;f%6f%6F=%22b%61r\",").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        URLValue.from("data:ima%67e/sv%67;f%6f%6F=\"b\\%61r%22,").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        URLValue.from("data:ima%67e/sv%67;f%6f%6F=%22b%5c%61r%22,").getContentMediaType());
    assertEquals(
        null,
        URLValue.from("data:text%2fhtml,").getContentMediaType());
    assertEquals(
        null,
        URLValue.from("data:text/html%3fcharset=utf-8,").getContentMediaType());
    assertEquals(
        MediaType.parse("text/html;charset=utf-8"),
        URLValue.from("data:text/html;charset=utf-8,").getContentMediaType());
  }

  @Test
  public void testHumanReadableContext() {
    URLContext humanReadableContext =
        new URLContext(URLContext.DEFAULT.absolutizer)
        .with(URLContext.URLSource.HUMAN_READABLE_INPUT);
    assertEquals(
        "http://example.org./",
        URLValue.from(humanReadableContext, "").urlText);
    assertEquals(
        "http://example.org./",
        URLValue.from(humanReadableContext, "/").urlText);
    assertEquals(
        "http://foo.com/bar",
        URLValue.from(humanReadableContext, "http://foo.com/bar").urlText);
    assertEquals(
        "http://foo.com/bar",
        URLValue.from(humanReadableContext, "foo.com/bar").urlText);
    assertEquals(
        "http://foo.com/",
        URLValue.from(humanReadableContext, "foo.com").urlText);
    assertEquals(
        "mailto:foo@bar.com",
        URLValue.from(humanReadableContext, "foo@bar.com").urlText);
    assertEquals(
        "http://example.org./foo@",
        URLValue.from(humanReadableContext, "foo@").urlText);
    assertEquals(
        "http://example.org./@twitterHandle",
        URLValue.from(humanReadableContext, "@twitterHandle").urlText);
  }

  @Test
  public void testFlippingSlashes() {
    URLContext flippingContext =
        new URLContext(URLContext.DEFAULT.absolutizer)
        .with(URLContext.MicrosoftPathStrategy.BACK_TO_FORWARD);

    URLValue u;

    u = URLValue.from(flippingContext, "");
    assertEquals("http://example.org./", u.urlText);
    assertEquals(u.toString(), ImmutableSet.of(), u.cornerCases);

    u = URLValue.from(flippingContext, "/");
    assertEquals("http://example.org./", u.urlText);
    assertEquals(u.toString(), ImmutableSet.of(), u.cornerCases);

    u = URLValue.from(flippingContext, "http://foo.com/bar");
    assertEquals("http://foo.com/bar", u.urlText);
    assertEquals(u.toString(), ImmutableSet.of(), u.cornerCases);

    u = URLValue.from(flippingContext, "file:\\C|\\foo\\bar");
    assertEquals("file:/C|/foo/bar", u.urlText);
    assertEquals("/C|/foo/bar", u.getRawPath());
    assertEquals(
        u.toString(),
        ImmutableSet.of(URLValue.URLSpecCornerCase.FLIPPED_SLASHES),
        u.cornerCases);
  }
}
