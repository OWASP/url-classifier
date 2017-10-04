package com.mikesamuel.url;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.common.net.MediaType;

@SuppressWarnings({"javadoc", "static-method"})
public final class URLValueTest {

  @Test
  public void testInheritsPlaceholderAuthority() {
    final String PH = URLContext.PLACEHOLDER_AUTHORITY;

    assertTrue(URLValue.of("").inheritsPlaceholderAuthority);
    assertTrue(URLValue.of("#").inheritsPlaceholderAuthority);
    assertTrue(URLValue.of("?query").inheritsPlaceholderAuthority);
    assertTrue(URLValue.of("/").inheritsPlaceholderAuthority);
    assertTrue(URLValue.of("/foo").inheritsPlaceholderAuthority);
    assertTrue(URLValue.of("/foo/./").inheritsPlaceholderAuthority);
    assertTrue(URLValue.of("/foo/./").inheritsPlaceholderAuthority);
    assertTrue(URLValue.of("/foo?q#f").inheritsPlaceholderAuthority);
    assertFalse(URLValue.of("//localhost/").inheritsPlaceholderAuthority);
    assertFalse(URLValue.of("//localhost").inheritsPlaceholderAuthority);
    assertFalse(URLValue.of("http://" + PH).inheritsPlaceholderAuthority);
    assertFalse(URLValue.of("http://" + PH + "/").inheritsPlaceholderAuthority);
    assertFalse(URLValue.of("http://foo.com/").inheritsPlaceholderAuthority);
    assertFalse(URLValue.of("https://" + PH).inheritsPlaceholderAuthority);
    assertFalse(URLValue.of("https://" + PH + "/foo/").inheritsPlaceholderAuthority);
    assertFalse(URLValue.of("https://" + PH + ":443/foo/").inheritsPlaceholderAuthority);
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
      URLValue v = URLValue.of(url);
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
      URLValue v = URLValue.of(url);
      assertTrue(url, v.pathSimplificationReachedRootsParent);
    }
  }

  @Test
  public void testGetContentMediaType() {
    assertEquals(
        MediaType.parse("text/plain"),
        URLValue.of("data:text/plain,").getContentMediaType());
    assertEquals(
        MediaType.parse("text/plain;charset=UTF-8"),
        URLValue.of("data:text/plain;charset=UTF-8,").getContentMediaType());
    assertEquals(
        MediaType.parse("text/plain;charset=UTF-8"),
        URLValue.of("data:text/plain;charset=\"UTF\\-8\",").getContentMediaType());
    assertEquals(
        MediaType.parse("image/gif; desc=\"a logo\""),
        URLValue.of("data:image/gif;desc=a logo,").getContentMediaType());
    assertEquals(
        MediaType.parse("image/png"),
        URLValue.of("data:ima%67e/pn%67,f%6f%6F=b%61r").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        URLValue.of("data:ima%67e/sv%67;f%6f%6F=b%61r,").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        URLValue.of("data:ima%67e/sv%67;f%6f%6F=\"b%61r\",").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        URLValue.of("data:ima%67e/sv%67;f%6f%6F=%22b%61r\",").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        URLValue.of("data:ima%67e/sv%67;f%6f%6F=\"b\\%61r%22,").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        URLValue.of("data:ima%67e/sv%67;f%6f%6F=%22b%5c%61r%22,").getContentMediaType());
    assertEquals(
        null,
        URLValue.of("data:text%2fhtml,").getContentMediaType());
    assertEquals(
        null,
        URLValue.of("data:text/html%3fcharset=utf-8,").getContentMediaType());
    assertEquals(
        MediaType.parse("text/html;charset=utf-8"),
        URLValue.of("data:text/html;charset=utf-8,").getContentMediaType());
  }
}
