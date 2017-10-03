package com.mikesamuel.url;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

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
    URLValue f = URLValue.of("file:..");
    assertTrue(f.pathSimplificationReachedRootsParent);
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
}
