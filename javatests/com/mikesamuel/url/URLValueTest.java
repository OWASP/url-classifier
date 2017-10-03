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


}
