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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.common.collect.ImmutableSet;
import com.google.common.net.MediaType;

@SuppressWarnings({"javadoc", "static-method"})
public final class UrlValueTest {

  @Test
  public void testInheritsPlaceholderAuthority() {
    final String PH = UrlContext.PLACEHOLDER_AUTHORITY;

    assertTrue(UrlValue.from("").inheritsPlaceholderAuthority);
    assertTrue(UrlValue.from("#").inheritsPlaceholderAuthority);
    assertTrue(UrlValue.from("?query").inheritsPlaceholderAuthority);
    assertTrue(UrlValue.from("/").inheritsPlaceholderAuthority);
    assertTrue(UrlValue.from("/foo").inheritsPlaceholderAuthority);
    assertTrue(UrlValue.from("/foo/./").inheritsPlaceholderAuthority);
    assertTrue(UrlValue.from("/foo/./").inheritsPlaceholderAuthority);
    assertTrue(UrlValue.from("/foo?q#f").inheritsPlaceholderAuthority);
    assertFalse(UrlValue.from("//localhost/").inheritsPlaceholderAuthority);
    assertFalse(UrlValue.from("//localhost").inheritsPlaceholderAuthority);
    assertFalse(UrlValue.from("http://" + PH).inheritsPlaceholderAuthority);
    assertFalse(UrlValue.from("http://" + PH + "/").inheritsPlaceholderAuthority);
    assertFalse(UrlValue.from("http://foo.com/").inheritsPlaceholderAuthority);
    assertFalse(UrlValue.from("https://" + PH).inheritsPlaceholderAuthority);
    assertFalse(UrlValue.from("https://" + PH + "/foo/").inheritsPlaceholderAuthority);
    assertFalse(UrlValue.from("https://" + PH + ":443/foo/").inheritsPlaceholderAuthority);
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
      UrlValue v = UrlValue.from(url);
      assertFalse(
          url,
          v.cornerCases.contains(
              UrlValue.CornerCase.PATH_SIMPLIFICATION_REACHES_ROOT_PARENT));
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
      UrlValue v = UrlValue.from(url);
      assertTrue(
          url,
          v.cornerCases.contains(
              UrlValue.CornerCase.PATH_SIMPLIFICATION_REACHES_ROOT_PARENT));
    }
  }

  @Test
  public void testGetContentMediaType() {
    assertEquals(
        MediaType.parse("text/plain"),
        UrlValue.from("data:text/plain,").getContentMediaType());
    assertEquals(
        MediaType.parse("text/plain;charset=UTF-8"),
        UrlValue.from("data:text/plain;charset=UTF-8,").getContentMediaType());
    assertEquals(
        MediaType.parse("text/plain;charset=UTF-8"),
        UrlValue.from("data:text/plain;charset=\"UTF\\-8\",").getContentMediaType());
    assertEquals(
        MediaType.parse("image/gif; desc=\"a logo\""),
        UrlValue.from("data:image/gif;desc=a logo,").getContentMediaType());
    assertEquals(
        MediaType.parse("image/png"),
        UrlValue.from("data:ima%67e/pn%67,f%6f%6F=b%61r").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        UrlValue.from("data:ima%67e/sv%67;f%6f%6F=b%61r,").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        UrlValue.from("data:ima%67e/sv%67;f%6f%6F=\"b%61r\",").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        UrlValue.from("data:ima%67e/sv%67;f%6f%6F=%22b%61r\",").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        UrlValue.from("data:ima%67e/sv%67;f%6f%6F=\"b\\%61r%22,").getContentMediaType());
    assertEquals(
        MediaType.parse("image/svg;foo=bar"),
        UrlValue.from("data:ima%67e/sv%67;f%6f%6F=%22b%5c%61r%22,").getContentMediaType());
    assertEquals(
        null,
        UrlValue.from("data:text%2fhtml,").getContentMediaType());
    assertEquals(
        null,
        UrlValue.from("data:text/html%3fcharset=utf-8,").getContentMediaType());
    assertEquals(
        MediaType.parse("text/html;charset=utf-8"),
        UrlValue.from("data:text/html;charset=utf-8,").getContentMediaType());
  }

  @Test
  public void testHumanReadableContext() {
    UrlContext humanReadableContext =
        new UrlContext(UrlContext.DEFAULT.absolutizer)
        .with(UrlContext.UrlSource.HUMAN_READABLE_INPUT);
    assertEquals(
        "http://example.org./",
        UrlValue.from(humanReadableContext, "").urlText);
    assertEquals(
        "http://example.org./",
        UrlValue.from(humanReadableContext, "/").urlText);
    assertEquals(
        "http://foo.com/bar",
        UrlValue.from(humanReadableContext, "http://foo.com/bar").urlText);
    assertEquals(
        "http://foo.com/bar",
        UrlValue.from(humanReadableContext, "foo.com/bar").urlText);
    assertEquals(
        "http://foo.com/",
        UrlValue.from(humanReadableContext, "foo.com").urlText);
    assertEquals(
        "mailto:foo@bar.com",
        UrlValue.from(humanReadableContext, "foo@bar.com").urlText);
    assertEquals(
        "http://example.org./foo@",
        UrlValue.from(humanReadableContext, "foo@").urlText);
    assertEquals(
        "http://example.org./@twitterHandle",
        UrlValue.from(humanReadableContext, "@twitterHandle").urlText);
  }

  @Test
  public void testFlippingSlashes() {
    UrlContext flippingContext =
        new UrlContext(UrlContext.DEFAULT.absolutizer)
        .with(UrlContext.MicrosoftPathStrategy.BACK_TO_FORWARD);

    UrlValue u;

    u = UrlValue.from(flippingContext, "");
    assertEquals("http://example.org./", u.urlText);
    assertEquals(u.toString(), ImmutableSet.of(), u.cornerCases);

    u = UrlValue.from(flippingContext, "/");
    assertEquals("http://example.org./", u.urlText);
    assertEquals(u.toString(), ImmutableSet.of(), u.cornerCases);

    u = UrlValue.from(flippingContext, "http://foo.com/bar");
    assertEquals("http://foo.com/bar", u.urlText);
    assertEquals(u.toString(), ImmutableSet.of(), u.cornerCases);

    u = UrlValue.from(flippingContext, "file:\\C|\\foo\\bar");
    assertEquals("file:/C|/foo/bar", u.urlText);
    assertEquals("/C|/foo/bar", u.getRawPath());
    assertEquals(
        u.toString(),
        ImmutableSet.of(UrlValue.CornerCase.FLIPPED_SLASHES),
        u.cornerCases);

    String jsUrl = "javascript:/\\./.test(0)";
    u = UrlValue.from(flippingContext, jsUrl);
    assertEquals(jsUrl, u.urlText);
    assertEquals("/\\./.test(0)", u.getRawContent());
    assertEquals("/\\./.test(0)", u.getDecodedContent());
    assertEquals(u.toString(), ImmutableSet.of(), u.cornerCases);

    String mailtoUrl = "mailto:\\\"\\\\f\\\\o\\\\o\\\"@domain.com";
    u = UrlValue.from(flippingContext, mailtoUrl);
    assertEquals(mailtoUrl, u.urlText);
    assertEquals(u.toString(), ImmutableSet.of(), u.cornerCases);
  }

  @Test
  public void testRfc2392() {
    UrlValue cid0 = UrlValue.from("cid:foo4*foo1@bar.net");
    UrlValue cid1 = UrlValue.from("cid:foo4*foo1%40bar.net");
    UrlValue mid0 = UrlValue.from(
        "mid:960830.1639@XIson.com/partA.960830.1639@XIson.com");
    UrlValue mid1 = UrlValue.from(
        "mid:960830.1639%40XIson.com/partA.960830.1639%40XIson.com");

    assertEquals(
        "cid0",
        "foo4*foo1@bar.net",
        cid0.getDecodedContent());
    assertEquals(
        "cid1",
        "foo4*foo1@bar.net",
        cid1.getDecodedContent());

    assertEquals(
        "mid0",
        "960830.1639@XIson.com/partA.960830.1639@XIson.com",
        mid0.getDecodedContent());
    assertEquals(
        "mid1",
        "960830.1639@XIson.com/partA.960830.1639@XIson.com",
        mid1.getDecodedContent());
  }
}
