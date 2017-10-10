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

import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;


@SuppressWarnings({ "javadoc", "static-method" })
public final class AuthorityClassifierBuilderTest {

  private static void runCommonTestsWith(
      AuthorityClassifier p,
      UrlContext context,
      String... shouldMatch) {

    Diagnostic.CollectingReceiver<UrlValue> cr = Diagnostic.CollectingReceiver.from(
        TestUtil.STDERR_RECEIVER);

    ImmutableSet<String> matchSet = ImmutableSet.copyOf(shouldMatch);

    try {
      for (int i = 0; i < MAY_MATCH.size(); ++i) {
        cr.clear();
        String url = MAY_MATCH.get(i);
        UrlValue inp = UrlValue.from(context, url);
        assertEquals(
            i + ": " + url,

            matchSet.contains(url)
            ? Classification.MATCH
            : Classification.NOT_A_MATCH,

            p.apply(inp, cr));
      }

      for (int i = 0; i < MUST_BE_INVALID.size(); ++i) {
        cr.clear();
        String url = MUST_BE_INVALID.get(i);
        UrlValue inp = UrlValue.from(context, url);
        assertEquals(
            i + ": " + url,
            Classification.INVALID,
            p.apply(inp, cr));
      }
      for (String url : matchSet) {
        cr.clear();
        assertEquals(
            url,
            Classification.MATCH,
            p.apply(UrlValue.from(context, url), cr));
      }
      cr.clear();
    } finally {
      cr.flush();
    }
  }

  private static final ImmutableList<String> MAY_MATCH = ImmutableList.of(
      // 0
      "/",
      "http://example/",
      "htTpS://example/",
      "//example.com/",
      "/",
      "/foo",
      "bar",
      "./bar",
      "blob:https://example.com/uuid",
      "http://foo.com:80/",
      // 10
      "http://foo.com:/",
      "http://foo.com:65535/",
      "http://foo.com:1/",
      "http://example.com:80/",
      "http://[3ffe:0:0:0:0:0:0:1]/",
      "http://192.168.1.1/",
      "http://192.168.1.1:1/",
      "http://localhost/",
      "http://loc%61lhost/",
      "http://localhos%74/",
      // 20
      // All of these should be equivalent.
      "https://\u4f8b/\ud83d\ude00#",
      "https://xn--fsq/%F0%9F%98%80#",
      "https://%E4%BE%8B/\ud83d\ude00#",
      // Done with equivalents.
      "//example.com.:/",
      "ssh://user@server/project.git",
      "ssh://user@sErvEr:22/project.git",
      "ssh://u%73er@server/project.git",
      "ssh://u%2573er@server/project.git",
      "ssh://u%73er@evil/project.git",
      ""
      );

  private static final ImmutableList<String> MUST_BE_INVALID = ImmutableList.of(
      "http://ex ample/",
      "http://ex%20ample/",
      "http://ex+ample/",
      "blob:file:///uuid",  // No authority.
      "http:///",
      "http://@/",
      "http://foo@/",
      "http://%@example.com/",
      "http://example.com:@/",
      "http://:/",
      "http://foo.com:65536/",
      "http://foo.com:0/",
      "http://3ffe:0:0:0:0:0:0:1/",
      "http://192.168.999.888/",
      "http://192.168.1.1.1/",
      "http:///",
      "http://loc%6lhost/",
      "http://loc%2561lhost/",
      "http://loc%lhost/",
      "http://loc%lhost/",
      "http://localhos%7/",
      "http://localhos%7",
      "http://localhos%",
      "http://localhos%/",
      "http://localhos%c0%80/"  // Non-minimal encoding
      );


  @Test
  public void testUnconfiguredClassifier() throws Exception {
    runCommonTestsWith(
        AuthorityClassifiers.builder().build(),
        UrlContext.DEFAULT);
  }

  @Test
  public void testAllowLocalhost() throws Exception {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .host("localhost")
           .build(),
        UrlContext.DEFAULT,
        "http://localhost/",
        "http://loc%61lhost/",
        "http://localhos%74/");
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .hostGlob("localhost")
           .build(),
        UrlContext.DEFAULT,
        "http://localhost/",
        "http://loc%61lhost/",
        "http://localhos%74/");
  }

  @Test
  public void testPunycodeUnicodeEquivalence() throws Exception {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .host("xn--fsq")  // Mandarin for "example"
           .build(),
        UrlContext.DEFAULT,
        "https://\u4f8b/\ud83d\ude00#",
        "https://xn--fsq/%F0%9F%98%80#",
        "https://%E4%BE%8B/\ud83d\ude00#");
  }

  @Test
  public void testSingleIntegerPortExclusion() throws Exception {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .host("example", "example.com")
           .port(443)
           .build(),
        UrlContext.DEFAULT,
        "htTpS://example/",
        "https://example.com/",
        "blob:https://example.com/uuid");
  }

  @Test
  public void testMultipleIntegerPortExclusionsOutOfOrder() throws Exception {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .host("example", "example.com")
           .port(443, 80)
           .build(),
        UrlContext.DEFAULT,
        "http://example/",
        "http://example.com:80/",
        "//example.com/",
        "//example.com.:/",
        "htTpS://example/",
        "https://example.com/",
        "blob:https://example.com/uuid");
  }

  @Test
  public void testSinglePortClassifier() throws Exception {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .host("example", "example.com")
           .port(
               new Predicate<Integer>() {

                @Override
                public boolean apply(Integer x) {
                  return x != null && x.intValue() == 443;
                }

               })
           .build(),
        UrlContext.DEFAULT,
        "htTpS://example/",
        "https://example.com/",
        "blob:https://example.com/uuid");
  }

  @Test
  public void testMultiplePortExclusion() throws Exception {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .host("example", "example.com")
           .port(443)
           .port(new Predicate<Integer>() {

            @Override
            public boolean apply(Integer port) {
              return port != null && port == 80;
            }

           })
           .build(),
        UrlContext.DEFAULT,
        "http://example/",
        "http://example.com:80/",
        "//example.com/",
        "//example.com.:/",
        "htTpS://example/",
        "https://example.com/",
        "blob:https://example.com/uuid");
  }

  @Test
  public void testUnameClassifiersAndCustomScheme() throws Exception {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
            .host("server")
            .userName(
                new Predicate<Optional<String>>() {

                  @Override
                  public boolean apply(Optional<String> uname) {
                    return uname.isPresent() && "user".equals(uname.get());
                  }

                })
            .build(),
        new UrlContext(new Absolutizer(
            new SchemeLookupTable(ImmutableList.of(
                new Scheme(
                    ImmutableSet.of("ssh"), true, 22,
                    Scheme.SchemePart.AUTHORITY, Scheme.SchemePart.PATH))),
                UrlContext.DEFAULT.absolutizer.contextUrl)),
        "ssh://user@server/project.git",
        "ssh://user@sErvEr:22/project.git",
        "ssh://u%73er@server/project.git");
  }

  @Test
  public void testUnameClassifiersWithoutCustomScheme() throws Exception {
    // URLClassifier should never pass Scheme.UNKNOWN through to
    // AuthorityClassifier, but we should stake out a sensible behavior
    // if it's used standalone.
    runCommonTestsWith(
        AuthorityClassifiers.builder()
            .host("server")
            .userName(
                new Predicate<Optional<String>>() {

                  @Override
                  public boolean apply(Optional<String> uname) {
                    return uname.isPresent() && "user".equals(uname.get());
                  }

                })
            .build(),
        UrlContext.DEFAULT,
        // ssh is a hierarchical scheme, so these particular examples work
        // out of the box.
        "ssh://user@server/project.git",
        "ssh://user@sErvEr:22/project.git",
        "ssh://u%73er@server/project.git");
  }

}
