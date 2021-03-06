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

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;


@SuppressWarnings({ "javadoc", "static-method" })
public final class AuthorityClassifierBuilderTest {

  private static final UrlContext TEST_URL_CONTEXT = new UrlContext(new Absolutizer(
      new SchemeLookupTable(ImmutableList.of(
          new Scheme(
              ImmutableSet.of("ssh"), true, 22,
              Scheme.SchemePart.AUTHORITY, Scheme.SchemePart.PATH,
              Scheme.SchemePart.USERINFO))),
          UrlContext.DEFAULT.absolutizer.contextUrl));

  private static void runCommonTestsWith(
      AuthorityClassifier p,
      String... shouldMatch) {

    ImmutableList<String> matches = ImmutableList.copyOf(shouldMatch);
    Set<String> notMatchSet = Sets.newLinkedHashSet(MAY_MATCH);
    notMatchSet.removeAll(matches);
    ImmutableList<String> notMatches = ImmutableList.copyOf(notMatchSet);

    ImmutableMap<Classification, ImmutableList<String>> inputs =
        ImmutableMap.of(
            Classification.INVALID, MUST_BE_INVALID,
            Classification.MATCH, matches,
            Classification.NOT_A_MATCH, notMatches);

    runTests(p, inputs);
  }

  private static void runTests(
      AuthorityClassifier p,
      ImmutableMap<Classification, ImmutableList<String>> inputs) {

    Diagnostic.CollectingReceiver<UrlValue> cr = Diagnostic.CollectingReceiver.from(
        TestUtil.STDERR_RECEIVER);

    try {
      for (Map.Entry<Classification, ImmutableList<String>> e
          : inputs.entrySet()) {
        Classification want = e.getKey();
        ImmutableList<String> inputList = e.getValue();
        for (int i = 0; i < inputList.size(); ++i) {
          cr.clear();
          String url = inputList.get(i);
          UrlValue inp = UrlValue.from(TEST_URL_CONTEXT, url);
          Classification got = p.apply(inp, cr);
          assertEquals(i + ": " + url, want, got);
        }
        cr.clear();
      }
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
      "http://example.com:8000/",
      "http://[3ffe:0:0:0:0:0:0:1]/",
      "http://192.168.1.1/",
      "http://192.168.1.1:1/",
      "http://localhost/",
      "http://loc%61lhost/",
      // 20
      "http://localhos%74/",
      // All of these should be equivalent.
      "https://\u4f8b/\ud83d\ude00#",
      "https://xn--fsq/%F0%9F%98%80#",
      "https://%E4%BE%8B/\ud83d\ude00#",
      // Done with equivalents.
      "//example.com.:/",
      // Username with a scheme that allows it.
      "ssh://user@server/project.git",
      "ssh://user@sErvEr:22/project.git",
      "ssh://u%73er@server/project.git",
      "ssh://u%2573er@server/project.git",
      // 30
      "ssh://u%73er@evil/project.git",
      "ssh://other@server/project.git",
      "ssh://USER@server/project.git",
      "file://foo@127.0.0.1/bar",
      "",
      "data:text/plain,Hello%20World!"
      );

  private static final ImmutableList<String> MUST_BE_INVALID = ImmutableList.of(
      "http://ex ample/",
      "http://ex%20ample/",
      "http://ex+ample/",
      "blob:file:///uuid",  // No authority.
      "http:///",
      "http://@/",
      "http://0/",
      "http://foo@/",
      "http://foo@bar@baz.com/",
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
      "http://localhos%c0%80/",  // Non-minimal encoding
      // https://tools.ietf.org/html/rfc7230#section-2.7.1 says
      //    A sender MUST NOT generate the userinfo subcomponent (and its "@"
      //    delimiter) when an "http" URI reference is generated within a
      //    message as a request target or header field value.
      "//@example.com/",
      "https://@example.com/",
      "ssh://USER:pwd@server/project.git"
      );


  @Test
  public void testUnconfiguredClassifier() {
    runCommonTestsWith(
        AuthorityClassifiers.builder().build());
  }

  @Test
  public void testOneHost() {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
        .host("example.com")
        .build(),
        "//example.com/",
        "blob:https://example.com/uuid",
        "http://example.com:80/",
        "http://example.com:8000/",
        "//example.com.:/"
        );
    runCommonTestsWith(
        AuthorityClassifiers.builder()
        .host(InternetDomainName.from("example.com"))
        .build(),
        "//example.com/",
        "blob:https://example.com/uuid",
        "http://example.com:80/",
        "http://example.com:8000/",
        "//example.com.:/"
        );
  }

  @Test
  public void testOneIpv4() {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
        .host(InetAddresses.forUriString("127.0.0.1"))
        .build(),
        // Localhost does not show here because we do not assume
        // localhost == 127.0.0.1 or resolve hostnames.
        "file://foo@127.0.0.1/bar"
        );
    runCommonTestsWith(
        AuthorityClassifiers.builder()
        .host((Inet4Address) InetAddresses.forUriString("127.0.0.1"))
        .build(),
        "file://foo@127.0.0.1/bar"
        );
  }

  @Test
  public void testOneIpv6() {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
        .host(InetAddresses.forUriString("[3ffe:0:0:0:0:0:0:1]"))
        .build(),
        "http://[3ffe:0:0:0:0:0:0:1]/"
        );
    runCommonTestsWith(
        AuthorityClassifiers.builder()
        .host((Inet6Address) InetAddresses.forUriString("[3ffe:0:0:0:0:0:0:1]"))
        .build(),
        "http://[3ffe:0:0:0:0:0:0:1]/"
        );
  }


  @Test
  public void testAllowLocalhost() {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .host("localhost")
           .build(),
        "http://localhost/",
        "http://loc%61lhost/",
        "http://localhos%74/",
        "file://localhost/");
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .hostGlob("localhost")
           .build(),
        "http://localhost/",
        "http://loc%61lhost/",
        "http://localhos%74/",
        "file://localhost/");
  }

  @Test
  public void testPunycodeUnicodeEquivalence() {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .host("xn--fsq")  // Mandarin for "example"
           .build(),
        "https://\u4f8b/\ud83d\ude00#",
        "https://xn--fsq/%F0%9F%98%80#",
        "https://%E4%BE%8B/\ud83d\ude00#");
  }

  @Test
  public void testSingleIntegerPortExclusion() {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .host("example", "example.com")
           .port(443)
           .build(),
        "htTpS://example/",
        "https://example.com/",
        "blob:https://example.com/uuid");
  }

  @Test
  public void testMultipleIntegerPortExclusionsOutOfOrder() {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .host("example", "example.com")
           .port(443, 80)
           .build(),
        "http://example/",
        "http://example.com:80/",
        "//example.com/",
        "//example.com.:/",
        "htTpS://example/",
        "https://example.com/",
        "blob:https://example.com/uuid");
    runCommonTestsWith(
        AuthorityClassifiers.builder()
           .host("example", "example.com")
           .port(80)
           .port(443)
           .build(),
        "http://example/",
        "http://example.com:80/",
        "//example.com/",
        "//example.com.:/",
        "htTpS://example/",
        "https://example.com/",
        "blob:https://example.com/uuid");
  }

  @Test
  public void testSinglePortClassifier() {
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
        "htTpS://example/",
        "https://example.com/",
        "blob:https://example.com/uuid");
  }

  @Test
  public void testMultiplePortExclusion() {
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
        "http://example/",
        "http://example.com:80/",
        "//example.com/",
        "//example.com.:/",
        "htTpS://example/",
        "https://example.com/",
        "blob:https://example.com/uuid");
  }

  @Test
  public void testUnameClassifiersAndCustomScheme() {
    runCommonTestsWith(
        AuthorityClassifiers.builder()
            .host("server")
            .userInfo(
                UserInfoClassifiers.and(
                    UserInfoClassifiers.NO_PASSWORD_BUT_USERNAME_IF_ALLOWED_BY_SCHEME,
                    new UserInfoClassifier() {

                      @Override
                      public Classification apply(
                          UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
                        Authority auth = x.getAuthority(r);
                        return auth != null && auth.userName.isPresent()
                            && "user".equals(auth.userName.get())
                            ? Classification.MATCH
                                : Classification.NOT_A_MATCH;
                      }

                    }))
            .build(),
        "ssh://user@server/project.git",
        "ssh://user@sErvEr:22/project.git",
        "ssh://u%73er@server/project.git");
  }

  @Test
  public void testUnameClassifiersWithoutCustomScheme() {
    // URLClassifier should never pass Scheme.UNKNOWN through to
    // AuthorityClassifier, but we should stake out a sensible behavior
    // if it's used standalone.
    runCommonTestsWith(
        AuthorityClassifiers.builder()
            .host("server")
            .userInfo(
                UserInfoClassifiers.and(
                    UserInfoClassifiers.NO_PASSWORD_BUT_USERNAME_IF_ALLOWED_BY_SCHEME,
                    new UserInfoClassifier() {

                      @Override
                      public Classification apply(
                          UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
                        Authority auth = x.getAuthority(r);
                        return auth != null && auth.userName.isPresent()
                            && "user".equals(auth.userName.get())
                            ? Classification.MATCH
                                : Classification.NOT_A_MATCH;
                      }

                    }))
            .build(),
        // ssh is a hierarchical scheme, so these particular examples work
        // out of the box.
        "ssh://user@server/project.git",
        "ssh://user@sErvEr:22/project.git",
        "ssh://u%73er@server/project.git");
  }

  @Test
  public void testStarStarHostGlobs() {
    runTests(
        AuthorityClassifiers.builder()
        .hostGlob("**.foo.com", "**.bar.*")
        .build(),
        ImmutableMap.of(
            Classification.NOT_A_MATCH,
            ImmutableList.of("//foo.org", "//bar.unknown", "//baz.com",
                "//bar.foo.org"),
            Classification.MATCH,
            ImmutableList.of(
                "//foo.com", "//a.foo.com", "//a.b.foo.com",
                "//bar.com", "//bar.org", "//bar.co.uk",
                "//a.bar.com", "//a.b.bar.com"
                )
            ));
  }

  @Test
  public void testAnyHostGlob() {
    runTests(
        AuthorityClassifiers.builder()
        .hostGlob("**", "**.bar.*")
        .build(),
        ImmutableMap.of(
            Classification.MATCH,
            ImmutableList.of(
                "//foo.org", "//bar.unknown", "//baz.com",
                "//bar.foo.org",
                "//foo.com", "//a.foo.com", "//a.b.foo.com",
                "//bar.com", "//bar.org", "//bar.co.uk",
                "//a.bar.com", "//a.b.bar.com"
                )
            ));
  }

  @Test
  public void testStarOnlyHostGlobs() {
    runTests(
        AuthorityClassifiers.builder()
        .hostGlob("**.*")
        .build(),
        ImmutableMap.of(
            Classification.NOT_A_MATCH,
            ImmutableList.of("//bar.unknown"),
            Classification.MATCH,
            ImmutableList.of(
                "//foo.org", "//baz.com", "//bar.foo.org",
                "//foo.com", "//a.foo.com", "//a.b.foo.com",
                "//bar.com", "//bar.org", "//bar.co.uk",
                "//a.bar.com", "//a.b.bar.com"
                )
            ));
    runTests(
        AuthorityClassifiers.builder()
        .hostGlob("*.*")
        .build(),
        ImmutableMap.of(
            Classification.NOT_A_MATCH,
            ImmutableList.of(
                "//bar.unknown",
                "//a.foo.com", "//a.b.foo.com",
                "//a.bar.com", "//a.b.bar.com",
                "//bar.foo.org"),
            Classification.MATCH,
            ImmutableList.of(
                "//foo.org", "//baz.com",
                "//foo.com", "//bar.com", "//bar.org", "//bar.co.uk"
                )
            ));
  }

  @Test
  public void testTheOnlyDotIsDot() {
    AuthorityClassifier c = AuthorityClassifiers.builder()
        .host("a.b", "127.0.0.1", "[3ffe:0:0:0:0:0:0:1]")
        .build();
    for (String[] urlTemplateAndValidSubst : new String[][] {
      { "http://a%sb", "." },
      { "http://a.%s", "b", "B" },
      { "http://127%s0.0.1/", "." },
      { "http://127.0.%s.1/", "0" },
      { "http://%s27.0.0.1/", "1" },
      { "http://1%s7.0.0.1/", "2" },
      { "http://12%s.0.0.1/", "7" },
      { "http://%s3ffe:0:0:0:0:0:0:1]/", "[" },
      { "http://[3ffe%s0:0:0:0:0:0:1]/", ":" },
      { "http://[3ffe:0:0:0:0:0:%s:1]/", "", "0" },
      { "http://[3ffe:0:0:0:0:0:0:1%s/", "]" },
    }) {
      String urlTemplate = urlTemplateAndValidSubst[0];
      Set<String> allowed = ImmutableSet.copyOf(
          Arrays.asList(urlTemplateAndValidSubst)
          .subList(1, urlTemplateAndValidSubst.length));
      for (int i = -1; i <= 0x101ff; ++i) {
        String replacement = i < 0
            ? ""
            : new StringBuilder().appendCodePoint(i).toString();
        UrlValue x = UrlValue.from(urlTemplate.replace("%s", replacement));
        Classification got = c.apply(x, Diagnostic.Receiver.NULL);
        try {
        assertEquals(
            "U+" + Integer.toString(i, 16) + " : " + x.originalUrlText,
            allowed.contains(replacement),
            got == Classification.MATCH);
        } catch (Error e) {
          System.err.println("urlTemplate=" + urlTemplate + ", allowed=" + allowed);
          throw e;
        }
      }
    }
  }

}
