package com.mikesamuel.url;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;


@SuppressWarnings({ "javadoc", "static-method" })
public final class AuthorityClassifierBuilderTest {

  private static void runCommonTestsWith(
      AuthorityClassifier p,
      URLContext context,
      String... shouldMatch) {
    ImmutableSet<String> matchSet = ImmutableSet.copyOf(shouldMatch);

    for (int i = 0; i < MAY_MATCH.size(); ++i) {
      String url = MAY_MATCH.get(i);
      URLValue inp = URLValue.from(context, url);
      assertEquals(
          i + ": " + url,

          matchSet.contains(url)
          ? Classification.MATCH
          : Classification.NOT_A_MATCH,

          p.apply(inp));
    }

    for (int i = 0; i < MUST_BE_INVALID.size(); ++i) {
      String url = MUST_BE_INVALID.get(i);
      URLValue inp = URLValue.from(context, url);
      assertEquals(
          i + ": " + url,
          Classification.INVALID,
          p.apply(inp));
    }
    for (String url : matchSet) {
      assertEquals(
          url,
          Classification.MATCH,
          p.apply(URLValue.from(context, url)));
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
        AuthorityClassifier.builder().build(),
        URLContext.DEFAULT);
  }

  @Test
  public void testAllowLocalhost() throws Exception {
    runCommonTestsWith(
        AuthorityClassifier.builder()
           .matchesHosts("localhost")
           .build(),
        URLContext.DEFAULT,
        "http://localhost/",
        "http://loc%61lhost/",
        "http://localhos%74/");
    runCommonTestsWith(
        AuthorityClassifier.builder()
           .matchesHostGlob("localhost")
           .build(),
        URLContext.DEFAULT,
        "http://localhost/",
        "http://loc%61lhost/",
        "http://localhos%74/");
  }

  @Test
  public void testPunycodeUnicodeEquivalence() throws Exception {
    runCommonTestsWith(
        AuthorityClassifier.builder()
           .matchesHosts("xn--fsq")  // Mandarin for "example"
           .build(),
        URLContext.DEFAULT,
        "https://\u4f8b/\ud83d\ude00#",
        "https://xn--fsq/%F0%9F%98%80#",
        "https://%E4%BE%8B/\ud83d\ude00#");
  }

  @Test
  public void testSingleIntegerPortExclusion() throws Exception {
    runCommonTestsWith(
        AuthorityClassifier.builder()
           .matchesHosts("example", "example.com")
           .matchesPort(443)
           .build(),
        URLContext.DEFAULT,
        "htTpS://example/",
        "https://example.com/",
        "blob:https://example.com/uuid");
  }

  @Test
  public void testMultipleIntegerPortExclusionsOutOfOrder() throws Exception {
    runCommonTestsWith(
        AuthorityClassifier.builder()
           .matchesHosts("example", "example.com")
           .matchesPort(443, 80)
           .build(),
        URLContext.DEFAULT,
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
        AuthorityClassifier.builder()
           .matchesHosts("example", "example.com")
           .matchesPort(
               new Predicate<Integer>() {

                @Override
                public boolean apply(Integer x) {
                  return x != null && x.intValue() == 443;
                }

               })
           .build(),
        URLContext.DEFAULT,
        "htTpS://example/",
        "https://example.com/",
        "blob:https://example.com/uuid");
  }

  @Test
  public void testMultiplePortExclusion() throws Exception {
    runCommonTestsWith(
        AuthorityClassifier.builder()
           .matchesHosts("example", "example.com")
           .matchesPort(443)
           .matchesPort(new Predicate<Integer>() {

            @Override
            public boolean apply(Integer port) {
              return port != null && port == 80;
            }

           })
           .build(),
        URLContext.DEFAULT,
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
        AuthorityClassifier.builder()
            .matchesHosts("server")
            .matchesUserName(
                new Predicate<CharSequence>() {

                  @Override
                  public boolean apply(CharSequence uname) {
                    return uname != null && "user".contentEquals(uname);
                  }

                })
            .build(),
        new URLContext(new Absolutizer(
            new SchemeLookupTable(ImmutableList.of(
                new Scheme(
                    ImmutableSet.of("ssh"), true, 22,
                    Scheme.SchemePart.AUTHORITY, Scheme.SchemePart.PATH))),
                URLContext.DEFAULT.absolutizer.contextUrl)),
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
        AuthorityClassifier.builder()
            .matchesHosts("server")
            .matchesUserName(
                new Predicate<CharSequence>() {

                  @Override
                  public boolean apply(CharSequence uname) {
                    return uname != null && "user".contentEquals(uname);
                  }

                })
            .build(),
        URLContext.DEFAULT,
        // ssh is a hierarchical scheme, so these particular examples work
        // out of the box.
        "ssh://user@server/project.git",
        "ssh://user@sErvEr:22/project.git",
        "ssh://u%73er@server/project.git");
  }

}
