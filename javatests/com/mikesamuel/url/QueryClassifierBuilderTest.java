package com.mikesamuel.url;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

@SuppressWarnings({ "javadoc", "static-method" })
public class QueryClassifierBuilderTest {

  private static void runCommonTestsWith(
      QueryClassifier p,
      URLContext context,
      String... shouldMatch) {

    Diagnostic.CollectingReceiver<URLValue> cr = Diagnostic.collecting(
        TestUtil.STDERR_RECEIVER);

    ImmutableSet<String> matchSet = ImmutableSet.copyOf(shouldMatch);

    try {
      for (int i = 0; i < MAY_MATCH.size(); ++i) {
        cr.reset();
        String url = MAY_MATCH.get(i);
        assertEquals(
            i + ": " + url,

            matchSet.contains(url)
            ? Classification.MATCH
            : Classification.NOT_A_MATCH,

            p.apply(URLValue.from(context, url), cr));
      }

      for (int i = 0; i < MUST_BE_INVALID.size(); ++i) {
        cr.reset();
        String url = MUST_BE_INVALID.get(i);
        assertEquals(
            i + ": " + url,
            Classification.INVALID,
            p.apply(URLValue.from(context, url), cr));
      }
      for (String url : matchSet) {
        cr.reset();
        assertEquals(
            url,
            Classification.MATCH,
            p.apply(URLValue.from(context, url), cr));
      }
      cr.reset();
    } finally {
      cr.flush();
    }
  }

  private static final ImmutableList<String> MAY_MATCH = ImmutableList.of(
      "",
      "?",
      "?a=b&c=d",
      "?%61=%62&%63=%64",
      "?a=b%26c=d",
      "?a=b+c",
      "?a=b&&c",
      "?a=b&a=c",
      "?a=b&C=D",
      "?%3D=%3d",
      "http://foo/?foo=bar",
      "about:blank?really=no",
      "javascript:foo?a=b:x=y",
      "http://example/path&more=path",
      "?a=b?c",
      "?a=b%3fc"
      );

  private static final ImmutableList<String> MUST_BE_INVALID = ImmutableList.of(
      "http://example/?%=v",
      "http://example/?k=%"
      );


  @Test
  public void testRestrictivePolicy() throws Exception {
    runCommonTestsWith(
        QueryClassifier.builder()
            .mayHaveKeys(Predicates.alwaysFalse())
            .mustHaveKeys("NONCE")
            .build(),
        URLContext.DEFAULT);
  }

  @Test
  public void testNoKeys() throws Exception {
    runCommonTestsWith(
        QueryClassifier.builder()
            .mayHaveKeys(Predicates.alwaysFalse())
            .build(),
        URLContext.DEFAULT,
        "",
        "?",
        "javascript:foo?a=b:x=y",
        "http://example/path&more=path"
        );
  }

  @Test
  public void testAllowAllAC() throws Exception {
    runCommonTestsWith(
        QueryClassifier.builder()
            .mayHaveKeys("a", "c")
            .mustHaveKeys("a")
            .build(),
        URLContext.DEFAULT,
        "?a=b&c=d",
        "?%61=%62&%63=%64",
        "?a=b%26c=d",
        "?a=b+c",
        "?a=b&&c",
        "?a=b&a=c",
        // "?a=b&C=D",  // keys are case sensitive
        "?a=b?c",
        "?a=b%3fc"
        );
  }

  @Test
  public void testDisallowRepeatingA() throws Exception {
    runCommonTestsWith(
        QueryClassifier.builder()
            .mayHaveKeys("a", "c")
            .mayNotRepeatKeys("a")
            .mustHaveKeys("a")
            .build(),
        URLContext.DEFAULT,
        "?a=b&c=d",
        "?%61=%62&%63=%64",
        "?a=b%26c=d",
        "?a=b+c",
        "?a=b&&c",
        // "?a=b&a=c",  // a repeats
        // "?a=b&C=D",  // keys are case sensitive
        "?a=b&c=d&c=e",
        "?a=b?c",
        "?a=b%3fc"
        );
  }

  @Test
  public void testValueDecoding() throws Exception {
    runCommonTestsWith(
        QueryClassifier.builder()
            .mustHaveKeys("a", "c")
            .valueMustMatch("a", hasValue("b"))
            .valueMustMatch("c", hasValue("d"))
            .build(),
        URLContext.DEFAULT,
        "?a=b&c=d",
        "?%61=%62&%63=%64"
        //"?a=b%26c=d",  // No key c
        // "?a=b+c",  // No key c
        // "?a=b&&c",   // Value is not d
        // "?a=b&a=c"  // No key c
        );
  }

  @Test
  public void testEncodedAmp() throws Exception {
    runCommonTestsWith(
        QueryClassifier.builder()
            .mustHaveKeys("a")
            .valueMustMatch("a", hasValue("b&c=d"))
            .build(),
        URLContext.DEFAULT,
        "?a=b%26c=d"
        );
  }

  @Test
  public void testEncodedMetas() throws Exception {
    runCommonTestsWith(
        QueryClassifier.builder()
            .mustHaveKeys("a")
            .valueMustMatch("a", hasValue("b&c=d"))
            .build(),
        URLContext.DEFAULT,
        "?a=b%26c=d"
        );
  }

  @Test
  public void testAboutSchemeFindsQuery() throws Exception {
    runCommonTestsWith(
        QueryClassifier.builder()
            .mayHaveKeys("really")
            .mustHaveKeys("really")
            .build(),
        URLContext.DEFAULT,
        "about:blank?really=no"
        );
  }

  @Test
  public void testEq() throws Exception {
    runCommonTestsWith(
        QueryClassifier.builder()
            .mustHaveKeys("=")
            .valueMustMatch("=", hasValue("="))
            .build(),
        URLContext.DEFAULT,
        "?%3D=%3d"
        );
  }

  @Test
  public void testQmarkInValue() throws Exception {
    runCommonTestsWith(
        QueryClassifier.builder()
            .mustHaveKeys("a")
            .valueMustMatch("a", hasValue("b?c"))
            .build(),
        URLContext.DEFAULT,
        "?a=b?c",
        "?a=b%3fc"
        );
  }

  @Test
  public void testSpaceInValue() throws Exception {
    runCommonTestsWith(
        QueryClassifier.builder()
            .mustHaveKeys("a")
            .valueMustMatch("a", hasValue("b c"))
            .build(),
        URLContext.DEFAULT,
        "?a=b+c"
        );
  }


  private static Predicate<Optional<String>> hasValue(String want) {
    return new Predicate<Optional<String>>() {

      @Override
      public boolean apply(Optional<String> got) {
        return got.isPresent() && want.contentEquals(got.get());
      }

    };
  }
}
