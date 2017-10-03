package com.mikesamuel.url;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.base.Predicates;

@SuppressWarnings({ "javadoc", "static-method" })
public final class FragmentPredicateBuilderTest {

  private static void assertFragmentClassification(
      Classification want, String inputUrl, FragmentPredicate p) {
    Classification got = p.apply(URLValue.of(URLContext.DEFAULT, inputUrl));
    assertEquals(inputUrl, want, got);
  }

  @Test
  public void testNoFragment() {
    for (String inputUrl
         : new String[] { "", "/foo", "mailto:you@example.com" }) {
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentPredicateBuilder.builder().build());
      assertFragmentClassification(
          Classification.MATCH,
          inputUrl,
          FragmentPredicateBuilder.builder()
              .matches(Predicates.equalTo(Optional.<String>absent()))
              .build());
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentPredicateBuilder.builder()
              .matches(Predicates.equalTo(Optional.of("#foo")))
              .build());
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentPredicateBuilder.builder()
              .matchFragmentAsIfRelativeURL(
                  new URLPredicate() {

                    @Override
                    public Classification apply(URLValue x) {
                      return Classification.MATCH;
                    }

                  })
              .build());
    }
  }

  @Test
  public void testSimpleFragment() {
    for (String inputUrl
         : new String[] { "#foo", "/bar#foo", "mailto:you@example.com#foo" }) {
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentPredicateBuilder.builder().build());
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentPredicateBuilder.builder()
              .matches(Predicates.equalTo(Optional.<String>absent()))
              .build());
      assertFragmentClassification(
          Classification.MATCH,
          inputUrl,
          FragmentPredicateBuilder.builder()
              .matches(Predicates.equalTo(Optional.of("#foo")))
              .build());
      assertFragmentClassification(
          Classification.MATCH,
          inputUrl,
          FragmentPredicateBuilder.builder()
              .matchFragmentAsIfRelativeURL(
                  new URLPredicate() {

                    @Override
                    public Classification apply(URLValue x) {
                      assertEquals(
                          "http://example.org./foo", x.urlText);
                      assertTrue(x.inheritsPlaceholderAuthority);
                      return Classification.MATCH;
                    }

                  })
              .build());
    }
  }

  @Test
  public void testComplexFragment() {
    for (String inputUrl : new String[] {
            "#foo/../bar/baz",
            "/boo#foo/../bar/baz",
            "mailto:you@example.com#foo/../bar/baz",
         }) {
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentPredicateBuilder.builder().build());
      assertFragmentClassification(
          Classification.NOT_A_MATCH,
          inputUrl,
          FragmentPredicateBuilder.builder()
              .matches(Predicates.equalTo(Optional.<String>absent()))
              .build());
      assertFragmentClassification(
          Classification.MATCH,
          inputUrl,
          FragmentPredicateBuilder.builder()
              .matches(Predicates.equalTo(Optional.of("#foo/../bar/baz")))
              .build());
      assertFragmentClassification(
          Classification.MATCH,
          inputUrl,
          FragmentPredicateBuilder.builder()
              .matchFragmentAsIfRelativeURL(
                  new URLPredicate() {

                    @Override
                    public Classification apply(URLValue x) {
                      return x.getPath().equals("/bar/baz")
                          ? Classification.MATCH
                          : Classification.NOT_A_MATCH;
                    }

                  })
              .build());
    }
  }
}
