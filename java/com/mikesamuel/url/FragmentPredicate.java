package com.mikesamuel.url;

import java.util.Arrays;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;

/** A URLPredicate that considers only the fragment portion. */
public interface FragmentPredicate extends URLPredicate {
  /**
   * A predicate that passes when applying ps in order results in a match before a
   * classification of INVALID.
   */
  public static FragmentPredicate or(FragmentPredicate... ps) {
    return or(Arrays.asList(ps));
  }

  /**
   * A predicate that passes when applying ps in order results in a match before a
   * classification of INVALID.
   */
  public static FragmentPredicate or(Iterable<? extends FragmentPredicate> ps) {
    return URLPredicateOr.<FragmentPredicate>abstractOr(
        ps,
        FragmentPredicateOr.FP_FALSE,
        FragmentPredicateOr.FP_NEW);
  }
}

final class FragmentPredicateOr
extends URLPredicateOr<FragmentPredicate> implements FragmentPredicate {

  static final FragmentPredicateOr FP_FALSE =
      new FragmentPredicateOr(ImmutableList.of());

  static final Function<ImmutableList<FragmentPredicate>, FragmentPredicate> FP_NEW =
      new Function<ImmutableList<FragmentPredicate>, FragmentPredicate>() {

        @Override
        public FragmentPredicate apply(ImmutableList<FragmentPredicate> ps) {
          return new FragmentPredicateOr(ps);
        }

      };

  FragmentPredicateOr(ImmutableList<FragmentPredicate> ps) {
    super(ps);
  }

}
