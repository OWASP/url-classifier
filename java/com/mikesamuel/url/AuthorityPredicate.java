package com.mikesamuel.url;

import java.util.Arrays;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;

/**
 * A URL predicate that only looks at the authority
 * which normally comprises hostname:port
 */
public interface AuthorityPredicate extends URLPredicate {

  /**
   * A predicate that passes when applying ps in order results in a match before a
   * classification of INVALID.
   */
  public static AuthorityPredicate or(AuthorityPredicate... ps) {
    return or(Arrays.asList(ps));
  }

  /**
   * A predicate that passes when applying ps in order results in a match before a
   * classification of INVALID.
   */
  public static AuthorityPredicate or(Iterable<? extends AuthorityPredicate> ps) {
    return URLPredicateOr.<AuthorityPredicate>abstractOr(
        ps,
        AuthorityPredicateOr.AP_FALSE,
        AuthorityPredicateOr.AP_NEW);
  }
}

final class AuthorityPredicateOr
extends URLPredicateOr<AuthorityPredicate> implements AuthorityPredicate {

  static final AuthorityPredicateOr AP_FALSE =
      new AuthorityPredicateOr(ImmutableList.of());

  static final Function<ImmutableList<AuthorityPredicate>, AuthorityPredicate> AP_NEW =
      new Function<ImmutableList<AuthorityPredicate>, AuthorityPredicate>() {

        @Override
        public AuthorityPredicate apply(ImmutableList<AuthorityPredicate> ps) {
          return new AuthorityPredicateOr(ps);
        }

      };

  AuthorityPredicateOr(ImmutableList<AuthorityPredicate> ps) {
    super(ps);
  }

}
