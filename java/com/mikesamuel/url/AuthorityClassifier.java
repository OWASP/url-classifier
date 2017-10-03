package com.mikesamuel.url;

import java.util.Arrays;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;

/**
 * A URL classifier that only looks at the authority
 * which normally comprises hostname:port
 */
public interface AuthorityClassifier extends URLClassifier {

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   */
  public static AuthorityClassifier or(AuthorityClassifier... cs) {
    return or(Arrays.asList(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   */
  public static AuthorityClassifier or(Iterable<? extends AuthorityClassifier> cs) {
    return URLClassifierOr.<AuthorityClassifier>abstractOr(
        cs,
        AuthorityClassifierOr.AP_FALSE,
        AuthorityClassifierOr.AP_NEW);
  }
}

final class AuthorityClassifierOr
extends URLClassifierOr<AuthorityClassifier> implements AuthorityClassifier {

  static final AuthorityClassifierOr AP_FALSE =
      new AuthorityClassifierOr(ImmutableList.of());

  static final Function<ImmutableList<AuthorityClassifier>, AuthorityClassifier> AP_NEW =
      new Function<ImmutableList<AuthorityClassifier>, AuthorityClassifier>() {

        @Override
        public AuthorityClassifier apply(ImmutableList<AuthorityClassifier> cs) {
          return new AuthorityClassifierOr(cs);
        }

      };

  AuthorityClassifierOr(ImmutableList<AuthorityClassifier> cs) {
    super(cs);
  }

}
