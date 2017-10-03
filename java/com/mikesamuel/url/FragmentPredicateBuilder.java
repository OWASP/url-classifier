package com.mikesamuel.url;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;

/**
 * Builds a predicate over the fragment content excluding the '#'.
 * An absent fragment is equivalent to the empty fragment per RFC 3986.
 */
public final class FragmentPredicateBuilder {
  private URLPredicate asRelativeUrlPred;
  private Predicate<? super Optional<String>> fragmentPred;

  static final URLPredicate MATCH_NO_URLS = URLPredicate.or();

  private FragmentPredicateBuilder() {
    // Use static factory
  }

  /** A new blank builder. */
  public static FragmentPredicateBuilder builder() {
    return new FragmentPredicateBuilder();
  }

  /**
   * Builds a predicate based on previous allow/match decisions.
   * This may be reused after a call to build and subsequent calls to
   * allow/match methods will not affect previously built predicates.
   */
  public FragmentPredicate build() {
    Predicate<? super Optional<String>> fragmentPredicate = this.fragmentPred;
    URLPredicate asRelativeUrlPredicate = this.asRelativeUrlPred;
    if (fragmentPredicate == null) {
      fragmentPredicate = Predicates.alwaysFalse();
    }
    if (asRelativeUrlPredicate == null) {
      asRelativeUrlPredicate = MATCH_NO_URLS;
    }
    return new FragmentPredicateImpl(fragmentPredicate, asRelativeUrlPredicate);
  }

  /**
   * If there is no fragment then p will receive the absent optional.
   * If there is a fragment then p will receive it with the leading "#".
   * RFC 3986 says
   * <blockquote>
   *    two URIs that differ only by the suffix "#" are considered
   *    different regardless of the scheme.
   * </blockquote>
   */
  public FragmentPredicateBuilder matches(Predicate<? super Optional<String>> p) {
    this.fragmentPred = this.fragmentPred == null
        ? p
        : Predicates.or(this.fragmentPred, p);
    return this;
  }

  /**
   * It's not uncommon for single-page applications to embed a path in a query.
   * URLs will match when there is a fragment whose content (sans "#") parses
   * as a relative URL that matches p in the context of
   * http://[special-unkown-host]/
   *
   * <p>By "relative," we mean not absolute per RFC 3986.  An absolute path is
   * still a relatvie URL by this scheme since it specifies no scheme.
   *
   * <p>This requires that the fragment will be present, so to allow
   * no fragment OR the fragments described above, use FragmentPredicate.or(...).
   */
  public FragmentPredicateBuilder matchFragmentAsIfRelativeURL(URLPredicate p) {
    this.asRelativeUrlPred = this.asRelativeUrlPred == null
        ? p
        : URLPredicate.or(this.asRelativeUrlPred, p);
    return this;
  }
}

final class FragmentPredicateImpl implements FragmentPredicate {
  final Predicate<? super Optional<String>> fragmentPredicate;
  final URLPredicate asRelativeUrlPredicate;

  FragmentPredicateImpl(
      Predicate<? super Optional<String>> fragmentPredicate,
      URLPredicate asRelativeUrlPredicate) {
    this.fragmentPredicate = Preconditions.checkNotNull(fragmentPredicate);
    this.asRelativeUrlPredicate = Preconditions.checkNotNull(asRelativeUrlPredicate);
  }

  @Override
  public Classification apply(URLValue x) {
    String fragment = x.getFragment();
    Classification result = Classification.NOT_A_MATCH;
    Optional<String> fragmentOpt = Optional.fromNullable(fragment);
    if (this.fragmentPredicate.apply(fragmentOpt)) {
      result = Classification.MATCH;
    }
    if (fragment != null
        && result == Classification.NOT_A_MATCH
        && !FragmentPredicateBuilder.MATCH_NO_URLS.equals(
            this.asRelativeUrlPredicate)) {
      URLValue fragmentUrl = URLValue.of(
          // Explicitly do not use x's path.
          URLContext.DEFAULT, fragment.substring(1));
      switch (this.asRelativeUrlPredicate.apply(fragmentUrl)) {
        case INVALID:
          return Classification.INVALID;
        case MATCH:
          result = Classification.MATCH;
          break;
        case NOT_A_MATCH:
          break;
      }
    }
    return result;
  }

}