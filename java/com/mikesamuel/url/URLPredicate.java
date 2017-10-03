package com.mikesamuel.url;

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

/**
 * A predicate over URL inputs.
 */
public interface URLPredicate extends Function<URLValue, Classification> {
  /** Classifies the URL as matching, not matching or structurally invalid. */
  @Override
  Classification apply(URLValue x);

  /**
   * A predicate that passes when applying ps in order results in a match before a
   * classification of INVALID.
   */
  public static URLPredicate or(URLPredicate... ps) {
    return or(ImmutableList.copyOf(ps));
  }

  /**
   * A predicate that passes when applying ps in order results in a match before a
   * classification of INVALID.
   */
  public static URLPredicate or(Iterable<? extends URLPredicate> ps) {
    return URLPredicateOr.<URLPredicate>abstractOr(
        ps,
        URLPredicateOr.UP_FALSE,
        URLPredicateOr.UP_NEW);
  }
}

class URLPredicateOr<P extends URLPredicate> implements URLPredicate {
  @Override
  public final int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((ps == null) ? 0 : ps.hashCode());
    return result;
  }

  @Override
  public final boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    URLPredicateOr<?> other = (URLPredicateOr<?>) obj;
    if (ps == null) {
      if (other.ps != null) {
        return false;
      }
    } else if (!ps.equals(other.ps)) {
      return false;
    }
    return true;
  }

  final ImmutableList<P> ps;

  static final URLPredicateOr<URLPredicate> UP_FALSE =
      new URLPredicateOr<>(ImmutableList.of());

  static final Function<ImmutableList<URLPredicate>, URLPredicate> UP_NEW =
      new Function<ImmutableList<URLPredicate>, URLPredicate>() {

        @Override
        public URLPredicate apply(ImmutableList<URLPredicate> ps) {
          return new URLPredicateOr<>(ps);
        }

      };


  URLPredicateOr(ImmutableList<P> ps) {
    this.ps = ps;
  }

  @Override
  public Classification apply(URLValue x) {
    Classification result = Classification.MATCH;
    for (P p : ps) {
      Classification c = p.apply(x);
      switch (c) {
        case INVALID:
          result = Classification.INVALID;
          continue;
        case MATCH:
          return Classification.MATCH;
        case NOT_A_MATCH:
          continue;
      }
      throw new AssertionError(c);
    }
    return result;
  }

  @SuppressWarnings("unchecked")
  static <P extends URLPredicate>
  P abstractOr(
      Iterable<? extends P> ps, P zero,
      Function<ImmutableList<P>, P> maker) {
    ImmutableList.Builder<P> b = ImmutableList.builder();
    for (P p : ps) {
      if (p instanceof URLPredicateOr<?>) {
        // Unsound except by convention that
        // URLPredicate<P> instanceof P
        b.addAll(((URLPredicateOr<P>) p).ps);
      } else {
        b.add(p);
      }
    }
    ImmutableList<P> plist = b.build();

    P result;
    switch (plist.size()) {
      case 0:
        result = zero;
        break;
      case 1:
        result = plist.get(0);
        break;
      default:
        result = maker.apply(plist);
        break;
    }
    return Preconditions.checkNotNull(result);
  }
}
