package org.owasp.url;

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

/**
 * Classifies {@linkplain URLValue URLs} as
 * {@linkplain Classification matching, not matching, or invalid}.
 */
public interface URLClassifier {

  /**
   * Classifies the URL as matching, not matching or structurally invalid.
   *
   * @param x the URL to classify.
   * @param r receives any notifications about why x did not match or was invalid.
   *     Pass {@link Diagnostic.Receiver#NULL} if you only need the result.
   * @return the classification of x
   */
  public Classification apply(URLValue x, Diagnostic.Receiver<? super URLValue> r);

  /** A new blank builder. */
  public static URLClassifierBuilder builder() {
    return new URLClassifierBuilder();
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static URLClassifier or(URLClassifier... cs) {
    return or(ImmutableList.copyOf(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static URLClassifier or(Iterable<? extends URLClassifier> cs) {
    return URLClassifierOr.<URLClassifier>abstractOr(
        cs,
        URLClassifierOr.UP_FALSE,
        URLClassifierOr.UP_NEW);
  }
}

class URLClassifierOr<C extends URLClassifier> implements URLClassifier {
  final ImmutableList<C> cs;

  static final URLClassifierOr<URLClassifier> UP_FALSE =
      new URLClassifierOr<>(ImmutableList.of());

  static final Function<ImmutableList<URLClassifier>, URLClassifier> UP_NEW =
      new Function<ImmutableList<URLClassifier>, URLClassifier>() {

        @Override
        public URLClassifier apply(ImmutableList<URLClassifier> cs) {
          return new URLClassifierOr<>(cs);
        }

      };


  URLClassifierOr(ImmutableList<C> cs) {
    this.cs = cs;
  }

  @Override
  public Classification apply(URLValue x, Diagnostic.Receiver<? super URLValue> r) {
    if (!cs.isEmpty()) {
      Diagnostic.CollectingReceiver<? super URLValue> delayedR = Diagnostic.collecting(r);
      for (C c : cs) {
        Classification cl = c.apply(x, delayedR);
        switch (cl) {
          case INVALID:
            delayedR.flush();
            return Classification.INVALID;
          case MATCH:
            return Classification.MATCH;
          case NOT_A_MATCH:
            continue;
        }
        throw new AssertionError(c);
      }
      delayedR.flush();
    }
    return Classification.NOT_A_MATCH;
  }

  @SuppressWarnings("unchecked")
  static <C extends URLClassifier>
  C abstractOr(
      Iterable<? extends C> cs, C zero,
      Function<ImmutableList<C>, C> maker) {
    ImmutableList.Builder<C> b = ImmutableList.builder();
    for (C c : cs) {
      if (c instanceof URLClassifierOr<?>) {
        // Unsound except by convention that
        // URLClassifier<C> instanceof C
        b.addAll(((URLClassifierOr<C>) c).cs);
      } else {
        b.add(c);
      }
    }
    ImmutableList<C> clist = b.build();

    C result;
    switch (clist.size()) {
      case 0:
        result = zero;
        break;
      case 1:
        result = clist.get(0);
        break;
      default:
        result = maker.apply(clist);
        break;
    }
    return Preconditions.checkNotNull(result);
  }

  @Override
  public final int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((cs == null) ? 0 : cs.hashCode());
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
    URLClassifierOr<?> other = (URLClassifierOr<?>) obj;
    if (cs == null) {
      if (other.cs != null) {
        return false;
      }
    } else if (!cs.equals(other.cs)) {
      return false;
    }
    return true;
  }
}
