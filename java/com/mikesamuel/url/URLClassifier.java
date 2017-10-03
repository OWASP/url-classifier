package com.mikesamuel.url;

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

/**
 * A classifier over URL inputs.
 */
public interface URLClassifier extends Function<URLValue, Classification> {
  /** Classifies the URL as matching, not matching or structurally invalid. */
  @Override
  Classification apply(URLValue x);

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   */
  public static URLClassifier or(URLClassifier... cs) {
    return or(ImmutableList.copyOf(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
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
  public Classification apply(URLValue x) {
    Classification result = Classification.MATCH;
    for (C c : cs) {
      Classification cl = c.apply(x);
      switch (cl) {
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
