package com.mikesamuel.url;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;

/** A URLClassifier that considers only the query portion. */
public interface QueryClassifier extends URLClassifier {
  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   */
  public static QueryClassifier or(QueryClassifier... cs) {
    return or(ImmutableList.copyOf(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   */
  public static QueryClassifier or(Iterable<? extends QueryClassifier> cs) {
    return URLClassifierOr.<QueryClassifier>abstractOr(
      cs,
      QueryClassifierOr.QP_FALSE,
      QueryClassifierOr.QP_NEW);
  }

  /** A classifier that matches all inputs. */
  public static QueryClassifier any() {
    return AnyQueryClassifier.INSTANCE;
  }
}

final class AnyQueryClassifier implements QueryClassifier {
  static final AnyQueryClassifier INSTANCE = new AnyQueryClassifier();

  @Override
  public Classification apply(URLValue x) {
    return Classification.MATCH;
  }
}

final class QueryClassifierOr
extends URLClassifierOr<QueryClassifier> implements QueryClassifier {

  static final QueryClassifierOr QP_FALSE =
      new QueryClassifierOr(ImmutableList.of());

  static final Function<ImmutableList<QueryClassifier>, QueryClassifier> QP_NEW =
      new Function<ImmutableList<QueryClassifier>, QueryClassifier>() {

    @Override
    public QueryClassifier apply(ImmutableList<QueryClassifier> cs) {
      return new QueryClassifierOr(cs);
    }

  };

  QueryClassifierOr(ImmutableList<QueryClassifier> cs) {
    super(cs);
  }
}


