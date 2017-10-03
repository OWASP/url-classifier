package com.mikesamuel.url;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;

/** A URLPredicate that considers only the query portion. */
public interface QueryPredicate extends URLPredicate {
  /**
   * A predicate that passes when applying ps in order results in a match before a
   * classification of INVALID.
   */
  public static QueryPredicate or(QueryPredicate... ps) {
    return or(ImmutableList.copyOf(ps));
  }

  /**
   * A predicate that passes when applying ps in order results in a match before a
   * classification of INVALID.
   */
  public static QueryPredicate or(Iterable<? extends QueryPredicate> ps) {
    return URLPredicateOr.<QueryPredicate>abstractOr(
      ps,
      QueryPredicateOr.QP_FALSE,
      QueryPredicateOr.QP_NEW);
  }
}

final class QueryPredicateOr
extends URLPredicateOr<QueryPredicate> implements QueryPredicate {

  static final QueryPredicateOr QP_FALSE =
      new QueryPredicateOr(ImmutableList.of());

  static final Function<ImmutableList<QueryPredicate>, QueryPredicate> QP_NEW =
      new Function<ImmutableList<QueryPredicate>, QueryPredicate>() {

    @Override
    public QueryPredicate apply(ImmutableList<QueryPredicate> ps) {
      return new QueryPredicateOr(ps);
    }

  };

  QueryPredicateOr(ImmutableList<QueryPredicate> ps) {
    super(ps);
  }
}


