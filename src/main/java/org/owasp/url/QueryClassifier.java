package org.owasp.url;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;

/**
 * A URLClassifier that considers the query: <tt>http://example.com/<b>?key=value</b></tt>.
 */
public interface QueryClassifier extends URLClassifier {

  /** A new blank builder. */
  public static QueryClassifierBuilder builder() {
    return new QueryClassifierBuilder();
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static QueryClassifier or(QueryClassifier... cs) {
    return or(ImmutableList.copyOf(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
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
  public Classification apply(
      URLValue x, Diagnostic.Receiver<? super URLValue> r) {
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


