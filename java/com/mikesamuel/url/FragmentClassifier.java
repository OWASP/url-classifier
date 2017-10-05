package com.mikesamuel.url;

import java.util.Arrays;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;

/** A URLClassifier that considers only the fragment portion. */
public interface FragmentClassifier extends URLClassifier {

  /** A new blank builder. */
  public static FragmentClassifierBuilder builder() {
    return new FragmentClassifierBuilder();
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   */
  public static FragmentClassifier or(FragmentClassifier... cs) {
    return or(Arrays.asList(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   */
  public static FragmentClassifier or(Iterable<? extends FragmentClassifier> cs) {
    return URLClassifierOr.<FragmentClassifier>abstractOr(
        cs,
        FragmentClassifierOr.FP_FALSE,
        FragmentClassifierOr.FP_NEW);
  }

  /** A classifier that matches all inputs. */
  public static FragmentClassifier any() {
    return AnyFragmentClassifier.INSTANCE;
  }
}

final class AnyFragmentClassifier implements FragmentClassifier {
  static final AnyFragmentClassifier INSTANCE = new AnyFragmentClassifier();

  @Override
  public Classification apply(
      URLValue x, Diagnostic.Receiver<? super URLValue> r) {
    return Classification.MATCH;
  }
}

final class FragmentClassifierOr
extends URLClassifierOr<FragmentClassifier> implements FragmentClassifier {

  static final FragmentClassifierOr FP_FALSE =
      new FragmentClassifierOr(ImmutableList.of());

  static final Function<ImmutableList<FragmentClassifier>, FragmentClassifier> FP_NEW =
      new Function<ImmutableList<FragmentClassifier>, FragmentClassifier>() {

        @Override
        public FragmentClassifier apply(ImmutableList<FragmentClassifier> cs) {
          return new FragmentClassifierOr(cs);
        }

      };

  FragmentClassifierOr(ImmutableList<FragmentClassifier> cs) {
    super(cs);
  }

}
