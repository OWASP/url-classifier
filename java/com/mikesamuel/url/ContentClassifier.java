package com.mikesamuel.url;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;

/**
 * A URL classifier that checks the content and content-metadata portions
 * of a non-hierarchical URL.
 */
public interface ContentClassifier extends URLClassifier {

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   */
  public static ContentClassifier or(ContentClassifier... cs) {
    return or(ImmutableList.copyOf(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   */
  public static ContentClassifier or(Iterable<? extends ContentClassifier> cs) {
    return URLClassifierOr.abstractOr(
        cs, ContentClassifierOr.FP_FALSE,
        new Function<ImmutableList<ContentClassifier>, ContentClassifier>() {

          @Override
          public ContentClassifier apply(ImmutableList<ContentClassifier> flat) {
            return new ContentClassifierOr(flat);
          }

        });
  }
}

final class ContentClassifierOr
extends URLClassifierOr<ContentClassifier> implements ContentClassifier {

  static final ContentClassifierOr FP_FALSE =
      new ContentClassifierOr(ImmutableList.of());

  static final Function<ImmutableList<ContentClassifier>, ContentClassifier> FP_NEW =
      new Function<ImmutableList<ContentClassifier>, ContentClassifier>() {

        @Override
        public ContentClassifier apply(ImmutableList<ContentClassifier> cs) {
          return new ContentClassifierOr(cs);
        }

      };

  ContentClassifierOr(ImmutableList<ContentClassifier> cs) {
    super(cs);
  }
}