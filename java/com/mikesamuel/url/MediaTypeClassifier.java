package com.mikesamuel.url;

import java.util.Arrays;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;

/**
 * A classifier over media types like ones found in {@code data:media/type;...}.
 * @see URLValue#getContentMediaType()
 */
public interface MediaTypeClassifier extends URLClassifier {

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static MediaTypeClassifier or(MediaTypeClassifier... cs) {
    return or(Arrays.asList(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static MediaTypeClassifier or(
      Iterable<? extends MediaTypeClassifier> cs) {
    return URLClassifierOr.<MediaTypeClassifier>abstractOr(
        cs,
        MediaTypeClassifierOr.MT_FALSE,
        MediaTypeClassifierOr.MT_NEW);
  }

  /** A classifier that matches all inputs. */
  public static MediaTypeClassifier any() {
    return AnyMediaTypeClassifier.INSTANCE;
  }
}

final class AnyMediaTypeClassifier implements MediaTypeClassifier {
  static final AnyMediaTypeClassifier INSTANCE = new AnyMediaTypeClassifier();

  @Override
  public Classification apply(
      URLValue x, Diagnostic.Receiver<? super URLValue> r) {
    return Classification.MATCH;
  }
}

final class MediaTypeClassifierOr
extends URLClassifierOr<MediaTypeClassifier> implements MediaTypeClassifier {

  static final MediaTypeClassifierOr MT_FALSE =
      new MediaTypeClassifierOr(ImmutableList.of());

  static final Function<ImmutableList<MediaTypeClassifier>, MediaTypeClassifier> MT_NEW =
      new Function<ImmutableList<MediaTypeClassifier>, MediaTypeClassifier>() {

        @Override
        public MediaTypeClassifier apply(ImmutableList<MediaTypeClassifier> cs) {
          return new MediaTypeClassifierOr(cs);
        }

      };

  MediaTypeClassifierOr(ImmutableList<MediaTypeClassifier> cs) {
    super(cs);
  }

}
