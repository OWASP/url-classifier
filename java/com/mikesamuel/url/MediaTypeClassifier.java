package com.mikesamuel.url;

import java.util.Arrays;

import com.google.common.base.Function;
import com.google.common.net.MediaType;

/**
 * A classifier over media types like ones found in {@code data:media/type;...}.
 */
public interface MediaTypeClassifier extends Function<MediaType, Classification> {

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   */
  public static MediaTypeClassifier or(MediaTypeClassifier... cs) {
    return or(Arrays.asList(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   */
  public static MediaTypeClassifier or(
      Iterable<? extends MediaTypeClassifier> cs) {
    // TODO Auto-generated method stub
    return null;
  }

}
