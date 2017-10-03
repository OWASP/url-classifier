package com.mikesamuel.url;

/**
 * A tri-state predicate result.
 */
public enum Classification {
  /** The URL input does not match the predicate. */
  NOT_A_MATCH,
  /** The URL input does match the predicate. */
  MATCH,
  /** THe URL input is structurally invalid. */
  INVALID,
  ;

  /**
   * Logical inverse where invalid -> invalid.
   */
  public Classification invert() {
    switch (this) {
    case NOT_A_MATCH: return MATCH;
    case MATCH:       return NOT_A_MATCH;
    case INVALID:     return INVALID;
    }
    throw new AssertionError(this);
  }
}
