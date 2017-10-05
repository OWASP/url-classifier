package org.owasp.url;

/**
 * A tri-state classifier result.
 */
public enum Classification {
  /** The URL input does not match the classifier. */
  NOT_A_MATCH,
  /** The URL input does match the classifier. */
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
