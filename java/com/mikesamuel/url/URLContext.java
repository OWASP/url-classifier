package com.mikesamuel.url;

/**
 * Encapsulates the context in which a URL is interpreted.
 */
public final class URLContext {
  /** A base URL against which relative URLs will be resolved. */
  public final Absolutizer absolutizer;

  /**
   * A placeholder for an unknown authority.
   * <p>
   * Per https://tools.ietf.org/html/rfc2606 this will not be assigned, and
   * the {@link URLValue#inheritsPlaceholderAuthority} bit unambiguously
   * represents
   */
  public static final String PLACEHOLDER_AUTHORITY = "example.org.";

  /** A context that may be used to resolve */
  public static final URLContext DEFAULT = new URLContext(new Absolutizer(
      SchemeLookupTable.BUILTINS_ONLY,
      "http://" + PLACEHOLDER_AUTHORITY + "/"));

  /** */
  public URLContext(Absolutizer absolutizer) {
    this.absolutizer = absolutizer;
  }
}
