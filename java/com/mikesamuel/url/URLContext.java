package com.mikesamuel.url;

import com.google.common.base.Preconditions;

/**
 * Encapsulates the context in which a URL is interpreted.
 */
public final class URLContext {
  /** A base URL against which relative URLs will be resolved. */
  public final Absolutizer absolutizer;
  /** @see EncodedDotStrategy */
  public final EncodedDotStrategy encodedDotStrategy;
  /** @see MicrosoftPathStrategy */
  public final MicrosoftPathStrategy microsoftPathStrategy;


  /**
   * By default, path components like ("%2e", "%2e%2e") that, post decoding
   * are ambiguous with the special path components (".", "..") will not be
   * matched.  If these must be matched, then enable this but ensure that the
   * server that processes these deals with these path components correctly.
   * Default is TREAT_AS_INVALID
   */
  public enum EncodedDotStrategy {
    /** The default. */
    TREAT_AS_INVALID,
    /** */
    DO_NOT_MATCH,
    /** */
    MATCH_AS_PATH,
    /** */
    MATCH_AS_DECODED,
    ;

    /** */
    @SuppressWarnings("hiding")
    public static final EncodedDotStrategy DEFAULT = TREAT_AS_INVALID;
  }


  /**
   * Microsoft uses back-slash ('\\') to separate file components and many
   * Microsoft systems helpfully treat ('\\') as equivalent to the normal
   * URL path component separator ('/').
   * Use BACK_TO_FORWARD if you want to emulate this behavior.
   * By default, you don't.
   */
  public enum MicrosoftPathStrategy {
    /** The default */
    STANDARDS_COMPLIANT,
    /**
     * If you use this, please use {@link URLValue#urlText}
     * not {@link URLValue#originalUrlText}.
     */
    BACK_TO_FORWARD,
    ;

    /** */
    @SuppressWarnings("hiding")
    public static final MicrosoftPathStrategy DEFAULT = STANDARDS_COMPLIANT;
  }


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
    this(absolutizer, EncodedDotStrategy.DEFAULT, MicrosoftPathStrategy.DEFAULT);
  }

  private URLContext(
      Absolutizer absolutizer, EncodedDotStrategy eds,
      MicrosoftPathStrategy mps) {
    this.absolutizer = Preconditions.checkNotNull(absolutizer);
    this.encodedDotStrategy = Preconditions.checkNotNull(eds);
    this.microsoftPathStrategy = Preconditions.checkNotNull(mps);
  }

  /** @see EncodedDotStrategy */
  public URLContext with(EncodedDotStrategy eds) {
    return eds == this.encodedDotStrategy
        ? this
        : new URLContext(absolutizer, eds, microsoftPathStrategy);
  }

  /** @see MicrosoftPathStrategy */
  public URLContext with(MicrosoftPathStrategy mps) {
    return mps == this.microsoftPathStrategy
        ? this
        : new URLContext(absolutizer, encodedDotStrategy, mps);
  }
}
