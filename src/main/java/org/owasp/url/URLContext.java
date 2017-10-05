// Copyright (c) 2017, Mike Samuel
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// Neither the name of the OWASP nor the names of its contributors may
// be used to endorse or promote products derived from this software
// without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package org.owasp.url;

import com.google.common.base.Preconditions;

/**
 * The context in which a URL is encountered.
 */
public final class URLContext {
  /** A base URL against which relative URLs will be resolved. */
  public final Absolutizer absolutizer;
  /** @see MicrosoftPathStrategy */
  public final MicrosoftPathStrategy microsoftPathStrategy;
  /** @see URLSource */
  public final URLSource urlSource;

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
   * The kind of entity providing the URL text.
   */
  public enum URLSource {
    /**
     * The URL came from a message crafted for consumption by a machine.
     * For example, a HTTP header, or an HTML attribute.
     */
    MACHINE_READABLE_INPUT,
    /**
     * The URL came from an end user.  For example, copy/pasted from an
     * email into a browser's URL bar or sent in an email or chat message
     * to another human.
     * <p>
     * Human readable inputs often exclude details like protocols.
     * A reasonable human assumes {@code user@domain.com} is an email address even
     * though it is also a valid relative path and that {@code www.example.com} is
     * a hostname even though it is also a valid relative path URL.
     */
    HUMAN_READABLE_INPUT,
    ;

    /** */
    @SuppressWarnings("hiding")
    public static final URLSource DEFAULT = MACHINE_READABLE_INPUT;
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
    this(absolutizer, MicrosoftPathStrategy.DEFAULT, URLSource.DEFAULT);
  }

  private URLContext(
      Absolutizer absolutizer,
      MicrosoftPathStrategy mps,
      URLSource urlSource) {
    this.absolutizer = Preconditions.checkNotNull(absolutizer);
    this.microsoftPathStrategy = Preconditions.checkNotNull(mps);
    this.urlSource = Preconditions.checkNotNull(urlSource);
  }

  /** @see MicrosoftPathStrategy */
  public URLContext with(MicrosoftPathStrategy mps) {
    return mps == this.microsoftPathStrategy
        ? this
        : new URLContext(absolutizer, mps, urlSource);
  }

  /** @see URLSource */
  public URLContext with(URLSource us) {
    return us == this.urlSource
        ? this
        : new URLContext(absolutizer, microsoftPathStrategy, us);
  }
}
