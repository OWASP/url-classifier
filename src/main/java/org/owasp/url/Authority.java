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

import java.net.IDN;
import java.net.Inet4Address;
import java.net.Inet6Address;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;
import com.ibm.icu.text.IDNA;


/**
 * The authority component of a URL: <tt>http://<b>example.com</b>/</tt>.
 * <p>
 * It has the general form [user[':'password]'@']host[':'port].
 */
public final class Authority {
  /** The username component of the userinfo. */
  public final Optional<String> userName;
  /** The password component of the userinfo. */
  public final Optional<String> password;
  /**
   * The host represented as an
   * {@link InternetDomainName}, {@link Inet6Address},
   * or {@link Inet4Address}.
   */
  public final Optional<Object> host;
  /**
   * The port or -1.  If the port was not specified but the scheme
   * has a default port this will be the scheme default.
   */
  public final int portOrNegOne;
  private final IDNA.Info info;

  /** */
  private Authority(
      Optional<String> userName, Optional<String> password,
      Optional<Object> host, int portOrNegOne,
      IDNA.Info info) {
    if (host.isPresent()) {
      Object hostObj = host.get();
      Preconditions.checkArgument(
          hostObj instanceof InternetDomainName
          || hostObj instanceof Inet4Address
          || hostObj instanceof Inet6Address,
          "Invalid host", hostObj);
    }

    this.userName = userName;
    this.password = password;
    this.host = host;
    this.portOrNegOne = portOrNegOne;
    this.info = info;
  }

  static Authority decode(
      UrlValue x,
      Diagnostic.Receiver<? super UrlValue> r) {
    String auth = x.getRawAuthority();
    if (auth == null) {  // Nothing to do here
      return null;
    }

    int at = auth.lastIndexOf('@');
    int colon = auth.indexOf(':');

    Optional<String> password = Optional.absent();
    Optional<String> uname = Optional.absent();

    // An authority has the form [uname[':'[password]]'@']host[':'port]
    if (at >= 0) {
      int unameEnd = at;
      if (colon >= 0 && colon < at) {
        unameEnd = colon;
        Optional<CharSequence> passwordOpt =
            Percent.decode(auth, colon + 1, at, false);
        if (!passwordOpt.isPresent()) {
          r.note(Diagnostics.MALFORMED_PASSWORD, x);
          return null;
        }
        password = Optional.of(passwordOpt.get().toString());
      }
      Optional<CharSequence> unameOpt =
          Percent.decode(auth, 0, unameEnd, false);
      if (!unameOpt.isPresent()) {
        r.note(Diagnostics.MALFORMED_USERNAME, x);
        return null;
      }
      uname = Optional.of(unameOpt.get().toString());
    }

    int port = -1;
    int hostStart = at + 1;
    int hostEnd = auth.length();
    {
      for (int i = hostEnd; --i >= hostStart;) {
        char c = auth.charAt(i);
        if ('0' <= c && c <= '9') {
          continue;
        }
        if (c == ':') {
          if (i + 1 == hostEnd) {
            // RFC 3986 section 3.2.3 allows empty ports per
            //     port        = *DIGIT
            // and suggest the empty port is equivalent to the scheme default
            //     URI producers and normalizers should omit the port component
            //     and its ":" delimiter if port is empty or if its value would
            //     be the same as that of the scheme's default.
            // That is reinforced in section 6.2.3:
            //     Likewise, an explicit ":port", for which the port is empty
            //     or the default for the scheme, is equivalent to one where
            //     the port and its ":" delimiter are elided and thus should
            //     be removed by scheme-based normalization.
          } else {
            // We have a port.
            port = parseDecimalUintLessThan(auth, i + 1, hostEnd, 65536);
            if (port <= 0) {
              // -1 means parse or bounds failure. 0 is not a valid port number.
              // "UNIX Network Programming" by Stevens, Fenner & Rudoff says
              //     If we specify a port number of 0, the kernel chooses
              //     an ephemeral port when bind is called.
              r.note(Diagnostics.PORT_OUT_OF_RANGE, x);
              return null;
            }
          }
          hostEnd = i;
        }
        break;
      }
    }

    // An empty host name as in http:/// or http://a@/ or http://:80/
    if (at + 1 == auth.length()) {
      r.note(Diagnostics.EMPTY_HOSTNAME, x);
      return null;
    }

    if (port == -1) {
      port = x.scheme.defaultPortOrNegOne;
    }

    Optional<Object> host = Optional.absent();
    String rawHost = auth.substring(at + 1, hostEnd);
    int hostLength = rawHost.length();
    IDNA.Info idnaInfo = null;
    if (hostLength != 0) {
      Object hostValue;
      try {
        if (InetAddresses.isUriInetAddress(rawHost)) {
          // Numeric addresses should be ascii.
          if (hasNonAsciiMetacharacters(rawHost)) {
            r.note(Diagnostics.NON_ASCII_METACHARACTERS, x);
            return null;
          }
          hostValue = InetAddresses.forUriString(rawHost);
        } else {
          Optional<String> decodedHostOpt = Percent.decode(rawHost);
          if (!decodedHostOpt.isPresent()) {
            r.note(Diagnostics.MALFORMED_HOSTNAME, x);
            return null;
          }
          String decodedHost = decodedHostOpt.get();
          if (hasNonAsciiDomainNameMetacharacters(decodedHost)) {
            r.note(Diagnostics.NON_ASCII_METACHARACTERS, x);
            return null;
          }
          idnaInfo = new IDNA.Info();
          hostValue = toDomainName(decodedHost, idnaInfo);
        }
      } catch (@SuppressWarnings("unused") IllegalArgumentException e) {
        r.note(Diagnostics.MALFORMED_HOST, x);
        return null;
      }
      host = Optional.of(hostValue);
    }
    return new Authority(uname, password, host, port, idnaInfo);
  }

  boolean hasValidHost() {
    return this.host.isPresent() && (info == null || !info.hasErrors());
  }

  boolean hasTransitionalDifference() {
    return info != null && info.isTransitionalDifferent();
  }

  /**
   * @param info will have the errors and transitional differences set if
   *    appropriate.
   */
  static InternetDomainName toDomainName(String decodedHost, IDNA.Info info) {
    String unicodeName = IDN.toUnicode(decodedHost, IDN.USE_STD3_ASCII_RULES);
    IDNA idna = IDNA.getUTS46Instance(IDNA.DEFAULT);
    StringBuilder nameBuffer = new StringBuilder(decodedHost.length() + 16);
    nameBuffer = idna.nameToASCII(decodedHost, nameBuffer, info);
    return InternetDomainName.from(unicodeName);
  }

  private static int parseDecimalUintLessThan(String s, int left, int right, int limit) {
    int n = 0;
    for (int i = left; i < right; ++i) {
      char c = s.charAt(i);
      int d = c - '0';
      if (d < 0) { return -1; }
      int np = n * 10 + d;
      // Test for underflow and limit breaking.
      if (0 > np || np >= limit) { return -1; }
      n = np;
    }
    return n;
  }

  enum Diagnostics implements Diagnostic {
    MALFORMED_PASSWORD,
    MALFORMED_USERNAME,
    PORT_OUT_OF_RANGE,
    EMPTY_HOSTNAME,
    NON_ASCII_METACHARACTERS,
    MALFORMED_HOSTNAME,
    MALFORMED_HOST,
  }

  private static boolean hasNonAsciiDomainNameMetacharacters(String host) {
    int n = host.length();
    for (int i = 0; i < n; ++i) {
      char c = host.charAt(i);
      if (c < 0x80) { continue; }  // Common case
      switch (c) {
        // Normalize to '.'
        // InternetDomainName starts off
        // name = Ascii.toLowerCase(DOTS_MATCHER.replaceFrom(name, '.'));
        // Prevent that.
        case 0x3002:
        case 0xff0e:
        case 0xff61:
          return true;
      }
    }
    return false;
  }

  private static boolean hasNonAsciiMetacharacters(String host) {
    // Lots of digits in the Arabic, Devanagiri and other code tables are
    // recognized as decimal digits by the Java core library numeric IP
    // parsing methods.
    // The RFCs are very clear though that only the ASCII variants are
    // valid.
    int n = host.length();
    for (int i = 0; i < n; ++i) {
      char c = host.charAt(i);
      if (c >= 0x80) { return true; }
    }
    return false;
  }
}
