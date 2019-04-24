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
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;
import com.ibm.icu.text.IDNA;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Iterator;

/**
 * Builder for {@link AuthorityClassifier}s.
 *
 * <p>
 * The main use case is to whitelist some group of named hosts or a small
 * number of numeric IP addresses.
 * Arbitrary subdomains may be matched via a glob-style syntax.
 *
 * <h2>Caveats</h2>
 * Host names are properly decoded before being compared.
 * This means that <tt>file://localhost/path</tt> is treated the same as
 * <tt>file://loc%61lhost/path</tt>.
 * The <tt>file:</tt> scheme specification uses "<tt>localhost</tt>" as a
 * keyword value, but there is no way to distinguish between these two
 * potentially different authorities via this API.
 * A custom classifier may examine the
 * {@linkplain UrlValue#getRawAuthority raw authority} to make such a
 * distinction if needed.
 *
 * @see AuthorityClassifiers#builder
 */
public final class AuthorityClassifierBuilder {
  private final ImmutableSet.Builder<Inet4Address> ipv4s = ImmutableSet.builder();
  private final ImmutableSet.Builder<Inet6Address> ipv6s = ImmutableSet.builder();
  private final ImmutableSet.Builder<InternetDomainName> domainNames = ImmutableSet.builder();
  private final ImmutableSet.Builder<HostGlob> hostGlobs = ImmutableSet.builder();
  private boolean matchesAnyHost = false;
  private final ImmutableSet.Builder<Integer> allowedPorts = ImmutableSet.builder();
  private Predicate<? super Integer> allowedPortClassifier = null;
  private PunycodeIdentifier punycodeIdentifier = null;
  private UserInfoClassifier allowedUserInfoClassifier = null;
  // We intentionally do not allow matching against a password.
  // There is no way to match http://msamuel:hello-kitty@google.com/
  // via this API.  Also, get your own password.

  AuthorityClassifierBuilder() {
    // Static factory.
  }

  /**
   * Builds a classifier based on previous allow/match decisions.
   * This may be reused after a call to build and subsequent calls to
   * allow/match methods will not affect previously built classifiers.
   */
  public AuthorityClassifier build() {
    ImmutableSet<Inet4Address> ipv4Set = ipv4s.build();
    ImmutableSet<Inet6Address> ipv6Set = ipv6s.build();
    ImmutableSet<InternetDomainName> domainNameSet = domainNames.build();
    HostGlobMatcher hostGlobMatcher = new HostGlobMatcher(hostGlobs.build());
    int[] allowedPortsSorted;
    {
      ImmutableSet<Integer> allowedPortIntSet = allowedPorts.build();
      int n = allowedPortIntSet.size();
      allowedPortsSorted = new int[n];
      Iterator<Integer> allowedPortIt = allowedPortIntSet.iterator();
      for (int i = 0; i < n; ++i) {
        allowedPortsSorted[i] = allowedPortIt.next();
      }
      Arrays.sort(allowedPortsSorted);
    }
    Predicate<? super Integer> portClassifier =
        allowedPortsSorted.length == 0  // No exclusion specified
        ? Predicates.alwaysTrue()
        : Predicates.alwaysFalse();
    if (this.allowedPortClassifier != null) {
      portClassifier = this.allowedPortClassifier;
    }
    UserInfoClassifier userInfoClassifier =
        this.allowedUserInfoClassifier != null
        ? this.allowedUserInfoClassifier
        : UserInfoClassifiers.NO_PASSWORD_BUT_USERNAME_IF_ALLOWED_BY_SCHEME;
    PunycodeIdentifier punycodeIdentifier = PunycodeIdentifierBuilder.DEFAULT;
    return new AuthorityClassifierImpl(
        ipv4Set,
        ipv6Set,
        domainNameSet,
        hostGlobMatcher,
        matchesAnyHost,
        allowedPortsSorted,
        portClassifier,
        punycodeIdentifier,
        userInfoClassifier);
  }

  /**
   * Accepts hostnames or numeric IPAs.
   * IPv6 addresses should be in square brackets.
   */
  public AuthorityClassifierBuilder host(String... hosts) {
    for (String host : hosts) {
      int len = host.length();
      Preconditions.checkArgument(len > 0, "Empty string passed as hostname");
      if (InetAddresses.isUriInetAddress(host)) {
        InetAddress addr = InetAddresses.forUriString(host);
        if (addr instanceof Inet6Address) {
          ipv6s.add((Inet6Address) addr);
        } else {
          ipv4s.add((Inet4Address) addr);
        }
      } else {
        IDNA.Info info = new IDNA.Info();
        domainNames.add(Authority.toDomainName(host, info));
        Preconditions.checkArgument(
            !info.hasErrors(), "Invalid domain name", host, info.getErrors());
      }
    }
    return this;
  }
  /** @see #host(String...) */
  public AuthorityClassifierBuilder host(InternetDomainName... addresses) {
    domainNames.addAll(Arrays.asList(addresses));
    return this;
  }
  /** @see #host(String...) */
  public AuthorityClassifierBuilder host(Inet4Address... addresses) {
    ipv4s.addAll(Arrays.asList(addresses));
    return this;
  }
  /** @see #host(String...) */
  public AuthorityClassifierBuilder host(Inet6Address... addresses) {
    ipv6s.addAll(Arrays.asList(addresses));
    return this;
  }
  /** @see #host(String...) */
  public AuthorityClassifierBuilder host(InetAddress... addresses) {
    for (InetAddress address : addresses) {
      if (address instanceof Inet4Address) {
        ipv4s.add((Inet4Address) address);
      } else if (address instanceof Inet6Address) {
        ipv6s.add((Inet6Address) address);
      } else {
        throw new IllegalArgumentException(address.toString());
      }
    }
    return this;
  }

  /** @see #hostGlob(Iterable) */
  public AuthorityClassifierBuilder hostGlob(String... globs) {
    return hostGlob(Arrays.asList(globs));
  }
  /**
   * hostGlob("**.example.com") matches any subdomain of example.com
   * including example.com.
   * <p>
   * hostGlob("*.example.com") matches foo.example.com but neither
   * foo.bar.example.com nor example.com.
   * <p>
   * hostGlob("example.*") matches "example." followed by any entry on
   * <a href="http://publicsuffix.org/">Mozilla's public suffix list</a> so will
   * match "example.com", "example.org", and "example.co.uk".
   * <p>
   * hostGlob("**") matches any valid host including numeric IPAs.
   * <p>
   * One of "**." and "*." may appear at the beginning and ".*" may appear at the end
   * but otherwise, "*" may not appear in a host glob.
   */
  public AuthorityClassifierBuilder hostGlob(
      Iterable<? extends String> globs) {
    for (String glob : globs) {
      // Treat as a proper hostname.
      if ("**".equals(glob)) {
        matchesAnyHost = true;
      } else if (glob.indexOf('*') < 0) {
        IDNA.Info info = new IDNA.Info();
        domainNames.add(Authority.toDomainName(glob, info));
        Preconditions.checkArgument(
            !info.hasErrors(), "Invalid domain name", glob, info.getErrors());
      } else {
        hostGlobs.add(new HostGlob(glob));
      }
    }
    return this;
  }

  /**
   * If a port matcher is specified we assume default ports based on
   * scheme, so matching ports (80, 443) matches http://example.com/
   * but not https://example.com/ and https://example.com:80/ but not
   * https://example.com:10000/
   */
  public AuthorityClassifierBuilder port(
      Predicate<? super Integer> portIsAllowed) {
    Preconditions.checkNotNull(portIsAllowed);
    if (allowedPortClassifier == null) {
      allowedPortClassifier = portIsAllowed;
    } else if (portIsAllowed != Predicates.alwaysFalse()) {  // x || false -> x
      allowedPortClassifier = Predicates.or(
          allowedPortClassifier, portIsAllowed);
    }
    return this;
  }
  /** @see #port(Predicate) */
  public AuthorityClassifierBuilder port(int... ports) {
    for (int port : ports) {
      allowedPorts.add(port);
    }
    return this;
  }

  /**
   * Specifies a classifier for the user info portion of the authority.
   * <p>
   * If not specified, the default is
   * {@link UserInfoClassifiers#NO_PASSWORD_BUT_USERNAME_IF_ALLOWED_BY_SCHEME}.
   *
   * @see Authority#userName
   * @see Authority#password
   */
  public AuthorityClassifierBuilder userInfo(UserInfoClassifier c) {
    Preconditions.checkNotNull(c);
    if (this.allowedUserInfoClassifier == null) {
      allowedUserInfoClassifier = c;
    } else {
      allowedUserInfoClassifier = UserInfoClassifiers.or(
          allowedUserInfoClassifier, c);
    }
    return this;
  }
}


final class AuthorityClassifierImpl implements AuthorityClassifier {

  private final ImmutableSet<Inet4Address> ipv4Set;
  private final ImmutableSet<Inet6Address> ipv6Set;
  private final ImmutableSet<InternetDomainName> domainNameSet;
  private final HostGlobMatcher hostGlobMatcher;
  private final boolean matchesAnyHost;
  private final int[] allowedPortsSorted;
  private final Predicate<? super Integer> portClassifier;
  private final PunycodeIdentifier punycodeIdentifier;
  private final UserInfoClassifier userInfoClassifier;

  enum Diagnostics implements Diagnostic {
    INHERITS_PLACEHOLDER_AUTHORITY,
    DISALLOWED_PORT,
    MISSING_HOST,
    HOST_NOT_IN_APPROVED_SET,
    POTENTIAL_HOMOGRAPH,
  }

  public AuthorityClassifierImpl(
      ImmutableSet<Inet4Address> ipv4Set, ImmutableSet<Inet6Address> ipv6Set,
      ImmutableSet<InternetDomainName> canonHostnameSet, HostGlobMatcher hostGlobMatcher,
      boolean matchesAnyHost, int[] allowedPortsSorted, Predicate<? super Integer> portClassifier,
      PunycodeIdentifier punycodeIdentifier, UserInfoClassifier userInfoClassifier) {
    this.ipv4Set = ipv4Set;
    this.ipv6Set = ipv6Set;
    this.domainNameSet = canonHostnameSet;
    this.hostGlobMatcher = hostGlobMatcher;
    this.matchesAnyHost = matchesAnyHost;
    this.allowedPortsSorted = allowedPortsSorted;
    this.portClassifier = portClassifier;
    this.punycodeIdentifier = punycodeIdentifier;
    this.userInfoClassifier = userInfoClassifier;
  }

  @Override
  public Classification apply(
      UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
    Authority auth = x.getAuthority(r);
    if (auth == null) {
      if (x.ranges.authorityLeft >= 0 || x.scheme.naturallyHasAuthority) {
        return Classification.INVALID;
      } else {
        return Classification.NOT_A_MATCH;
      }
    }

    // We collect a result and look for reasons not to match.
    // We don't early out on NOT_A_MATCH in case we find evidence for INVALID.
    Classification result = Classification.MATCH;

    if (x.inheritsPlaceholderAuthority && !matchesAnyHost) {
      // We treat the placeholder authority specially.
      // Whitelisting example.org should not cause a URL that doesn't definitely
      // have that authority to match.
      r.note(Diagnostics.INHERITS_PLACEHOLDER_AUTHORITY, x);
      result = Classification.NOT_A_MATCH;
    }

    switch (this.userInfoClassifier.apply(x, r)) {
      case INVALID:
        return Classification.INVALID;
      case NOT_A_MATCH:
        result = Classification.NOT_A_MATCH;
        break;
      case MATCH:
        break;
    }

    int port = auth.portOrNegOne;
    if (port != -1 && result == Classification.MATCH) {
      if (!this.portClassifier.apply(port)) {
        int pos = Arrays.binarySearch(this.allowedPortsSorted, port);
        if (pos < 0) {
          r.note(Diagnostics.DISALLOWED_PORT, x);
          result = Classification.NOT_A_MATCH;
        }
      }
    }

    if (!auth.host.isPresent()) {
      r.note(Diagnostics.MISSING_HOST, x);
      return Classification.INVALID;
    }

    if (result == Classification.MATCH) {
      if (!matchesAnyHost) {
        Object hostValue = auth.host.get();
        if (hostValue instanceof Inet6Address) {
          Inet6Address addr = (Inet6Address) hostValue;
          if (!ipv6Set.contains(addr)) {
            r.note(Diagnostics.HOST_NOT_IN_APPROVED_SET, x);
            result = Classification.NOT_A_MATCH;
          }
        } else if (hostValue instanceof Inet4Address) {
          Inet4Address addr = (Inet4Address) hostValue;
          if (!ipv4Set.contains(addr)) {
            r.note(Diagnostics.HOST_NOT_IN_APPROVED_SET, x);
            result = Classification.NOT_A_MATCH;
          }
        } else {
          InternetDomainName name = (InternetDomainName) hostValue;

          if (punycodeIdentifier.isPotentialHomograph(name.toString())) {
            r.note(Diagnostics.POTENTIAL_HOMOGRAPH, x);
          }

          if (!(domainNameSet.contains(name) || hostGlobMatcher.matches(name))) {
            r.note(Diagnostics.HOST_NOT_IN_APPROVED_SET, x);
            result = Classification.NOT_A_MATCH;
          }
        }
      }
    }

    return result;
  }
}

final class HostGlob {
  final boolean anySubdomain;  // Starts with **.
  final boolean aSubdomain;  // Starts with *.
  final boolean anyPublicSuffix;  // Ends with a public suffix
  final ImmutableList<String> middleParts;

  HostGlob(String globPattern) {
    int left = 0;
    int right = globPattern.length();

    this.anySubdomain = globPattern.startsWith("**.");
    if (anySubdomain) {
      left += 3;
      this.aSubdomain = false;
    } else {
      this.aSubdomain = globPattern.startsWith("*.");
      if (this.aSubdomain) {
        left += 2;
      }
    }
    this.anyPublicSuffix = globPattern.endsWith(".*");
    if (this.anyPublicSuffix) {
      right = Math.max(right - 2, left);
    }
    if (left == right) {
      this.middleParts = ImmutableList.of();
    } else {
      this.middleParts =
          InternetDomainName.from(globPattern.substring(left,  right)).parts();
    }
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (aSubdomain ? 1231 : 1237);
    result = prime * result + (anyPublicSuffix ? 1231 : 1237);
    result = prime * result + (anySubdomain ? 1231 : 1237);
    result = prime * result + ((middleParts == null) ? 0 : middleParts.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    HostGlob other = (HostGlob) obj;
    if (aSubdomain != other.aSubdomain)
      return false;
    if (anyPublicSuffix != other.anyPublicSuffix)
      return false;
    if (anySubdomain != other.anySubdomain)
      return false;
    if (middleParts == null) {
      if (other.middleParts != null)
        return false;
    } else if (!middleParts.equals(other.middleParts))
      return false;
    return true;
  }
}
