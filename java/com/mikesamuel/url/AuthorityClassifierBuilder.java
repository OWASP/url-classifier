package com.mikesamuel.url;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.IDN;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSortedMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;

/**
 * Builds a classifier over username:password@hostname:port style authorities.
 */
public final class AuthorityClassifierBuilder {
  private final ImmutableSet.Builder<Inet4Address> ipv4s = ImmutableSet.builder();
  private final ImmutableSet.Builder<Inet6Address> ipv6s = ImmutableSet.builder();
  private final ImmutableSet.Builder<InternetDomainName> domainNames = ImmutableSet.builder();
  private final ImmutableSet.Builder<HostGlob> hostGlobs = ImmutableSet.builder();
  private boolean matchesAnyHost = false;
  private final ImmutableSet.Builder<Integer> allowedPorts = ImmutableSet.builder();
  private Predicate<? super Integer> allowedPortClassifier = null;
  private Predicate<? super CharSequence> allowedUnameClassifier = null;
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
    Predicate<? super CharSequence> unameClassifier = Predicates.alwaysTrue();
    if (this.allowedUnameClassifier != null) {
      unameClassifier = this.allowedUnameClassifier;
    }
    return new AuthorityClassifierImpl(
        ipv4Set,
        ipv6Set,
        domainNameSet,
        hostGlobMatcher,
        matchesAnyHost,
        allowedPortsSorted,
        portClassifier,
        unameClassifier);
  }

  /** Returns a canonical domain name.  The canonical domain name is UNICODE with punycode. */
  static InternetDomainName toDomainName(String decodedHost) {
    String unicodeName = IDN.toUnicode(decodedHost, IDN.USE_STD3_ASCII_RULES);
    return InternetDomainName.from(unicodeName);
  }

  /**
   * Accepts hostnames or numeric IPAs.
   * IPv6 addresses should be in square brackets.
   */
  public AuthorityClassifierBuilder matchesHosts(String... hosts) {
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
        domainNames.add(toDomainName(host));
      }
    }
    return this;
  }
  /** @see #matchesHosts(String...) */
  public AuthorityClassifierBuilder matchesHosts(InternetDomainName... addresses) {
    domainNames.addAll(Arrays.asList(addresses));
    return this;
  }
  /** @see #matchesHosts(String...) */
  public AuthorityClassifierBuilder matchesHosts(Inet4Address... addresses) {
    ipv4s.addAll(Arrays.asList(addresses));
    return this;
  }
  /** @see #matchesHosts(String...) */
  public AuthorityClassifierBuilder matchesHosts(Inet6Address... addresses) {
    ipv6s.addAll(Arrays.asList(addresses));
    return this;
  }
  /** @see #matchesHostGlob(Iterable) */
  public AuthorityClassifierBuilder matchesHostGlob(String... globs) {
    return matchesHostGlob(Arrays.asList(globs));
  }
  /**
   * matchesHostGlob("**.example.com") matches any subdomain of example.com
   * including example.com.
   * <p>
   * matchesHostGlob("*.example.com") matches foo.example.com but neither
   * foo.bar.example.com nor example.com.
   * <p>
   * matchesHostGlob("example.*") matches "example." followed by any entry on
   * <a href="http://publicsuffix.org/">Mozilla's public suffix list</a> so will
   * match "example.com", "example.org", and "example.co.uk".
   * <p>
   * matchesHostGlob("**") matches any valid host including numeric IPAs.
   * <p>
   * One of "**." and "*." may appear at the beginning and ".*" may appear at the end
   * but otherwise, "*" may not appear in a hostname glob.
   */
  public AuthorityClassifierBuilder matchesHostGlob(
      Iterable<? extends String> globs) {
    for (String glob : globs) {
      // Treat as a proper hostname.
      if ("**".equals(glob)) {
        matchesAnyHost = true;
      } else if (glob.indexOf('*') < 0) {
        domainNames.add(toDomainName(glob));
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
  public AuthorityClassifierBuilder matchesPort(
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
  /** @see #matchesPort(Predicate) */
  public AuthorityClassifierBuilder matchesPort(int... ports) {
    for (int port : ports) {
      allowedPorts.add(port);
    }
    return this;
  }

  /**
   * Unless a userinfo classifier is specified no
   * URL with userinfo will match, so
   * http://@example.com/ will not match.
   */
  public AuthorityClassifierBuilder matchesUserName(
      Predicate<? super CharSequence> unameIsAllowed) {
    Preconditions.checkNotNull(unameIsAllowed);
    if (this.allowedUnameClassifier == null) {
      allowedUnameClassifier = unameIsAllowed;
    } else if (unameIsAllowed != Predicates.alwaysFalse()) {  // x || false -> x
      allowedUnameClassifier = Predicates.or(
          allowedUnameClassifier, unameIsAllowed);
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
  private final Predicate<? super CharSequence> unameClassifier;

  private static final boolean EXPLAIN_INVALID = false;

  public AuthorityClassifierImpl(
      ImmutableSet<Inet4Address> ipv4Set, ImmutableSet<Inet6Address> ipv6Set,
      ImmutableSet<InternetDomainName> canonHostnameSet, HostGlobMatcher hostGlobMatcher,
      boolean matchesAnyHost, int[] allowedPortsSorted, Predicate<? super Integer> portClassifier,
      Predicate<? super CharSequence> unameClassifier) {
    this.ipv4Set = ipv4Set;
    this.ipv6Set = ipv6Set;
    this.domainNameSet = canonHostnameSet;
    this.hostGlobMatcher = hostGlobMatcher;
    this.matchesAnyHost = matchesAnyHost;
    this.allowedPortsSorted = allowedPortsSorted;
    this.portClassifier = portClassifier;
    this.unameClassifier = unameClassifier;
  }

  @Override
  public Classification apply(URLValue x) {
    String auth = x.getAuthority();
    if (auth == null) {
      if (x.scheme.naturallyHasAuthority) {
        if (EXPLAIN_INVALID) { System.err.println("missing authority"); }
        return Classification.INVALID;
      } else {
        return Classification.NOT_A_MATCH;
      }
    }

    int at = auth.lastIndexOf('@');
    int colon = auth.indexOf(':');

    // An authority has the form [uname[':'[password]]'@']host[':'port]
    CharSequence uname = null;
    if (at >= 0) {
      if (colon >= 0 && colon < at) {
        // There's a password.
        // We don't encourage password matching in URL classifiers.
        // Don't put passwords in URLs.
        // Tell your friends.
        if (EXPLAIN_INVALID) { System.err.println("password"); }
        return Classification.INVALID;
      }
      Optional<CharSequence> unameOpt = Percent.decode(auth, 0, at, false);
      if (unameOpt.isPresent()) {
        uname = unameOpt.get();
      } else {
        if (EXPLAIN_INVALID) {
          System.err.println("can't decode uname");
        }
        return Classification.INVALID;
      }
    }

    // We collect a result and look for reasons not to match.
    // We don't early out on NOT_A_MATCH in case we find evidence for INVALID.
    Classification result = Classification.MATCH;

    if (x.inheritsPlaceholderAuthority && !matchesAnyHost) {
      // We treat the placeholder authority specially.
      // Whitelisting example.org should not cause a URL that doesn't definitely
      // have that authority to match.
      result = Classification.NOT_A_MATCH;
    }

    if (result == Classification.MATCH && !this.unameClassifier.apply(uname)) {
      result = Classification.NOT_A_MATCH;
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
              if (EXPLAIN_INVALID) {
                System.err.println(
                    "port out of bounds " + auth.substring(i + 1, hostEnd));
              }
              return Classification.INVALID;
            }
          }
          hostEnd = i;
        }
        break;
      }
    }

    // An empty host name as in http:/// or http://a@/ or http://:80/
    if (at + 1 == auth.length()) {
      if (EXPLAIN_INVALID) {
        System.err.println("missing host");
      }
      return Classification.INVALID;
    }

    if (port == -1) {
      port = x.scheme.defaultPortOrNegOne;
    }
    if (port != -1 && result == Classification.MATCH) {
      if (!this.portClassifier.apply(port)) {
        int pos = Arrays.binarySearch(this.allowedPortsSorted, port);
        if (pos < 0) {
          result = Classification.NOT_A_MATCH;
        }
      }
    }

    String host = auth.substring(at + 1, hostEnd);
    int hostLength = host.length();
    if (hostLength == 0) {
      if (EXPLAIN_INVALID) {
        System.err.println("empty host");
      }
      return Classification.INVALID;
    }
    Object hostValue;
    try {
      if (InetAddresses.isUriInetAddress(host)) {
        hostValue = InetAddresses.forUriString(host);
      } else {
        Optional<String> decodedHostOpt = Percent.decode(host);
        if (!decodedHostOpt.isPresent()) {
          if (EXPLAIN_INVALID) {
            System.err.println("misencoding in host " + host);
          }
          return Classification.INVALID;
        }
        hostValue = AuthorityClassifierBuilder
            .toDomainName(decodedHostOpt.get());
      }
    } catch (@SuppressWarnings("unused") IllegalArgumentException e) {
      if (EXPLAIN_INVALID) {
        System.err.println("malformed host " + host);
      }
      return Classification.INVALID;
    }

    if (result == Classification.MATCH && !matchesAnyHost) {
      if (hostValue instanceof Inet6Address) {
        Inet6Address addr = (Inet6Address) hostValue;
        if (!ipv6Set.contains(addr)) {
          result = Classification.NOT_A_MATCH;
        }
      } else if (hostValue instanceof Inet4Address) {
        Inet4Address addr = (Inet4Address) hostValue;
        if (!ipv4Set.contains(addr)) {
          result = Classification.NOT_A_MATCH;
        }
      } else {
        InternetDomainName name = (InternetDomainName) hostValue;
        if (!(domainNameSet.contains(name) || hostGlobMatcher.matches(name))) {
          result = Classification.NOT_A_MATCH;
        }
      }
    }

    return result;
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
      right -= 2;
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

/** Collects host globs together for quicker matching. */
final class HostGlobMatcher {

  /** We group globs by the kinds of ambiguity they allow. */
  static final class Group {
    final boolean anySubdomain;  // Starts with **.
    final boolean aSubdomain;  // Starts with *.
    final boolean anyPublicSuffix;  // Ends with a public suffix
    /** A suffix trie over host parts. */
    final Trie<String, Boolean> middleParts;

    Group(
        boolean anySubdomain,
        boolean aSubdomain,
        boolean anyPublicSuffix,
        Trie<String, Boolean> middleParts) {
      this.anySubdomain = anySubdomain;
      this.aSubdomain = aSubdomain;
      this.anyPublicSuffix = anyPublicSuffix;
      this.middleParts = middleParts;
    }
  }

  private final ImmutableList<Group> groups;

  HostGlobMatcher(Iterable<? extends HostGlob> globs) {
    @SuppressWarnings("unchecked")
    Map<List<String>, Boolean>[] byBits = new Map[8];
    for (HostGlob glob : globs) {
      int i = (glob.anyPublicSuffix ? 1 : 0)
          | (glob.anySubdomain ? 2 : 0)
          | (glob.aSubdomain ? 4 : 0);
      if (byBits[i] == null) {
        byBits[i] = Maps.newHashMap();
      }
      byBits[i].put(glob.middleParts.reverse(), true);
    }
    ImmutableList.Builder<Group> b = ImmutableList.builder();
    for (int i = 0; i < byBits.length; ++i) {
      if (byBits[i] == null) { continue; }
      boolean anyPublicSuffix = 0 != (i & 1);
      boolean anySubdomain = 0 != (i & 2);
      boolean aSubdomain = 0 != (i & 4);
      Group g = new Group(
          anySubdomain, aSubdomain, anyPublicSuffix,
          Trie.from(ImmutableList.copyOf(byBits[i].entrySet())));
      b.add(g);
    }
    this.groups = b.build();
  }

  boolean matches(InternetDomainName name) {
    ImmutableList<String> parts = name.parts();
    int nParts = parts.size();
    int publicSuffixSize = -1;
    next_group:
    for (Group g : groups) {
      int right = nParts;
      int left = 0;
      if (g.anyPublicSuffix) {
        if (name.hasPublicSuffix()) {
          if (publicSuffixSize == -1) {
            publicSuffixSize = name.publicSuffix().parts().size();
          }
          right -= publicSuffixSize;
        } else {
          continue next_group;
        }
      }
      if (g.aSubdomain) { ++left; }
      if (left > right) { continue; }
      Trie<String, Boolean> t = g.middleParts;
      if (g.anySubdomain) {
        boolean sawPartial = false;
        for (int i = right; --i >= left;) {
          sawPartial = sawPartial || Boolean.TRUE.equals(t.value);
          Trie<String, Boolean> child = t.els.get(parts.get(i));
          if (child == null) {
            break;
          }
          t = child;
        }
        if (sawPartial) { return true; }
      } else {
        for (int i = right; --i >= left;) {
          Trie<String, Boolean> child = t.els.get(parts.get(i));
          if (child == null) {
            continue next_group;
          }
          t = child;
        }
        return Boolean.TRUE.equals(t.value);
      }
    }
    return false;
  }
}

final class Trie<T extends Comparable<T>, V> {
  final ImmutableSortedMap<T, Trie<T, V>> els;
  final V value;

  Trie(ImmutableSortedMap<T, Trie<T, V>> els, V value) {
    this.els = els;
    this.value = value;
  }

  static <T extends Comparable<T>, V>
  Trie<T, V> from(List<Map.Entry<List<T>, V>> entries) {
    List<Map.Entry<List<T>, V>> entriesSorted = Lists.newArrayList(entries);
    Collections.sort(
        entriesSorted,
        new Comparator<Map.Entry<List<T>, V>>() {

          @Override
          public int compare(Map.Entry<List<T>, V> a, Map.Entry<List<T>, V> b) {
            List<T> aList = a.getKey();
            int aSize = aList.size();
            List<T> bList = b.getKey();
            int bSize = bList.size();
            int minSize = Math.min(aSize, bSize);
            for (int i = 0; i < minSize; ++i) {
              int delta = aList.get(i).compareTo(bList.get(i));
              if (delta != 0) { return delta; }
            }
            return aSize - bSize;
          }

        });
    return collate(entriesSorted, 0, 0, entriesSorted.size());
  }

  static <T extends Comparable<T>, V>
  Trie<T, V> collate(List<Map.Entry<List<T>, V>> entries, int depth, int left, int right) {
    V value = null;
    ImmutableSortedMap.Builder<T, Trie<T, V>> b = ImmutableSortedMap.naturalOrder();

    int childLeft = left;
    Map.Entry<List<T>, V> leftEntry = null;
    if (left != right) {
      leftEntry = entries.get(childLeft);
      if (leftEntry.getKey().size() == depth) {
        value = leftEntry.getValue();
        ++childLeft;
        leftEntry = childLeft < right
            ? Preconditions.checkNotNull(entries.get(childLeft)) : null;
      }
    }

    if (childLeft < right) {
      T keyAtDepth = Preconditions.checkNotNull(leftEntry).getKey().get(depth);
      for (int i = childLeft + 1; i < right; ++i) {
        Map.Entry<List<T>, V> e = entries.get(i);
        T k = e.getKey().get(depth);
        if (keyAtDepth.compareTo(k) != 0) {
          b.put(keyAtDepth, collate(entries, depth + 1, childLeft, i));
          childLeft = i;
          keyAtDepth = k;
        }
      }
      if (childLeft < right) {
        b.put(keyAtDepth, collate(entries, depth + 1, childLeft, right));
      }
    }

    return new Trie<>(b.build(), value);
  }
}
