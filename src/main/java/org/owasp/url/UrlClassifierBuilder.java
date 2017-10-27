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

import java.util.Arrays;
import java.util.EnumSet;
import java.util.regex.Pattern;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;

/**
 * Specifying multiple sub-classifiers of the same kind ORs those
 * together.
 * Classifiers of one kind AND with classifiers of another kind except
 * where stated below.
 *
 * <p>For example,
 * <pre>
 *    .scheme(HTTP, HTTPS)
 *    .scheme(FILE)
 *    .host("example.com")
 *    .pathGlob("/foo/**")
 *    .pathGlob("/*.js")
 * </pre>
 * corresponds to pseudocode like
 * <pre>
 * ((url.scheme in (HTTP, HTTPS))
 *    or (url.scheme is FILE))
 * and (not (url.has_authority or url.scheme.naturallyHasAuthority)
 *      or url.authority == "example.com")
 * and (not (url.has_path or url.scheme.naturallyHasPath)
 *      or glob("/foo/**").matches(url.path)
 *      or glob("/*.js").matches(url.path))
 * </pre>
 *
 * <p>If a URL's scheme does not naturally have an authority,
 * and it does not have an authority then any authority classifier
 * is ignored.
 * For example, {@code file:} URLs and {@code data:} URLs do not naturally
 * have an authority, though they may.
 * {@code file:} by the nature of the scheme, and
 * {@code data:} because it is not a hierarchical scheme.
 * Any authority classifier will be ignored for "{@code data:text/plain,}"
 * and for "{@code file:///}" but not for "{@code file://example.com/}".
 *
 * <p>If a URL's scheme naturally has an authority then it MUST have an
 * authority and any authority classifier must also pass.
 * For example: "{@code http:///}" will never pass any classifier.
 * <a href="https://w3c.github.io/FileAPI/#DefinitionOfScheme">Blobs</a>
 * naturally have an authority.
 *
 * <p>If a URL's scheme does not naturally have a path or query component
 * then path and query classifiers will not be applied.
 * All hierarchical URLs naturally have both, so a {@code file:} URL MUST
 * match any query classifiers.  Some opaque schemes also do, so any
 * query classifier will be applied to
 * "{@code mailto:name@domain.tld?subject=Hello+World}".
 *
 * <p>All URLs are treated as URI References, so fragments are allowed
 * regardless of scheme.
 *
 * <p>If a URL's scheme does not naturally have embedded content then
 * any content classifier is ignored.  For example, "{@code http:}" and
 * other hierarchical URLs do not have embedded content.
 *
 * <p>If a URL's scheme does naturally have embedded content, then it
 * MUST have embedded content and any content classifier must match
 * that content.  For example: "{@code data:text/plain;base64}
 * (note the missing '{@code ,}' will not match any classifier) but
 * "{@code data:text/plain,}" will match if the content
 * classifier matches the empty string.  Schemes that naturally have
 * embedded content include "{@code about:}", "{@code blob:}", "{@code data:}", and
 * "{@code javascript:}".
 *
 * @see UrlClassifiers#builder
 */
public final class UrlClassifierBuilder {
  UrlClassifierBuilder() {
    // Use static factory
  }

  /**
   * Builds a classifier based on previous allow/match decisions.
   * This may be reused after a call to build and subsequent calls to
   * allow/match methods will not affect previously built classifiers.
   * @return this
   */
  public UrlClassifier build() {
    EnumSet<UrlClassifierImpl.GlobalFlag> flags =
        EnumSet.noneOf(UrlClassifierImpl.GlobalFlag.class);
    if (this.allowPathsThatReachRootsParent) {
      flags.add(UrlClassifierImpl.GlobalFlag.ALLOW_PATHS_THAT_REACH_ROOT_PARENT);
    }
    if (this.matchesNuls) {
      flags.add(UrlClassifierImpl.GlobalFlag.ALLOW_NULS);
    }
    ImmutableSet<UrlValue.UrlSpecCornerCase> toleratedCornerCaseSet =
        Sets.immutableEnumSet(this.toleratedCornerCases);
    ImmutableSet<Scheme> allowedSchemeSet = allowedSchemes.build();
    MediaTypeClassifier mtc = mediaTypeClassifier != null
        ? mediaTypeClassifier
        : MediaTypeClassifiers.or();
    AuthorityClassifier ac = authorityClassifier != null
        ? authorityClassifier
        : AuthorityClassifiers.any();
    ImmutableSet<String> positivePathGlobSet = positivePathGlobs.build();
    ImmutableSet<String> negativePathGlobSet = negativePathGlobs.build();
    Pattern positivePathPattern = positivePathGlobSet.isEmpty()
        ? null
        : PathGlobs.toPattern(positivePathGlobSet);
    Pattern negativePathPattern = negativePathGlobSet.isEmpty()
        ? null
        : PathGlobs.toPattern(negativePathGlobSet);
    QueryClassifier qc = queryClassifier != null
        ? queryClassifier
        : QueryClassifiers.any();
    FragmentClassifier fc = fragmentClassifier != null
        ? fragmentClassifier
        : FragmentClassifiers.any();
    ContentClassifier cc = contentClassifier != null
        ? contentClassifier
        : ContentClassifiers.any();

    return new UrlClassifierImpl(
        flags,
        toleratedCornerCaseSet,
        allowedSchemeSet,
        mtc,
        ac,
        positivePathPattern,
        negativePathPattern,
        qc,
        fc,
        cc
        );
  }


  //// Flags that affect multiple sub-classifiers.
  private boolean matchesNuls = false;
  private boolean allowPathsThatReachRootsParent = false;
  private final EnumSet<UrlValue.UrlSpecCornerCase> toleratedCornerCases =
      EnumSet.noneOf(UrlValue.UrlSpecCornerCase.class);

  /**
   * URLs with NULs are a common problem case.
   * By default no URL is matched that contains the raw char 0.
   * {@code data:} URLs that need to embed NULs
   * in content typically base64 encode and NULs in encoded content will
   * not cause a mismatch.
   * If allowing NULs is definitely required enable this.
   *
   * @param allow true to allow NULs.
   * @return this
   */
  public UrlClassifierBuilder nuls(boolean allow) {
    this.matchesNuls = allow;
    return this;
  }

  /**
   * If not enabled (the default), apply(x) will return INVALID for
   * {@linkplain UrlValue#pathSimplificationReachedRootsParent overlong paths} like
   * "{@code ../../../...}".
   *
   * <p>These paths are rejected as INVALId by default.
   *
   * <p>It is safe to enable this if you plan on substituting
   * {@link UrlValue#urlText} for {@link UrlValue#originalUrlText}
   * in your output, but not if you plan on using the original text
   * or other computations have already made assumptions based on it.
   *
   * @param enable true to tolerate.
   * @return this
   */
  public UrlClassifierBuilder rootParent(boolean enable) {
    this.allowPathsThatReachRootsParent = enable;
    return this;
  }

  /**
   * Don't reject as {@linkplain Classification#INVALID invalid} URLs
   * that trigger the given corner cases.
   *
   * @param cornerCases to tolerate.  Unioned with previous calls' arguments.
   * @return this
   */
  public UrlClassifierBuilder tolerate(UrlValue.UrlSpecCornerCase... cornerCases) {
    return tolerate(Arrays.asList(cornerCases));
  }

  /**
   * Don't reject as {@linkplain Classification#INVALID invalid} URLs
   * that trigger the given corner cases.
   *
   * @param cornerCases to tolerate.  Unioned with previous calls' arguments.
   * @return this
   */
  public UrlClassifierBuilder tolerate(
      Iterable<? extends UrlValue.UrlSpecCornerCase> cornerCases) {
    for (UrlValue.UrlSpecCornerCase cornerCase : cornerCases) {
      this.toleratedCornerCases.add(cornerCase);
    }
    return this;
  }


  private final ImmutableSet.Builder<Scheme> allowedSchemes = ImmutableSet.builder();
  private MediaTypeClassifier mediaTypeClassifier;

  //// Sub-classifiers of kind scheme     MATCH_ME://...
  /**
   * Allows URLs with the given schemes assuming any per-component classifiers
   * also pass.
   *
   * @param schemes to white-list.
   * @return this
   */
  public UrlClassifierBuilder scheme(Scheme... schemes) {
    return scheme(Arrays.asList(schemes));
  }
  /**
   * Allows URLs with the given schemes assuming any per-component classifiers
   * also pass.
   *
   * @param schemes to white-list.
   * @return this
   */
  public UrlClassifierBuilder scheme(Iterable<? extends Scheme> schemes) {
    this.allowedSchemes.addAll(schemes);
    return this;
  }
  /**
   * Matches the {@linkplain BuiltinScheme#DATA <tt>data:</tt>} scheme with
   * an additional constraint on the media type.
   * <p>We special-case {@code data:} because content-types are not attached to
   * URLs with other schemes and its rare to want to match a data: URL
   * without caring about the type of data.
   *
   * @param c will be applied to any data: URLs media type.
   * @return this
   */
  public UrlClassifierBuilder schemeData(MediaTypeClassifier c) {
    this.allowedSchemes.add(BuiltinScheme.DATA);
    this.mediaTypeClassifier = this.mediaTypeClassifier == null
        ? c
        : MediaTypeClassifiers.or(this.mediaTypeClassifier, c);
    return this;
  }

  //// Sub-classifiers of kind authority  http://MATCH_ME/...
  private AuthorityClassifier authorityClassifier;
  /**
   * Specifies that any matching URLs must naturally have no authority
   * or have one that matches the given authority classifier.
   * <p>
   * If called multiple times, at least one authority classifier
   * must match for the URL as a whole to match.
   *
   * @param ac receives the URL when it's time to check the authority.
   * @return this
   */
  public UrlClassifierBuilder authority(AuthorityClassifier ac) {
    this.authorityClassifier = this.authorityClassifier == null
        ? ac
        : AuthorityClassifiers.or(this.authorityClassifier, ac);
    return this;
  }

  //// Sub-classifiers of kind path       http://example.com/MATCH_ME?...
  private final ImmutableSet.Builder<String> positivePathGlobs = ImmutableSet.builder();
  private final ImmutableSet.Builder<String> negativePathGlobs = ImmutableSet.builder();
  /**
   * Allow URLs whose paths match the given globs.
   *
   * <p>In the glob, "{@code **}" matches one or more path components and
   * "{@code *}" matches a single path component at most.
   * Matching is done after processing the special path components "{@code ..}" and
   * "{@code .}".
   *
   * <p>If a glob ends in "{@code /?}" then a slash is optionally allowed at the end.
   * For example,
   * <ul>
   *   <li>"<tt>**<!--->/*.html</tt>" matches all paths that end with
   *     "<tt>.html</tt>"
   *   <li>"<tt>**.html</tt>" matches the same.
   *   <li>"<tt>*.html</tt>" matches all single-component paths that end with
   *     "<tt>.html</tt>"
   *   <li>"<tt>foo/**<!--->/bar</tt>" matches all paths that start with a
   *     component "<tt>foo</tt>", followed by zero or more other components
   *     and ending with a component "<tt>bar</tt>".
   *   <li>"<tt>foo/</tt>" matches "<tt>foo/</tt>" but not "<tt>foo</tt>"
   *     while "<tt>foo/?</tt>" matches both.
   * </ul>
   * The following code-points may be %-encoded in a path glob to allow them
   * to be treated literally as part of a path component: ('/', '*', '?', '%').
   *
   * @param pathGlobs if at least one glob is specified,
   *      the path must match at least one of these globs for the URL to match.
   * @return this
   */
  public UrlClassifierBuilder pathGlob(String... pathGlobs) {
    return pathGlob(ImmutableList.copyOf(pathGlobs));
  }
  /**
   * @see #pathGlob(String...)
   *
   * @param pathGlobs if at least one glob is specified,
   *      the path must match at least one of these globs for the URL to match.
   * @return this
   */
  public UrlClassifierBuilder pathGlob(
      Iterable<? extends String> pathGlobs) {
    for (String pathGlob : pathGlobs) {
      Optional<String> decPathGlob = Percent.decode(pathGlob);
      Preconditions.checkArgument(
          decPathGlob.isPresent(), "Invalid %-encoding in path glob", pathGlob);
      positivePathGlobs.add(pathGlob);
    }
    return this;
  }
  /**
   * Like {@link #pathGlob(String...)} but the path must not match.
   *
   * @param pathGlobs if any of these matches the URL's path, the URL will not match.
   * @return this
   */
  public UrlClassifierBuilder notPathGlob(String... pathGlobs) {
    return notPathGlob(ImmutableList.copyOf(pathGlobs));
  }
  /**
   * Like {@link #pathGlob(String...)} but the path must not match.
   *
   * @param pathGlobs if any of these matches the URL's path, the URL will not match.
   * @return this
   */
  public UrlClassifierBuilder notPathGlob(
      Iterable<? extends String> pathGlobs) {
    for (String pathGlob : pathGlobs) {
      Optional<String> decPathGlob = Percent.decode(pathGlob);
      Preconditions.checkArgument(
          decPathGlob.isPresent(), "Invalid %-encoding in path glob", pathGlob);
      negativePathGlobs.add(pathGlob);
    }
    return this;
  }

  private QueryClassifier queryClassifier;
  //// Sub-classifiers of kind query      http://example.com/?MATCH_ME#...
  /**
   * Specifies a query classifier that, in order for the URL to match,
   * must match the URL's query if the URL's scheme naturally has a query.
   *
   * @param qc is applied to the URL when it's time to check the query portion.
   * @return this
   */
  public UrlClassifierBuilder query(QueryClassifier qc) {
    this.queryClassifier = this.queryClassifier == null
        ? qc
        : QueryClassifiers.or(this.queryClassifier, qc);
    return this;
  }
  /**
   * Reverses the classifier where not(INVALID) == INVALID.
   *
   * @param qc is applied to the URL when it's time to check the query portion.
   * @return this
   */
  public UrlClassifierBuilder notQuery(QueryClassifier qc) {
    return query(new NotQueryClassifier(qc));
  }
  static final class NotQueryClassifier implements QueryClassifier {
    final QueryClassifier qc;

    NotQueryClassifier(QueryClassifier qc) {
      this.qc = qc;
    }

    @Override
    public Classification apply(
        UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
      return qc.apply(x, Diagnostic.Receiver.NULL).invert();
    }
  }

  //// Sub-classifiers of kind fragment   http://example.com/#MATCH_ME
  private FragmentClassifier fragmentClassifier;
  /**
   * Specifies a fragment classifier that, in order for the URL to match,
   * must match the URL's fragment.
   *
   * @param fc is applied to the URL when it's time to check the fragment.
   * @return this
   */
  public UrlClassifierBuilder fragment(FragmentClassifier fc) {
    this.fragmentClassifier = this.fragmentClassifier == null
        ? fc
        : FragmentClassifiers.or(this.fragmentClassifier, fc);
    return this;
  }
  /**
   * Reverses the classifier where not(INVALID) == INVALID.
   *
   * @param fc is applied to the URL when it's time to check the fragment.
   * @return this
   */
  public UrlClassifierBuilder notFragment(
      FragmentClassifier fc) {
    return fragment(new NotFragmentClassifier(fc));
  }
  static final class NotFragmentClassifier implements FragmentClassifier {
    final FragmentClassifier fc;

    NotFragmentClassifier(FragmentClassifier fc) {
      this.fc = fc;
    }

    @Override
    public Classification apply(
        UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
      return fc.apply(x, Diagnostic.Receiver.NULL).invert();
    }
  }

  //// Sub-classifiers of kind content    javascript:MATCH_ME
  ////                                    data:foo/bar,MATCH_ME
  private ContentClassifier contentClassifier;
  /**
   * Matches when the scheme-specific part matches the classifier.
   * This is applied after any content metadata is stripped and after decoding.
   * For example,
   * data: URLs have the mime-type and any base64 specifier stripped, and if the
   * base64 is specified, the content is base64 decoded;
   * blob: URLs have the origin stripped.
   *
   * @param c is applied to the URL when it's time to check the content.
   * @return this
   */
  public UrlClassifierBuilder content(ContentClassifier c) {
    this.contentClassifier = this.contentClassifier == null
        ? c
        : ContentClassifiers.or(this.contentClassifier, c);
    return this;
  }
}

final class UrlClassifierImpl implements UrlClassifier {
  final boolean matchesNuls;
  final boolean allowPathsThatReachRootsParent;
  final ImmutableSet<UrlValue.UrlSpecCornerCase> toleratedCornerCaseSet;
  final ImmutableSet<Scheme> allowedSchemeSet;
  final MediaTypeClassifier mediaTypeClassifier;
  final AuthorityClassifier authorityClassifier;
  final Pattern positivePathPattern;
  final Pattern negativePathPattern;
  final QueryClassifier queryClassifier;
  final FragmentClassifier fragmentClassifier;
  final ContentClassifier contentClassifier;

  UrlClassifierImpl(
      EnumSet<GlobalFlag> flags,
      ImmutableSet<UrlValue.UrlSpecCornerCase> toleratedCornerCaseSet,
      ImmutableSet<Scheme> allowedSchemeSet,
      MediaTypeClassifier mediaTypeClassifier,
      AuthorityClassifier authorityClassifier,
      Pattern positivePathPattern,
      Pattern negativePathPattern,
      QueryClassifier queryClassifier,
      FragmentClassifier fragmentClassifier,
      ContentClassifier contentClassifier) {
    this.matchesNuls = flags.contains(GlobalFlag.ALLOW_NULS);
    this.allowPathsThatReachRootsParent = flags.contains(
        GlobalFlag.ALLOW_PATHS_THAT_REACH_ROOT_PARENT);
    this.toleratedCornerCaseSet = toleratedCornerCaseSet;
    this.allowedSchemeSet = allowedSchemeSet;
    this.mediaTypeClassifier = mediaTypeClassifier;
    this.authorityClassifier = authorityClassifier;
    this.positivePathPattern = positivePathPattern;
    this.negativePathPattern = negativePathPattern;
    this.queryClassifier = queryClassifier;
    this.fragmentClassifier = fragmentClassifier;
    this.contentClassifier = contentClassifier;
  }

  enum GlobalFlag {
    ALLOW_NULS,
    ALLOW_PATHS_THAT_REACH_ROOT_PARENT,
  }

  enum Diagnostics implements Diagnostic {
    UNTOLERATED_CORNER_CASE,
    NULS,
    MALFORMED_ACCORING_TO_SCHEME,
    DISALLOWED_SCHEME,
    AUTHORITY_DID_NOT_MATCH,
    MALFORMED_PATH,
    PATH_SIMPLIFICATION_REACHED_ROOTS_PARENT,
    PATH_MATCHED_NEGATIVE_PATH_GLOBS,
    PATH_DID_NOT_MATCH_PATH_GLOBS,
    QUERY_DID_NOT_MATCH,
    MEDIA_TYPE_DID_NOT_MATCH,
    CONTENT_DID_NOT_MATCH,
    FRAGMENT_DID_NOT_MATCH,
  }

  @Override
  public Classification apply(
      UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
    Diagnostic.CollectingReceiver<? super UrlValue> cr =
        Diagnostic.CollectingReceiver.from(r);

    if (!this.toleratedCornerCaseSet.containsAll(x.cornerCases)) {
      r.note(Diagnostics.UNTOLERATED_CORNER_CASE, x);
      return Classification.INVALID;
    }
    if (!matchesNuls && x.originalUrlText.indexOf('\0') >= 0) {
      r.note(Diagnostics.NULS, x);
      return Classification.INVALID;
    }
    if (x.ranges == null) {
      r.note(Diagnostics.MALFORMED_ACCORING_TO_SCHEME, x);
      return Classification.INVALID;
    }

    Scheme s = x.scheme;
    if (!allowedSchemeSet.contains(s)) {
      r.note(Diagnostics.DISALLOWED_SCHEME, x);
      return Classification.NOT_A_MATCH;
    }
    if (s.naturallyHasAuthority
        || x.ranges.authorityLeft < x.ranges.authorityRight) {
      // Make sure we are alerted to any invalid authorities.
      if (x.getAuthority(r) == null) {
        return Classification.INVALID;
      }
      Classification c = authorityClassifier.apply(x, cr);
      if (c != Classification.MATCH) {
        cr.flush();
        r.note(Diagnostics.AUTHORITY_DID_NOT_MATCH, x);
        return c;
      }
    }
    String path = x.getRawPath();
    if (path != null) {
      Optional<String> decPathOpt = Percent.decode(path);
      if (!decPathOpt.isPresent()) {
        r.note(Diagnostics.MALFORMED_PATH, x);
        return Classification.INVALID;
      }
      if (!allowPathsThatReachRootsParent
          && x.pathSimplificationReachedRootsParent) {
        r.note(Diagnostics.PATH_SIMPLIFICATION_REACHED_ROOTS_PARENT, x);
        return Classification.NOT_A_MATCH;
      }
      String decPath = decPathOpt.get();
      if (negativePathPattern != null
          && negativePathPattern.matcher(decPath).matches()) {
        r.note(Diagnostics.PATH_MATCHED_NEGATIVE_PATH_GLOBS, x);
        return Classification.NOT_A_MATCH;
      }
      if (positivePathPattern != null
          && !positivePathPattern.matcher(decPath).matches()) {
        r.note(Diagnostics.PATH_DID_NOT_MATCH_PATH_GLOBS, x);
        return Classification.NOT_A_MATCH;
      }
    }

    if (mediaTypeClassifier != null) {
      if (x.getContentMediaType() != null
          || x.scheme == BuiltinScheme.DATA) {
        cr.clear();
        Classification c = mediaTypeClassifier.apply(x, cr);
        if (c != Classification.MATCH) {
          cr.flush();
          r.note(Diagnostics.MEDIA_TYPE_DID_NOT_MATCH, x);
          return c;
        }
      }
    }
    if (s.naturallyEmbedsContent || x.ranges.contentLeft >= 0) {
      cr.clear();
      Classification c = contentClassifier.apply(x, cr);
      if (c != Classification.MATCH) {
        cr.flush();
        r.note(Diagnostics.CONTENT_DID_NOT_MATCH, x);
        return c;
      }
    }

    if (s.naturallyHasQuery || x.ranges.queryLeft >= 0) {
      cr.clear();
      Classification c = queryClassifier.apply(x, cr);
      if (c != Classification.MATCH) {
        cr.flush();
        r.note(Diagnostics.QUERY_DID_NOT_MATCH, x);
        return c;
      }
    }

    cr.clear();
    Classification c = fragmentClassifier.apply(x, r);
    if (c != Classification.MATCH) {
      cr.flush();
      r.note(Diagnostics.FRAGMENT_DID_NOT_MATCH, x);
    }
    return c;
  }
}
