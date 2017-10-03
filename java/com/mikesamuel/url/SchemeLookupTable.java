package com.mikesamuel.url;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

/** Maps scheme names like "http" or "HTTP" to Schemes. */
public final class SchemeLookupTable {
  final ImmutableMap<String, Scheme> additionalSchemes;

  /** */
  public static final SchemeLookupTable BUILTINS_ONLY =
      new SchemeLookupTable(ImmutableList.of());

  /**
   * @param additionalSchemes any schemes beyond the builtins to recognize.
   */
  public SchemeLookupTable(Iterable<? extends Scheme> additionalSchemes) {
    ImmutableMap.Builder<String, Scheme> b = ImmutableMap.builder();
    for (Scheme s : additionalSchemes) {
      for (String schemeName : s.lcaseNames) {
        b.put(schemeName, s);
      }
    }
    this.additionalSchemes = b.build();
  }

  /**
   * Looks up a scheme by name.
   * @return {@link Scheme#UNKNOWN} if schemeName is not recognized.
   */
  public Scheme schemeForName(String schemeName) {
    String lSchemeName = Ascii.toLowerCase(schemeName);
    Scheme s = additionalSchemes.get(lSchemeName);
    if (s == null) {
      s = BuiltinScheme.forName(lSchemeName);
    }
    return s != null ? s : Scheme.UNKNOWN;
  }

}
