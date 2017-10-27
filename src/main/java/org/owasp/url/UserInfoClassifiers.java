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

import org.owasp.url.Diagnostic.Receiver;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;

/**
 * Static API for {@link UserInfoClassifier}.
 */
public final class UserInfoClassifiers {
  /**
   * Matches a URL that lacks userInfo, returns invalid if there is a password or
   * if there is a userName but not {@link Scheme#mayHaveUserName}.
   */
  public static final UserInfoClassifier NO_PASSWORD_BUT_USERNAME_IF_ALLOWED_BY_SCHEME
  = new NoPasswordButUserNameIfAllowedByScheme();

  private UserInfoClassifiers() {
    // Static API
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static UserInfoClassifier or(UserInfoClassifier... cs) {
    return or(ImmutableList.copyOf(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static UserInfoClassifier or(Iterable<? extends UserInfoClassifier> cs) {
    return UrlClassifierOr.abstractOr(
        cs, UserInfoClassifierOr.UI_FALSE,
        new Function<ImmutableList<UserInfoClassifier>, UserInfoClassifier>() {

          @Override
          public UserInfoClassifier apply(ImmutableList<UserInfoClassifier> flat) {
            return new UserInfoClassifierOr(flat);
          }

        });
  }

  /**
   * A classifier that does not match when applying cs in order results in a
   * failure to match before a classification of INVALID.
   *
   * @param cs the operands.
   * @return The conjunction of cs.
   */
  public static UserInfoClassifier and(UserInfoClassifier... cs) {
    return and(ImmutableList.copyOf(cs));
  }

  /**
   * A classifier that does not match when applying cs in order results in a
   * failure to match before a classification of INVALID.
   *
   * @param cs the operands.
   * @return The conjunction of cs.
   */
  public static UserInfoClassifier and(Iterable<? extends UserInfoClassifier> cs) {
    return UrlClassifierAnd.abstractAnd(
        cs, UserInfoClassifierAnd.UI_TRUE,
        new Function<ImmutableList<UserInfoClassifier>, UserInfoClassifier>() {

          @Override
          public UserInfoClassifier apply(ImmutableList<UserInfoClassifier> flat) {
            return new UserInfoClassifierAnd(flat);
          }

        });
  }

  /**
   * A classifier that matches all inputs.
   */
  public static UserInfoClassifier any() {
    return UserInfoClassifierAnd.UI_TRUE;
  }
}

final class UserInfoClassifierOr
extends UrlClassifierOr<UserInfoClassifier> implements UserInfoClassifier {

  static final UserInfoClassifierOr UI_FALSE =
      new UserInfoClassifierOr(ImmutableList.<UserInfoClassifier>of());

  static final Function<ImmutableList<UserInfoClassifier>, UserInfoClassifier> UI_NEW =
      new Function<ImmutableList<UserInfoClassifier>, UserInfoClassifier>() {

        @Override
        public UserInfoClassifier apply(ImmutableList<UserInfoClassifier> cs) {
          return new UserInfoClassifierOr(cs);
        }

      };

  UserInfoClassifierOr(ImmutableList<UserInfoClassifier> cs) {
    super(cs);
  }
}

final class UserInfoClassifierAnd
extends UrlClassifierAnd<UserInfoClassifier> implements UserInfoClassifier {

  static final UserInfoClassifierAnd UI_TRUE =
      new UserInfoClassifierAnd(ImmutableList.<UserInfoClassifier>of());

  static final Function<ImmutableList<UserInfoClassifier>, UserInfoClassifier> UI_NEW =
      new Function<ImmutableList<UserInfoClassifier>, UserInfoClassifier>() {

        @Override
        public UserInfoClassifier apply(ImmutableList<UserInfoClassifier> cs) {
          return new UserInfoClassifierAnd(cs);
        }

      };

  UserInfoClassifierAnd(ImmutableList<UserInfoClassifier> cs) {
    super(cs);
  }
}

final class NoPasswordButUserNameIfAllowedByScheme implements UserInfoClassifier {

  enum Diagnostics implements Diagnostic {
    PASSWORD_PRESENT,
    USERINFO_NOT_ALLOWED_WITH_SCHEME,
  }

  @Override
  public Classification apply(UrlValue x, Receiver<? super UrlValue> r) {
    Authority auth = x.getAuthority(r);
    if (auth != null) {
      // An authority has the form [uname[':'[password]]'@']host[':'port]
      if (auth.password.isPresent()) {
        // There's a password.
        // We don't encourage password matching in URL classifiers.
        // Don't put passwords in URLs.
        // Tell your friends.
        r.note(Diagnostics.PASSWORD_PRESENT, x);
        return Classification.INVALID;
      }
      if (!x.scheme.mayHaveUserName && auth.userName.isPresent()) {
        r.note(Diagnostics.USERINFO_NOT_ALLOWED_WITH_SCHEME, x);
        return Classification.INVALID;
      }
    }
    return Classification.MATCH;
  }
}
