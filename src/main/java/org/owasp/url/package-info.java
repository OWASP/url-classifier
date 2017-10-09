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

/**
 * A declarative syntax for
 * {@linkplain org.owasp.url.UrlClassifier classifiers} (tri-state predicates)
 * over {@linkplain org.owasp.url.UrlValue URL}s.
 *
 * <p>
 * {@link org.owasp.url.UrlClassifierBuilder} allows building
 * {@link org.owasp.url.UrlClassifier}s that map
 * {@link org.owasp.url.UrlValue}s to {@link org.owasp.url.Classification}.
 *
 * <p>
 * Sometimes it's useful to know why a URL did not match a classifier in which
 * case {@link org.owasp.url.Diagnostic} may come in handy.
 *
 * <p>
 * The other interfaces and classes are <tt>*ClassifierBuilder</tt>s that can be
 * used with {@link org.owasp.url.UrlClassifierBuilder} to vet parts of a
 * URL or are mostly of interest when writing one's own classifier.
 */
package org.owasp.url;