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

import java.util.List;

import com.google.common.collect.Lists;

/**
 * A message typically used to explain why a URLClassifier didn't match its input.
 */
public interface Diagnostic {

  /**
   * A receiver of diagnostic messages; may hook into a logger.
   * <p>
   * Implementations may assume that only one thread is using a receiver
   * at a time.
   *
   * @param <T> The type of the context value passed to {@link Receiver#note}.
   */
  public interface Receiver<T> {

    /**
     * Is called when a classification operation fails in a noteworthy way.
     *
     * @param d A diagnostic message.
     * @param context a value associated with the failure.
     */
    public void note(Diagnostic d, T context);

    /**
     * A receiver that does nothing when notified.
     */
    public static final Receiver<Object> NULL = NullReceiver.INSTANCE;
  }


  /**
   * A receiver that collects diagnostics while waiting to see whether a larger
   * operation fails.
   */
  public static abstract class CollectingReceiver<T> implements Receiver<T> {
    CollectingReceiver() {}

    /**
     * Clears the queue of notifications.
     */
    public abstract void clear();

    /**
     * Replays collected notifications to the underlying receiver in order.
     */
    public abstract void replay();

    /** Replay then clear. */
    public abstract void flush();

    /**
     * A receiver that collects diagnostics while waiting to see whether a larger
     * operation fails.
     *
     * @param r the underlying receiver to notify when flushing.
     * @param <T> The type of the context value passed to {@link Receiver#note}.
     * @return a receiver that will collect diagnostics until replayed onto r.
     */
    @SuppressWarnings("unchecked")
    public static <T> CollectingReceiver<T> from(Receiver<T> r) {
      if (r == NullReceiver.INSTANCE) {
        // This cast is unsound, but safe since all NullReceiver operations
        // are null-ops.
        // Returning null receiver allows code that wants to avoid
        // spending time figuring out exactly which diagnostic to show to
        // first test whether anyone is on the other end of the receiver
        // by checking whether it is the null receiver.
        return (CollectingReceiver<T>) NullReceiver.INSTANCE;
      }
      return new CollectingReceiverImpl<T>(r);
    }
  }
}


final class NullReceiver extends Diagnostic.CollectingReceiver<Object> {

  static final NullReceiver INSTANCE = new NullReceiver();

  private NullReceiver() {
    // Singleton
  }

  @Override
  public String toString() {
    return "(NullReceiver)";
  }

  @Override
  public void note(Diagnostic d, Object context) {
    // This block left intentionally blank.
  }

  @Override
  public void clear() {
    // This block left intentionally blank.
  }

  @Override
  public void replay() {
    // This block left intentionally blank.
  }

  @Override
  public void flush() {
    // This block left intentionally blank.
  }
}


final class CollectingReceiverImpl<T> extends Diagnostic.CollectingReceiver<T> {

  private final Diagnostic.Receiver<T> underlying;
  private List<Object> diagnosticsAndContexts;

  CollectingReceiverImpl(Diagnostic.Receiver<T> underlying) {
    this.underlying = underlying;
  }

  @Override
  public String toString() {
    return "(CollectingReceiver " + underlying + ")";
  }

  @Override
  public void note(Diagnostic d, T context) {
    if (diagnosticsAndContexts == null) {
      diagnosticsAndContexts = Lists.newArrayList();
    }
    diagnosticsAndContexts.add(d);
    diagnosticsAndContexts.add(context);
  }

  @Override
  public void clear() {
    if (diagnosticsAndContexts != null) {
      diagnosticsAndContexts.clear();
    }
  }

  @Override
  public void replay() {
    if (this.diagnosticsAndContexts != null) {
      for (int i = 0, n = this.diagnosticsAndContexts.size(); i < n; i += 2) {
        Diagnostic d = (Diagnostic) this.diagnosticsAndContexts.get(i);
        @SuppressWarnings("unchecked")  // Sound modulo thread-unsafety
        T context = (T) this.diagnosticsAndContexts.get(i + 1);
        this.underlying.note(d, context);
      }
    }
  }

  @Override
  public void flush() {
    if (this.diagnosticsAndContexts != null) {
      if (underlying instanceof CollectingReceiverImpl) {
        CollectingReceiverImpl<T> cri = (CollectingReceiverImpl<T>) underlying;
        if (cri.diagnosticsAndContexts == null || cri.diagnosticsAndContexts.isEmpty()) {
          List<Object> swap = cri.diagnosticsAndContexts;
          cri.diagnosticsAndContexts = this.diagnosticsAndContexts;
          this.diagnosticsAndContexts = swap;
        } else {
          cri.diagnosticsAndContexts.addAll(this.diagnosticsAndContexts);
          this.diagnosticsAndContexts.clear();
        }
      } else {
        replay();
        this.diagnosticsAndContexts.clear();
      }
    }
  }
}
