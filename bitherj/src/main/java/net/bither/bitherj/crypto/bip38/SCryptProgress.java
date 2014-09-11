/*
 * Copyright 2014 http://Bither.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.bitherj.crypto.bip38;

import java.io.Serializable;

public class SCryptProgress implements Serializable{
   private static final long serialVersionUID = 1L;
   
   private int n;
   private long totalWork;
   private int progressN1;
   private int progressN2;
   private int progressP;
   private volatile boolean _terminate;

   public SCryptProgress(int n, int r, int p) {
      this.n = n;
      totalWork = ((long) n * 2) * (long) p;
      progressN1 = 0;
      progressN2 = 0;
      progressP = 0;
      _terminate = false;
   }

   public void setProgressN1(int n1) throws InterruptedException {
      // Don't synchronize due to performance. There will be a microscopic
      // change of getting a progress that is off by one
      progressN1 = n1;
      if (_terminate) {
         throw new InterruptedException();
      }
   }

   public void setProgressN2(int n2) throws InterruptedException {
      // Don't synchronize due to performance. There will be a microscopic
      // change of getting a progress that is off by one
      progressN2 = n2;
      if (_terminate) {
         throw new InterruptedException();
      }
   }

   public synchronized void setProgressP(int p) throws InterruptedException {
      progressP = p;
      progressN1 = 0;
      progressN2 = 0;
      if (_terminate) {
         throw new InterruptedException();
      }
   }

   public void terminate() {
      _terminate = true;
   }

   public synchronized double getProgress() {
      long work = (long) progressP * ((long) n * 2) + (long) progressN1 + (long) progressN2;
      return (double) work / totalWork;
   }

}
