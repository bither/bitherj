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

package net.bither.bitherj.runnable;

import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.db.AbstractDb;

public class EditPasswordThread extends Thread {


    public static interface EditPasswordListener {
        public void onSuccess();

        public void onFailed();

    }

    private SecureCharSequence oldPassword;
    private SecureCharSequence newPassword;
    private EditPasswordListener listener;

    public EditPasswordThread(SecureCharSequence oldPassword, SecureCharSequence newPassword,
                              EditPasswordListener listener) {
        this.oldPassword = oldPassword;
        this.newPassword = newPassword;
        this.listener = listener;
    }

    @Override
    public void run() {
        final boolean result = editPassword(oldPassword, newPassword);
        oldPassword.wipe();
        newPassword.wipe();
        if (listener != null) {
            if (result) {
                listener.onSuccess();
            } else {
                listener.onFailed();
            }
        }

    }

    public boolean editPassword(SecureCharSequence oldPassword, SecureCharSequence newPassword) {
        try {
            return AbstractDb.addressProvider.changePassword(oldPassword, newPassword);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

}
