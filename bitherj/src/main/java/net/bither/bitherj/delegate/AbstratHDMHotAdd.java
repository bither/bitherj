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

package net.bither.bitherj.delegate;


import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.core.HDMBId;
import net.bither.bitherj.core.HDMKeychain;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.hd.HDKeyDerivation;
import net.bither.bitherj.utils.Utils;

import java.util.Arrays;
import java.util.List;

public abstract class AbstratHDMHotAdd {


    public static interface IGenerateHDMKeyChain {
        public abstract void generateHDMKeyChain(HDMKeychain hdmKeychain);

        public abstract void beginCompleteAddress();

        public abstract void completeAddrees(List<HDMAddress> hdmAddresses);

        public abstract int getCanAddHDMCount(HDMKeychain keychain);


    }


    public interface IHDMHotAddDelegate {
        public void moveToCold(boolean anim);

        public void moveToServer(boolean anim);

        public void moveToFinal(boolean isFinal);

        public void callHDMKeychainHotUEntropy();

        public void callScanColdAccount();

        public void callScanSignedHDMServerQRCode();


    }
    protected IPasswordGetter passwordGetter;
    protected boolean isServerClicked = false;
    protected HDMBId hdmBid;
    protected byte[] coldRoot;

    public AbstractHDMSingular hdmSingular;

    protected IHDMHotAddDelegate delegate;

    public AbstratHDMHotAdd(IHDMHotAddDelegate delegate) {
        this.delegate = delegate;
    }

    public boolean hdmKeychainLimit() {
        return AddressManager.isHDMKeychainLimit();
    }


    public void wipe() {
        if (passwordGetter != null) {
            passwordGetter.wipe();
        }
        if (coldRoot != null) {
            Utils.wipeBytes(coldRoot);
        }
    }

    protected void initHDMBidFromColdRoot() {
        if (hdmBid != null) {
            return;
        }
        DeterministicKey root = HDKeyDerivation.createMasterPubKeyFromExtendedBytes(Arrays.copyOf
                (coldRoot, coldRoot.length));
        DeterministicKey key = root.deriveSoftened(0);
        String address = Utils.toAddress(key.getPubKeyHash());
        root.wipe();
        key.wipe();
        hdmBid = new HDMBId(address);
    }


}
