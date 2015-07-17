/*
 *
 *  * Copyright 2014 http://Bither.net
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *    http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package net.bither.bitherj.core;

import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.script.Script;
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.utils.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by songchenwen on 15/6/2.
 */
public class EnterpriseHDMAddress extends Address {

    private EnterpriseHDMKeychain keychain;
    private Pubs pubs;

    public EnterpriseHDMAddress(Pubs pubs, EnterpriseHDMKeychain keychain, boolean isSyncComplete) {
        this(pubs, pubs.getAddress(), keychain, isSyncComplete);
    }

    public EnterpriseHDMAddress(Pubs pubs, String address, EnterpriseHDMKeychain keychain,
                                boolean isSyncComplete) {
        super(address, pubs.getMultiSigScript().getProgram(), pubs.index, isSyncComplete, false,
                false, null);
        this.pubs = pubs;
        this.keychain = keychain;
    }


    public EnterpriseHDMKeychain getKeychain() {
        return keychain;
    }

    public int getIndex() {
        return pubs.index;
    }

    public List<byte[]> getPubkeys() {
        return pubs.pubs;
    }

    public int pubCount() {
        return keychain.pubCount();
    }

    public int threshold() {
        return keychain.threshold();
    }

    @Override
    public boolean isHDM() {
        return true;
    }

    @Override
    public String getFullEncryptPrivKey() {
        throw new RuntimeException("hdm address can't get encrypted private key");
    }

    @Override
    public void updateSyncComplete() {
        AbstractDb.enterpriseHDMProvider.updateSyncComplete(EnterpriseHDMAddress.this);
    }

    public static final class Pubs {

        public ArrayList<byte[]> pubs;
        public int index;
        public int threshold;

        public Pubs(int index, int threshold, List<byte[]> pubs) {
            this.index = index;
            this.threshold = threshold;
            this.pubs = new ArrayList<byte[]>();
            this.pubs.addAll(pubs);
        }

        public Pubs(int index, int threshold) {
            this.index = index;
            this.threshold = threshold;
            pubs = new ArrayList<byte[]>();
        }

        public void addPub(byte[] pub) {
            pubs.add(pub);
        }

        public Script getMultiSigScript() {
            return ScriptBuilder.createMultiSigOutputScript(threshold, pubs);
        }

        public String getAddress() {
            return Utils.toP2SHAddress(Utils.sha256hash160(getMultiSigScript().getProgram()));
        }
    }
}
