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

package net.bither.bitherj.core;

import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.Utils;

import org.junit.Test;

import java.util.Arrays;
import java.util.Date;

import static org.junit.Assert.*;

public class TxTest {
    @Test
    public void testDb() {
        Tx tx = new Tx();
        byte[] txHash = Utils.reverseBytes(
                Utils.hexStringToByteArray("f8a8335594d4c883f367e003cb3832015640f24714b48bd21cf6fbe84a617dfe"));
        tx.setTxHash(Utils.reverseBytes(
                Utils.hexStringToByteArray("f8a8335594d4c883f367e003cb3832015640f24714b48bd21cf6fbe84a617dfe")));
        tx.setBlockNo(304942);
        tx.setTxTime((int) new Date().getTime() / 1000);
        tx.setTxVer(1);
        In inPut = new In();
        inPut.setPrevTxHash(Utils.reverseBytes(
                Utils.hexStringToByteArray("d7f4efff7aeaffc1630dd3653e923a233fd463f9dc7dd4f97bb5cbf0cf99e56a")));
        inPut.setInSn(0);
        inPut.setTxHash(txHash);
        inPut.setInSequence(1);
        inPut.setInSignature(txHash);

        tx.addInput(inPut);
        Out out = new Out();
        out.setTxHash(txHash);
        out.setOutSn(0);
        out.setOutValue(3400);
        out.setOutScript(Utils.hexStringToByteArray("76a914abceaddc7d791f749671c17dfa36e9b17a4b055588ac"));
        out.setOutStatus(Out.OutStatus.spent);
        out.setOutAddress("test");
        tx.addOutput(out);
        AbstractDb.txProvider.add(tx);
        Tx testTx = AbstractDb.txProvider.getTxDetailByTxHash(txHash);
        assertEquals(Utils.bytesToHexString(tx.getTxHash()), Utils.bytesToHexString(testTx.getTxHash()));
    }

    @Test
    public void testConstructor() {
        byte[] rawTx = Utils.hexStringToByteArray("0100000001bdc0141fe3e5c2223a6d26a95acbf791042d93f9d9b8b38f133bf7adb5c1e293010000006a47304402202214770c0f5a9261190337273219a108132a4bc987c745db8dd6daded34b0dcb0220573de1d973166024b8342d6b6fef2a864a06cceee6aee13a910e5d8df465ed2a01210382b259804ad8d88b96a23222e24dd5a130d39588e78960c9e9b48a5b49943649ffffffff02a0860100000000001976a91479a7bf0bba8359561d4dab457042d7b632d5e64188ac605b0300000000001976a914b036c529faeca8040232cc4bd5918e709e90c4ff88ac00000000");
        Tx tx = new Tx(rawTx);
        byte[] txBytes = tx.bitcoinSerialize();
        assertTrue(Arrays.equals(rawTx, txBytes));
        byte[] exceptTxHash = Utils.reverseBytes(Utils.hexStringToByteArray("584985ca8a9ed57987da36ea3d13fe05a7c498f2098ddeb6c8d0f3214067640c"));
        byte[] txHash = tx.getTxHash();
        for (Out out : tx.getOuts()) {
            String outAddress = out.getOutAddress();
        }
        assertTrue(Arrays.equals(exceptTxHash, txHash));
    }
}
