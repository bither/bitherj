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

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.exception.TxBuilderException;
import net.bither.bitherj.script.Script;
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.utils.Utils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class TxBuilder {
    private static TxBuilder uniqueInstance = new TxBuilder();
    protected static long TX_FREE_MIN_PRIORITY = 57600000l;

    private TxBuilderProtocol emptyWallet = new TxBuilderEmptyWallet();
    private List<TxBuilderProtocol> txBuilders = new ArrayList<TxBuilderProtocol>();

    TxBuilder() {
        txBuilders.add(new TxBuilderDefault());
    }

    public static TxBuilder getInstance() {
        return uniqueInstance;
    }

    public Tx buildTxFromAllAddress(List<Out> unspendOuts, String changeAddress, List<Long> amounts, List<String> addresses) throws TxBuilderException {

        long value = 0;
        for (long amount : amounts) {
            value += amount;
        }

        if (value > getAmount(unspendOuts)) {
            throw new TxBuilderException.TxBuilderNotEnoughMoneyException(value - TxBuilder.getAmount(unspendOuts));
        }

        Tx emptyWalletTx = emptyWallet.buildTx(changeAddress, unspendOuts, prepareTx(amounts,
                addresses));
        if (emptyWalletTx != null && TxBuilder.estimationTxSize(emptyWalletTx.getIns().size(),
                emptyWalletTx.getOuts().size()) <= BitherjSettings.MAX_TX_SIZE) {
            return emptyWalletTx;
        } else if (emptyWalletTx != null) {
            throw new TxBuilderException(TxBuilderException.ERR_REACH_MAX_TX_SIZE_LIMIT_CODE);
        }

        for (long amount : amounts) {
            if (amount < Tx.MIN_NONDUST_OUTPUT) {
                throw new TxBuilderException(TxBuilderException.ERR_TX_DUST_OUT_CODE);
            }
        }

        boolean mayMaxTxSize = false;
        List<Tx> txs = new ArrayList<Tx>();
        for (TxBuilderProtocol builder : this.txBuilders) {
            Tx tx = builder.buildTx(changeAddress, unspendOuts, prepareTx(amounts, addresses));
            // note: need all unspent out is pay-to-pubkey-hash
            if (tx != null && TxBuilder.estimationTxSize(tx.getIns().size(), tx.getOuts().size()) <= BitherjSettings.MAX_TX_SIZE) {
                txs.add(tx);
            } else if (tx != null) {
                mayMaxTxSize = true;
            }
        }

        if (txs.size() > 0) {
            return txs.get(0);
        } else if (mayMaxTxSize) {
            throw new TxBuilderException(TxBuilderException.ERR_REACH_MAX_TX_SIZE_LIMIT_CODE);
        } else {
            throw new TxBuilderException();
        }
    }

    public Tx buildTx(Address address, String changeAddress, List<Long> amounts, List<String> addresses,boolean isBtc) throws TxBuilderException {
        Script scriptPubKey = null;
        if (address.isHDM()) {
            scriptPubKey = new Script(address.getPubKey());
        } else {
            scriptPubKey = ScriptBuilder.createOutputScript(address.address);
        }

        if (Utils.isEmpty(changeAddress)) {
            changeAddress = address.getAddress();
        }
        long value = 0;
        for (long amount : amounts) {
            value += amount;
        }
        List<Tx> unspendTxs;
        List<Out> unspendOuts;
        if (isBtc) {
            unspendTxs = AbstractDb.txProvider.getUnspendTxWithAddress(address.getAddress());
            unspendOuts = getUnspendOuts(unspendTxs);
        } else {
            unspendOuts = AbstractDb.txProvider.getUnspentOutputByBlockNo(BitherjSettings.BTCFORKBLOCKNO,address.getAddress());
            unspendTxs = AbstractDb.txProvider.getUnspendTxWithAddress(address.getAddress(),unspendOuts);
        }
        List<Out> canSpendOuts = getCanSpendOuts(unspendTxs);
        List<Out> canNotSpendOuts = getCanNotSpendOuts(unspendTxs);
        if (value > getAmount(unspendOuts)) {
            throw new TxBuilderException.TxBuilderNotEnoughMoneyException(value - TxBuilder.getAmount(unspendOuts));
        } else if (value > getAmount(canSpendOuts)) {
            throw new TxBuilderException.TxBuilderWaitConfirmException(TxBuilder.getAmount(canNotSpendOuts));
        } else if (value == TxBuilder.getAmount(unspendOuts) && TxBuilder.getAmount(canNotSpendOuts) != 0) {
            // there is some unconfirm tx, it will not empty wallet
            throw new TxBuilderException.TxBuilderWaitConfirmException(TxBuilder.getAmount(canNotSpendOuts));
        }

        Tx emptyWalletTx = emptyWallet.buildTx(address, changeAddress, unspendTxs, prepareTx(amounts, addresses));
        if (emptyWalletTx != null && TxBuilder.estimationTxSize(emptyWalletTx.getIns().size(), scriptPubKey, emptyWalletTx.getOuts(), address.isCompressed()) <= BitherjSettings.MAX_TX_SIZE) {
            return emptyWalletTx;
        } else if (emptyWalletTx != null) {
            throw new TxBuilderException(TxBuilderException.ERR_REACH_MAX_TX_SIZE_LIMIT_CODE);
        }

        for (long amount : amounts) {
            if (amount < Tx.MIN_NONDUST_OUTPUT) {
                throw new TxBuilderException(TxBuilderException.ERR_TX_DUST_OUT_CODE);
            }
        }

        boolean mayMaxTxSize = false;
        List<Tx> txs = new ArrayList<Tx>();
        for (TxBuilderProtocol builder : this.txBuilders) {
            Tx tx = builder.buildTx(address, changeAddress, unspendTxs, prepareTx(amounts, addresses));
            if (tx != null && TxBuilder.estimationTxSize(tx.getIns().size(), scriptPubKey, tx.getOuts(), address.isCompressed()) <= BitherjSettings.MAX_TX_SIZE) {
                txs.add(tx);
            } else if (tx != null) {
                mayMaxTxSize = true;
            }
        }

        if (txs.size() > 0) {
            return txs.get(0);
        } else if (mayMaxTxSize) {
            throw new TxBuilderException(TxBuilderException.ERR_REACH_MAX_TX_SIZE_LIMIT_CODE);
        } else {
            throw new TxBuilderException();
        }
    }

    static Tx prepareTx(List<Long> amounts, List<String> addresses) {
        Tx tx = new Tx();
        for (int i = 0; i < amounts.size(); i++) {
            tx.addOutput(amounts.get(i), addresses.get(i));
        }
        return tx;
    }

    static int estimationTxSize(int inCount, int outCount) {
        return 10 + 149 * inCount + 34 * outCount;
    }

    static int estimationTxSize(int inCount, Script scriptPubKey, List<Out> outs, boolean isCompressed) {
        int size = 8 + 2;

        Script redeemScript = null;
        if (scriptPubKey.isMultiSigRedeem()) {
            redeemScript = scriptPubKey;
            scriptPubKey = ScriptBuilder.createP2SHOutputScript(redeemScript);
        }

        int sigScriptSize = scriptPubKey.getNumberOfBytesRequiredToSpend(isCompressed, redeemScript);
        size += inCount * (32 + 4 + 1 + sigScriptSize + 4);

        for (Out out : outs) {
            size += 8 + 1 + out.getOutScript().length;
        }
        return size;
    }

    static boolean needMinFee(List<Out> amounts) {
        // note: for now must require fee because zero fee maybe cause the tx confirmed in long time
        return true;
    }

    static long getAmount(List<Out> outs) {
        long amount = 0;
        for (Out out : outs) {
            amount += out.getOutValue();
        }
        return amount;
    }

    static long getCoinDepth(List<Out> outs) {
        long coinDepth = 0;
        for (Out out : outs) {
            coinDepth += BlockChain.getInstance().lastBlock.getBlockNo() * out.getOutValue() - out.getCoinDepth() + out.getOutValue();
        }
        return coinDepth;
    }

    static List<Out> getUnspendOuts(List<Tx> txs) {
        List<Out> result = new ArrayList<Out>();
        for (Tx tx : txs) {
            result.add(tx.getOuts().get(0));
        }
        return result;
    }

    static List<Out> getCanSpendOuts(List<Tx> txs) {
        List<Out> result = new ArrayList<Out>();
        for (Tx tx : txs) {
//            if (tx.getBlockNo() != Tx.TX_UNCONFIRMED || tx.getSource() == Tx.SourceType.self.getValue()) {
                result.add(tx.getOuts().get(0));
//            }
        }
        return result;
    }

    static List<Out> getCanNotSpendOuts(List<Tx> txs) {
        List<Out> result = new ArrayList<Out>();
//        for (Tx tx : txs) {
//            if (tx.getBlockNo() == Tx.TX_UNCONFIRMED && tx.getSource() == Tx.SourceType.network.getValue()) {
//                result.add(tx.getOuts().get(0));
//            }
//        }
        return result;
    }
}

interface TxBuilderProtocol {
    public Tx buildTx(Address address, String changeAddress, List<Tx> unspendTxs, Tx tx);

    public Tx buildTx(String changeAddress, List<Out> unspendOuts, Tx tx);
}

class TxBuilderEmptyWallet implements TxBuilderProtocol {
    public Tx buildTx(Address address, String changeAddress, List<Tx> unspendTxs, Tx tx) {
        Script scriptPubKey = null;
        if (address.isHDM()) {
            scriptPubKey = new Script(address.getPubKey());
        } else {
            scriptPubKey = ScriptBuilder.createOutputScript(address.address);
        }

        List<Out> outs = TxBuilder.getCanSpendOuts(unspendTxs);
        List<Out> unspendOuts = TxBuilder.getUnspendOuts(unspendTxs);

        long value = 0;
        for (Out out : tx.getOuts()) {
            value += out.getOutValue();
        }
        boolean needMinFee = TxBuilder.needMinFee(tx.getOuts());

        if (value != TxBuilder.getAmount(unspendOuts) || value != TxBuilder.getAmount(outs)) {
            return null;
        }

        long fees = 0;
        if (needMinFee) {
            fees = Utils.getFeeBase();
        } else {
            // no fee logic
            int s = TxBuilder.estimationTxSize(outs.size(), scriptPubKey, tx.getOuts(), address.isCompressed());
            if (TxBuilder.getCoinDepth(outs) <= TxBuilder.TX_FREE_MIN_PRIORITY * s) {
                fees = Utils.getFeeBase();
            }
        }

        int size = TxBuilder.estimationTxSize(outs.size(), scriptPubKey, tx.getOuts(), address.isCompressed());
        if (size > 1000) {
            fees = (size / 1000 + 1) * Utils.getFeeBase();
        }

        // note : like bitcoinj, empty wallet will not check min output
        if (fees > 0) {
            Out lastOut = tx.getOuts().get(tx.getOuts().size() - 1);
            if (lastOut.getOutValue() > fees) {
                lastOut.setOutValue(lastOut.getOutValue() - fees);
            } else {
                return null;
            }
        }
        for (Out out : outs) {
            tx.addInput(out);
        }

        tx.setSource(Tx.SourceType.self.getValue());
        return tx;
    }

    @Override
    public Tx buildTx(String changeAddress, List<Out> unspendOuts, Tx tx) {
        List<Out> outs = unspendOuts;

        long value = 0;
        for (Out out : tx.getOuts()) {
            value += out.getOutValue();
        }
        boolean needMinFee = TxBuilder.needMinFee(tx.getOuts());

        if (value != TxBuilder.getAmount(unspendOuts) || value != TxBuilder.getAmount(outs)) {
            return null;
        }

        long fees = 0;
        if (needMinFee) {
            fees = Utils.getFeeBase();
        } else {
            // no fee logic
            int s = TxBuilder.estimationTxSize(outs.size(), tx.getOuts().size());
            if (TxBuilder.getCoinDepth(outs) <= TxBuilder.TX_FREE_MIN_PRIORITY * s) {
                fees = Utils.getFeeBase();
            }
        }

        int size = TxBuilder.estimationTxSize(outs.size(), tx.getOuts().size());
        if (size > 1000) {
            fees = (size / 1000 + 1) * Utils.getFeeBase();
        }

        // note : like bitcoinj, empty wallet will not check min output
        if (fees > 0) {
            Out lastOut = tx.getOuts().get(tx.getOuts().size() - 1);
            if (lastOut.getOutValue() > fees) {
                lastOut.setOutValue(lastOut.getOutValue() - fees);
            } else {
                return null;
            }
        }
        for (Out out : outs) {
            tx.addInput(out);
        }

        tx.setSource(Tx.SourceType.self.getValue());
        return tx;
    }
}

class TxBuilderDefault implements TxBuilderProtocol {
    public Tx buildTx(Address address, String changeAddress, List<Tx> unspendTxs, Tx tx) {
        boolean isCompressed = address.isCompressed();
        Script scriptPubKey = null;
        if (address.isHDM()) {
            scriptPubKey = new Script(address.getPubKey());
        } else {
            scriptPubKey = ScriptBuilder.createOutputScript(address.address);
        }

        List<Out> outs = TxBuilder.getUnspendOuts(unspendTxs);

        Collections.sort(outs, new Comparator<Out>() {
            public int compare(Out out1, Out out2) {
                int depth1 = 0;
                int depth2 = 0;
                long coinDepth1 = BlockChain.getInstance().lastBlock.getBlockNo() * out1.getOutValue() - out1.getCoinDepth() + out1.getOutValue();
                long coinDepth2 = BlockChain.getInstance().lastBlock.getBlockNo() * out2.getOutValue() - out2.getCoinDepth() + out2.getOutValue();
                if (coinDepth1 != coinDepth2) {
                    if (coinDepth2 > coinDepth1)
                        return 1;
                    else
                        return -1;
                } else if (out1.getOutValue() != out2.getOutValue()) {
                    if (out2.getOutValue() > out1.getOutValue())
                        return 1;
                    else
                        return -1;
                } else {
                    BigInteger hash1 = new BigInteger(1, out1.getTxHash());
                    BigInteger hash2 = new BigInteger(1, out2.getTxHash());
                    int result = hash1.compareTo(hash2);
                    if (result != 0) {
                        return result;
                    } else {
                        return out1.getOutSn() - out2.getOutSn();
                    }
                }
            }
        });

        long additionalValueForNextCategory = 0;
        List<Out> selection3 = null;
        List<Out> selection2 = null;
        Out selection2Change = null;
        List<Out> selection1 = null;
        Out selection1Change = null;

        int lastCalculatedSize = 0;
        long valueNeeded;
        long value = 0;
        for (Out out : tx.getOuts()) {
            value += out.getOutValue();
        }

        boolean needAtLeastReferenceFee = TxBuilder.needMinFee(tx.getOuts());

        List<Out> bestCoinSelection = null;
        Out bestChangeOutput = null;
        while (true) {
            long fees = 0;

            if (lastCalculatedSize >= 1000) {
                // If the size is exactly 1000 bytes then we'll over-pay, but this should be rare.
                fees += (lastCalculatedSize / 1000 + 1) * Utils.getFeeBase();
            }
            if (needAtLeastReferenceFee && fees < Utils.getFeeBase())
                fees = Utils.getFeeBase();

            valueNeeded = value + fees;

            if (additionalValueForNextCategory > 0)
                valueNeeded += additionalValueForNextCategory;

            long additionalValueSelected = additionalValueForNextCategory;

            List<Out> selectedOuts = this.selectOuts(outs, valueNeeded);

            if (TxBuilder.getAmount(selectedOuts) < valueNeeded)
                break;

            // no fee logic
            if (!needAtLeastReferenceFee) {
                long total = TxBuilder.getAmount(selectedOuts);
                if (total - value < Utils.CENT && total - value >= Utils.getFeeBase()) {
                    needAtLeastReferenceFee = true;
                    continue;
                }
                int s = TxBuilder.estimationTxSize(selectedOuts.size(), scriptPubKey, tx.getOuts(), isCompressed);
                if (total - value > Utils.CENT)
                    s += 34;
                if (TxBuilder.getCoinDepth(selectedOuts) <= TxBuilder.TX_FREE_MIN_PRIORITY * s) {
                    needAtLeastReferenceFee = true;
                    continue;
                }
            }

            boolean eitherCategory2Or3 = false;
            boolean isCategory3 = false;

            long change = TxBuilder.getAmount(selectedOuts) - valueNeeded;
            if (additionalValueSelected > 0)
                change += additionalValueSelected;

            if (BitherjSettings.ensureMinRequiredFee && change != 0 && change < Utils.CENT
                    && fees < Utils.getFeeBase()) {
                // This solution may fit into category 2, but it may also be category 3, we'll check that later
                eitherCategory2Or3 = true;
                additionalValueForNextCategory = Utils.CENT;
                // If the change is smaller than the fee we want to add, this will be negative
                change -= Utils.getFeeBase() - fees;
            }

            int size = 0;
            Out changeOutput = null;
            if (change > 0) {
                changeOutput = new Out();
                changeOutput.setOutValue(change);
                changeOutput.setOutAddress(changeAddress);
                // If the change output would result in this transaction being rejected as dust, just drop the change and make it a fee
                if (BitherjSettings.ensureMinRequiredFee && Tx.MIN_NONDUST_OUTPUT >= change) {
                    // This solution definitely fits in category 3
                    isCategory3 = true;
                    additionalValueForNextCategory = Utils.getFeeBase() + Tx.MIN_NONDUST_OUTPUT + 1;
                } else {
                    size += 34;
                    // This solution is either category 1 or 2
                    if (!eitherCategory2Or3) // must be category 1
                        additionalValueForNextCategory = 0;
                }
            } else {
                if (eitherCategory2Or3) {
                    // This solution definitely fits in category 3 (we threw away change because it was smaller than MIN_TX_FEE)
                    isCategory3 = true;
                    additionalValueForNextCategory = Utils.getFeeBase() + 1;
                }
            }
            size += TxBuilder.estimationTxSize(selectedOuts.size(), scriptPubKey, tx.getOuts(), isCompressed);
            if (size / 1000 > lastCalculatedSize / 1000 && Utils.getFeeBase() > 0) {
                lastCalculatedSize = size;
                // We need more fees anyway, just try again with the same additional value
                additionalValueForNextCategory = additionalValueSelected;
                continue;
            }

            if (isCategory3) {
                if (selection3 == null)
                    selection3 = selectedOuts;
            } else if (eitherCategory2Or3) {
                // If we are in selection2, we will require at least CENT additional. If we do that, there is no way
                // we can end up back here because CENT additional will always get us to 1
                if (selection2 != null) {
                    long oldFee = TxBuilder.getAmount(selection2) - selection2Change.getOutValue() - value;
                    long newFee = TxBuilder.getAmount(selectedOuts) - changeOutput.getOutValue() - value;
                    if (newFee <= oldFee) {
                        selection2 = selectedOuts;
                        selection2Change = changeOutput;
                    }
                } else {
                    selection2 = selectedOuts;
                    selection2Change = changeOutput;
                }
            } else {
                // Once we get a category 1 (change kept), we should break out of the loop because we can't do better
                if (selection1 != null) {
                    long oldFee = TxBuilder.getAmount(selection1) - value;
                    if (selection1Change != null) {
                        oldFee -= selection1Change.getOutValue();
                    }
                    long newFee = TxBuilder.getAmount(selectedOuts) - value;
                    if (changeOutput != null) {
                        newFee -= changeOutput.getOutValue();
                    }
                    if (newFee <= oldFee) {
                        selection1 = selectedOuts;
                        selection1Change = changeOutput;
                    }
                } else {
                    selection1 = selectedOuts;
                    selection1Change = changeOutput;
                }
            }

            if (additionalValueForNextCategory > 0) {
                continue;
            }
            break;
        }

        if (selection3 == null && selection2 == null && selection1 == null) {
//            DDLogDebug(@"%@ did not calculate valid tx", address);
            return null;
        }

        long lowestFee = 0;

        if (selection1 != null) {
            if (selection1Change != null)
                lowestFee = TxBuilder.getAmount(selection1) - selection1Change.getOutValue() - value;
            else
                lowestFee = TxBuilder.getAmount(selection1) - value;
            bestCoinSelection = selection1;
            bestChangeOutput = selection1Change;
        }

        if (selection2 != null) {
            long fee = TxBuilder.getAmount(selection2) - selection2Change.getOutValue() - value;
            if (lowestFee == 0 || fee < lowestFee) {
                lowestFee = fee;
                bestCoinSelection = selection2;
                bestChangeOutput = selection2Change;
            }
        }

        if (selection3 != null) {
            if (lowestFee == 0 || TxBuilder.getAmount(selection3) - value < lowestFee) {
                bestCoinSelection = selection3;
                bestChangeOutput = null;
            }
        }

        if (bestChangeOutput != null) {
            tx.addOutput(bestChangeOutput.getOutValue(), bestChangeOutput.getOutAddress());
        }

        for (Out out : bestCoinSelection) {
            tx.addInput(out);
        }

        tx.setSource(Tx.SourceType.self.getValue());
        return tx;
    }

    @Override
    public Tx buildTx(String changeAddress, List<Out> unspendOuts, Tx tx) {
        List<Out> outs = unspendOuts;

        long additionalValueForNextCategory = 0;
        List<Out> selection3 = null;
        List<Out> selection2 = null;
        Out selection2Change = null;
        List<Out> selection1 = null;
        Out selection1Change = null;

        int lastCalculatedSize = 0;
        long valueNeeded;
        long value = 0;
        for (Out out : tx.getOuts()) {
            value += out.getOutValue();
        }

        boolean needAtLeastReferenceFee = TxBuilder.needMinFee(tx.getOuts());

        List<Out> bestCoinSelection = null;
        Out bestChangeOutput = null;
        while (true) {
            long fees = 0;

            if (lastCalculatedSize >= 1000) {
                // If the size is exactly 1000 bytes then we'll over-pay, but this should be rare.
                fees += (lastCalculatedSize / 1000 + 1) * Utils.getFeeBase();
            }
            if (needAtLeastReferenceFee && fees < Utils.getFeeBase())
                fees = Utils.getFeeBase();

            valueNeeded = value + fees;

            if (additionalValueForNextCategory > 0)
                valueNeeded += additionalValueForNextCategory;

            long additionalValueSelected = additionalValueForNextCategory;

            List<Out> selectedOuts = this.selectOuts(outs, valueNeeded);

            if (TxBuilder.getAmount(selectedOuts) < valueNeeded)
                break;

            // no fee logic
            if (!needAtLeastReferenceFee) {
                long total = TxBuilder.getAmount(selectedOuts);
                if (total - value < Utils.CENT && total - value >= Utils.getFeeBase()) {
                    needAtLeastReferenceFee = true;
                    continue;
                }
                int s = TxBuilder.estimationTxSize(selectedOuts.size(), tx.getOuts().size());
                if (total - value > Utils.CENT)
                    s += 34;
                if (TxBuilder.getCoinDepth(selectedOuts) <= TxBuilder.TX_FREE_MIN_PRIORITY * s) {
                    needAtLeastReferenceFee = true;
                    continue;
                }
            }

            boolean eitherCategory2Or3 = false;
            boolean isCategory3 = false;

            long change = TxBuilder.getAmount(selectedOuts) - valueNeeded;
            if (additionalValueSelected > 0)
                change += additionalValueSelected;

            if (BitherjSettings.ensureMinRequiredFee && change != 0 && change < Utils.CENT
                    && fees < Utils.getFeeBase()) {
                // This solution may fit into category 2, but it may also be category 3, we'll check that later
                eitherCategory2Or3 = true;
                additionalValueForNextCategory = Utils.CENT;
                // If the change is smaller than the fee we want to add, this will be negative
                change -= Utils.getFeeBase() - fees;
            }

            int size = 0;
            Out changeOutput = null;
            if (change > 0) {
                changeOutput = new Out();
                changeOutput.setOutValue(change);
                changeOutput.setOutAddress(changeAddress);
                // If the change output would result in this transaction being rejected as dust, just drop the change and make it a fee
                if (BitherjSettings.ensureMinRequiredFee && Tx.MIN_NONDUST_OUTPUT >= change) {
                    // This solution definitely fits in category 3
                    isCategory3 = true;
                    additionalValueForNextCategory = Utils.getFeeBase() + Tx.MIN_NONDUST_OUTPUT + 1;
                } else {
                    size += 34;
                    // This solution is either category 1 or 2
                    if (!eitherCategory2Or3) // must be category 1
                        additionalValueForNextCategory = 0;
                }
            } else {
                if (eitherCategory2Or3) {
                    // This solution definitely fits in category 3 (we threw away change because it was smaller than MIN_TX_FEE)
                    isCategory3 = true;
                    additionalValueForNextCategory = Utils.getFeeBase() + 1;
                }
            }
            size += TxBuilder.estimationTxSize(selectedOuts.size(), tx.getOuts().size());
            if (size / 1000 > lastCalculatedSize / 1000 && Utils.getFeeBase() > 0) {
                lastCalculatedSize = size;
                // We need more fees anyway, just try again with the same additional value
                additionalValueForNextCategory = additionalValueSelected;
                continue;
            }

            if (isCategory3) {
                if (selection3 == null)
                    selection3 = selectedOuts;
            } else if (eitherCategory2Or3) {
                // If we are in selection2, we will require at least CENT additional. If we do that, there is no way
                // we can end up back here because CENT additional will always get us to 1
                if (selection2 != null) {
                    long oldFee = TxBuilder.getAmount(selection2) - selection2Change.getOutValue() - value;
                    long newFee = TxBuilder.getAmount(selectedOuts) - changeOutput.getOutValue() - value;
                    if (newFee <= oldFee) {
                        selection2 = selectedOuts;
                        selection2Change = changeOutput;
                    }
                } else {
                    selection2 = selectedOuts;
                    selection2Change = changeOutput;
                }
            } else {
                // Once we get a category 1 (change kept), we should break out of the loop because we can't do better
                if (selection1 != null) {
                    long oldFee = TxBuilder.getAmount(selection1) - value;
                    if (selection1Change != null) {
                        oldFee -= selection1Change.getOutValue();
                    }
                    long newFee = TxBuilder.getAmount(selectedOuts) - value;
                    if (changeOutput != null) {
                        newFee -= changeOutput.getOutValue();
                    }
                    if (newFee <= oldFee) {
                        selection1 = selectedOuts;
                        selection1Change = changeOutput;
                    }
                } else {
                    selection1 = selectedOuts;
                    selection1Change = changeOutput;
                }
            }

            if (additionalValueForNextCategory > 0) {
                continue;
            }
            break;
        }

        if (selection3 == null && selection2 == null && selection1 == null) {
//            DDLogDebug(@"%@ did not calculate valid tx", address);
            return null;
        }

        long lowestFee = 0;

        if (selection1 != null) {
            if (selection1Change != null)
                lowestFee = TxBuilder.getAmount(selection1) - selection1Change.getOutValue() - value;
            else
                lowestFee = TxBuilder.getAmount(selection1) - value;
            bestCoinSelection = selection1;
            bestChangeOutput = selection1Change;
        }

        if (selection2 != null) {
            long fee = TxBuilder.getAmount(selection2) - selection2Change.getOutValue() - value;
            if (lowestFee == 0 || fee < lowestFee) {
                lowestFee = fee;
                bestCoinSelection = selection2;
                bestChangeOutput = selection2Change;
            }
        }

        if (selection3 != null) {
            if (lowestFee == 0 || TxBuilder.getAmount(selection3) - value < lowestFee) {
                bestCoinSelection = selection3;
                bestChangeOutput = null;
            }
        }

        if (bestChangeOutput != null) {
            tx.addOutput(bestChangeOutput.getOutValue(), bestChangeOutput.getOutAddress());
        }

        for (Out out : bestCoinSelection) {
            tx.addInput(out);
        }

        tx.setSource(Tx.SourceType.self.getValue());
        return tx;
    }

    private List<Out> selectOuts(List<Out> outs, long amount) {
        List<Out> result = new ArrayList<Out>();
        long sum = 0;
        for (Out out : outs) {
            sum += out.getOutValue();
            result.add(out);
            if (sum >= amount) {
                break;
            }
        }
        return result;
    }
}