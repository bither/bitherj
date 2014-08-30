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

package net.bither.bitherj.sample;

import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;

import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.core.Block;
import net.bither.bitherj.core.BlockChain;
import net.bither.bitherj.core.PeerManager;
import net.bither.bitherj.crypto.DumpedPrivateKey;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.net.StreamParser;
import net.bither.bitherj.script.Script;
import net.bither.bitherj.utils.LogUtil;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.Utils;

public class MainActivity extends ActionBarActivity {
    private LinearLayout ll;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ll = (LinearLayout) findViewById(R.id.ll);
        addButton("peer", new Runnable() {
            @Override
            public void run() {
                Block block = new Block(2, "000000000000000098686ab04cc22fec77e4fa2d76d5a3cc0eb8cbf4ed800cdc", "e9087641b6f19e49dc37be1d35ec5b670b1baa4529883602b59068e1799adb44", 1398811175
                        , 419465580, 952935459, 298368);
                BlockChain.getInstance().addSPVBlock(block);
                if (AddressManager.getInstance().getAllAddresses().size() < 1) {
                    Address address1 = new Address("1C6FiRktL3UPd4sywhyU5CYSeLdKhvHxhR", Utils.hexStringToByteArray("034285edc746e4c8b4e9f022ee0a561f0b9d5a29e1e44e87e77b2156ecf2c45265"), null);
                    AddressManager.getInstance().addAddress(address1);
                }


                /*
                // these code is test satoshi's 3rd address to sync with get block message. we found it need
                //  add pub key to bloom filter, otherwise it can not receive tx.
                Block block = new Block(1, "0000000000000000000000000000000000000000000000000000000000000000", "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", 1231006505
                        , 486604799, 2083236893, 0);
                BlockChain.getInstance().addSPVBlock(block);
                if (AddressManager.getInstance().getAllAddresses().size() < 1) {
                    Address address1 = new Address("1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1"
                            , new byte[] {4,114,17,-88,36,-11,91,80,82,40,-28,-61,-43,25,76,31,-49
                            ,-86,21,-92,86,-85,-33,55,-7,-71,-39,122,64,64,-81,-64,115,-34,-26,-56
                            ,-112,100,-104,79,3,56,82,55,-39,33,103,-63,62,35,100,70,-76,23,-85,121
                            ,-96,-4,-82,65,42,-29,49,107,119}
                            , null);
                    AddressManager.getInstance().addAddress(address1);
                }
                */
                PeerManager.instance().start();
            }
        });

        addButton("stop", new Runnable() {
            @Override
            public void run() {
                Block block = new Block(2, "00000000000000000ee9b585e0a707347d7c80f3a905f48fa32d448917335366", "4d60e37c7086096e85c11324d70112e61e74fc38a5c5153587a0271fd22b65c5", 1400928750
                        , 409544770l, 4079278699l, 302400);
                BlockChain.getInstance().addSPVBlock(block);

                PeerManager.instance().stop();
            }
        });
    }

    private void addButton(final String name, final Runnable task) {
        final Button button = new Button(this);
        button.setText(name);
        ll.addView(button);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread() {
                    @Override
                    public void run() {
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                button.setEnabled(false);
                                button.setText(name + "  running");
                            }
                        });
                        LogUtil.i("test", "start testing " + name);
                        try {
                            task.run();
                        }catch (Exception e){
                            e.printStackTrace();
                        }
                        LogUtil.i("test", "end testing " + name);
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                button.setEnabled(true);
                                button.setText(name);
                            }
                        });
                    }
                }.start();
            }
        });
    }

}
