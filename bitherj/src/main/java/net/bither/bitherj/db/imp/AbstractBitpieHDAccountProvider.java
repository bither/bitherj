package net.bither.bitherj.db.imp;

import com.google.common.base.Function;

import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.db.imp.base.ICursor;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Base58;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nullable;

public abstract class AbstractBitpieHDAccountProvider extends AbstractHDAccountProvider {
    @Override
    public List<Integer> getHDAccountSeeds() {
        final List<Integer> hdSeedIds = new ArrayList<Integer>();
        String sql = "select bitpie_hd_account_id from bitpie_hd_account";
        this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                hdSeedIds.add(c.getInt(0));
                return null;
            }
        });
        return hdSeedIds;
    }

    @Override
    public boolean hasMnemonicSeed(int hdAccountId) {
        String sql = "select count(0) cnt from bitpie_hd_account where encrypt_mnemonic_seed is not null and bitpie_hd_account_id=?";
        final boolean[] result = {false};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("cnt");
                if (idColumn != -1) {
                    result[0] = c.getInt(idColumn) > 0;
                }
                return null;
            }
        });
        return result[0];
    }

    @Override
    public String getHDFirstAddress(int hdSeedId) {
        String sql = "select hd_address from bitpie_hd_account where bitpie_hd_account_id=?";
        final String[] address = {null};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.HD_ADDRESS);
                if (idColumn != -1) {
                    address[0] = c.getString(idColumn);
                }
                return null;
            }
        });
        return address[0];
    }

    @Override
    public String getHDAccountEncryptSeed(int hdSeedId) {
        final String[] hdAccountEncryptSeed = {null};
        String sql = "select encrypt_seed from bitpie_hd_account where bitpie_hd_account_id=? ";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.ENCRYPT_SEED);
                if (idColumn != -1) {
                    hdAccountEncryptSeed[0] = c.getString(idColumn);
                }
                return null;
            }
        });
        return hdAccountEncryptSeed[0];
    }

    @Override
    public boolean hdAccountIsXRandom(int seedId) {
        final boolean[] result = {false};
        String sql = "select is_xrandom from bitpie_hd_account where bitpie_hd_account_id=?";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(seedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.IS_XRANDOM);
                if (idColumn != -1) {
                    result[0] = c.getInt(idColumn) == 1;
                }
                return null;
            }
        });
        return result[0];
    }

    @Override
    public String getHDAccountEncryptMnemonicSeed(int hdSeedId) {
        final String[] hdAccountMnmonicEncryptSeed = {null};
        String sql = "select encrypt_mnemonic_seed from bitpie_hd_account where bitpie_hd_account_id=? ";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.ENCRYPT_MNMONIC_SEED);
                if (idColumn != -1) {
                    hdAccountMnmonicEncryptSeed[0] = c.getString(idColumn);
                }
                return null;
            }
        });
        return hdAccountMnmonicEncryptSeed[0];
    }

    @Override
    public byte[] getInternalPub(int hdSeedId) {
        final byte[][] pub = {null};
        String sql = "select internal_pub from bitpie_hd_account where bitpie_hd_account_id=? ";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.INTERNAL_PUB);
                if (idColumn != -1) {
                    String pubStr = c.getString(idColumn);
                    try {
                        pub[0] = Base58.decode(pubStr);
                    } catch (AddressFormatException e) {
                        e.printStackTrace();
                    }
                }
                return null;
            }
        });
        return pub[0];
    }

    @Override
    public byte[] getExternalPub(int hdSeedId) {
        final byte[][] pub = {null};
        String sql = "select external_pub from bitpie_hd_account where bitpie_hd_account_id=?";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.EXTERNAL_PUB);
                if (idColumn != -1) {
                    String pubStr = c.getString(idColumn);
                    try {
                        pub[0] = Base58.decode(pubStr);
                    } catch (AddressFormatException e) {
                        e.printStackTrace();
                    }
                }
                return null;
            }
        });
        return pub[0];
    }
}
