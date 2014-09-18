package net.bither.bitherj;

import java.io.File;

/**
 * Created by nn on 2014/9/19.
 */
public interface BitherjAppEnv {
    void addressIsReady();
    File getPrivateDir(String dirName);
    public boolean isApplicationRunInForeground();
}
