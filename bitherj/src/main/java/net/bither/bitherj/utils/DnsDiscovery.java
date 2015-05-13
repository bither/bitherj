/**
 * Copyright 2011 John Sample
 * Copyright 2014 Andreas Schildbach
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.bitherj.utils;

import com.google.common.collect.Lists;
import com.google.common.primitives.Ints;

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.core.Peer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class DnsDiscovery {
    private static final Logger log = LoggerFactory.getLogger(DnsDiscovery.class);

    private final String[] hostNames = BitherjSettings.dnsSeeds;

    private static DnsDiscovery instance;

    // added by scw (bither)
    public static final DnsDiscovery instance() {
        if (instance == null) {
            instance = new DnsDiscovery();
        }
        return instance;
    }

    private DnsDiscovery() {
    }

    public Peer[] getPeers(long timeoutValue, TimeUnit timeoutUnit) {

        // Java doesn't have an async DNS API so we have to do all lookups in a thread pool,
        // as sometimes seeds go
        // hard down and it takes ages to give up and move on.
        ExecutorService threadPool = Executors.newFixedThreadPool(hostNames.length);
        ArrayList<Peer> peers = Lists.newArrayList();
        try {
            List<Callable<InetAddress[]>> tasks = Lists.newArrayList();
            for (final String seed : hostNames)
                tasks.add(new Callable<InetAddress[]>() {
                    public InetAddress[] call() throws Exception {
                        return InetAddress.getAllByName(seed);
                    }
                });
            final List<Future<InetAddress[]>> futures = threadPool.invokeAll(tasks, timeoutValue,
                    timeoutUnit);
            for (int i = 0;
                 i < futures.size();
                 i++) {
                Future<InetAddress[]> future = futures.get(i);
                if (future.isCancelled()) {
                    log.warn("{} timed out", hostNames[i]);
                    continue;  // Timed out.
                }
                final InetAddress[] inetAddresses;
                try {
                    inetAddresses = future.get();
                } catch (ExecutionException e) {
                    log.error("Failed to look up DNS seeds from {}: {}", hostNames[i],
                            e.getMessage());
                    continue;
                }
                for (InetAddress addr : inetAddresses) {
                    //todo support ipv6
                    if (addr.getAddress().length <= Ints.BYTES) {
                        peers.add(new Peer(addr));
                    }
                }
            }
            Collections.shuffle(peers);
            threadPool.shutdownNow();
        } catch (InterruptedException e) {
        } finally {
            threadPool.shutdown();
        }
        return peers.toArray(new Peer[peers.size()]);
    }
}
