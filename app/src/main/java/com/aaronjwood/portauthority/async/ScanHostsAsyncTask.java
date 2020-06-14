package com.aaronjwood.portauthority.async;

import android.os.AsyncTask;
import android.os.Build;
import android.util.Pair;

import com.aaronjwood.portauthority.db.Database;
import com.aaronjwood.portauthority.network.Host;
import com.aaronjwood.portauthority.response.MainAsyncResponse;
import com.aaronjwood.portauthority.runnable.ScanHostsRunnable;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import jcifs.netbios.NbtAddress;

public class ScanHostsAsyncTask extends AsyncTask<Integer, Void, Void> {
    private final WeakReference<MainAsyncResponse> delegate;//被弱引用的对象
    private Database db;
    private static final String ARP_TABLE = "/proc/net/arp";
    private static final String IP_CMD = "ip neighbor";//ARP地址表相关
    private static final String NEIGHBOR_INCOMPLETE = "INCOMPLETE";
    private static final String NEIGHBOR_FAILED = "FAILED";
    private static final String ARP_INCOMPLETE = "0x0";
    private static final String ARP_INACTIVE = "00:00:00:00:00:00";
    private static final int NETBIOS_FILE_SERVER = 0x20;

    /**
     * Constructor to set the delegate
     *
     * @param delegate Called when host discovery has finished
     */
    public ScanHostsAsyncTask(MainAsyncResponse delegate, Database db) {
        this.delegate = new WeakReference<>(delegate);
        this.db = db;
    }

    /**
     * Scans for active hosts on the network
     *  用于执行较为费时的操作，此方法将接收输入参数和返回计算结果。在执行过程中可以调用publishProgress(Progress... values)来更新进度信息。
     * @param params IP address
     */
    @Override
    protected Void doInBackground(Integer... params) {
        int ipv4 = params[0];//内网IP地址
        int cidr = params[1];//子网掩码数量
        int timeout = params[2];//超时时间
        MainAsyncResponse activity = delegate.get();

        // Android 10+ doesn't let us access the ARP table.
        // Do an early check to see if we can get what we need from the system.
        // https://developer.android.com/about/versions/10/privacy/changes#proc-net-filesystem
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {//android10+以上
            try {
                Process ipProc = Runtime.getRuntime().exec(IP_CMD);
                ipProc.waitFor();//返回该Process对象代表的进程的出口值，值0表示正常退出，非0非正常。
                if (ipProc.exitValue() != 0) {//返回该Process对象代表的进程的出口值，值0表示正常退出，非0非正常。关于该方法，应该是返回System.exit(int)方法中的参数。

                    //地址解析协议，即ARP（Address Resolution Protocol），是根据IP地址获取物理地址的一个TCP/IP协议。
                    // 主机发送信息时将包含目标IP地址的ARP请求广播到局域网络上的所有主机，并接收返回消息，以此确定目标的物理地址；
                    // 收到返回消息后将该IP地址和物理地址存入本机ARP缓存中并保留一定时间，下次请求时直接查询ARP缓存以节约资源
                    activity.processFinish(new IOException("无法访问系统中的ARP缓存资源信息"));//Unable to access ARP entries
                    activity.processFinish(true);

                    return null;
                }
            } catch (IOException | InterruptedException e) {
                activity.processFinish(new IOException("无法解析ARP资源"));//Unable to parse ARP entries
                activity.processFinish(true);
            }
        } else {//Android 10以下直接访问ARP的
            File file = new File(ARP_TABLE);
            if (!file.exists()) {
                activity.processFinish(new FileNotFoundException("无法找到系统ARP资源"));//Unable to find ARP table
                activity.processFinish(true);

                return null;
            }

            if (!file.canRead()) {
                activity.processFinish(new IOException("不能读取ARP资源"));//Unable to read ARP table
                activity.processFinish(true);
            }
        }

        ExecutorService executor = Executors.newCachedThreadPool();

        double hostBits = 32.0d - cidr; // How many bits do we have for the hosts.
        int netmask = (0xffffffff >> (32 - cidr)) << (32 - cidr); // How many bits for the netmask.
        int numberOfHosts = (int) Math.pow(2.0d, hostBits) - 2; // 2 ^ hostbits = number of hosts in integer.
        int firstAddr = (ipv4 & netmask) + 1; // AND the bits we care about, then first addr.

        int SCAN_THREADS = (int) hostBits;
        int chunk = (int) Math.ceil((double) numberOfHosts / SCAN_THREADS); // Chunk hosts by number of threads.
        int previousStart = firstAddr;
        int previousStop = firstAddr + (chunk - 2); // Ignore network + first addr

        for (int i = 0; i < SCAN_THREADS; i++) {
            executor.execute(new ScanHostsRunnable(previousStart, previousStop, timeout, delegate));
            previousStart = previousStop + 1;
            previousStop = previousStart + (chunk - 1);
        }

        executor.shutdown();
        try {
            executor.awaitTermination(5, TimeUnit.MINUTES);
            executor.shutdownNow();
        } catch (InterruptedException e) {
            activity.processFinish(e);
            return null;
        }

        publishProgress();
        return null;
    }

    /**
     * Scans the ARP table and updates the list with hosts on the network
     * Resolves both DNS and NetBIOS
     * Don't update the UI in onPostExecute since we want to do multiple UI updates here
     * onPostExecute seems to perform all UI updates at once which would hinder what we're doing here
     * TODO: this method is gross, refactor it and break it up
     * 在调用publishProgress(Progress... values)时，此方法被执行，直接将进度信息更新到UI组件上。
     * @param params
     */
    @Override
    protected final void onProgressUpdate(Void... params) {
        BufferedReader reader = null;
        final MainAsyncResponse activity = delegate.get();
        ExecutorService executor = Executors.newCachedThreadPool();
        final AtomicInteger numHosts = new AtomicInteger(0);
        List<Pair<String, String>> pairs = new ArrayList<>();//Pair可以认为对象

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {//Android 10+
                Process ipProc = Runtime.getRuntime().exec(IP_CMD);
                ipProc.waitFor();
                if (ipProc.exitValue() != 0) {
                    throw new Exception("Unable to access ARP entries");
                }

                reader = new BufferedReader(new InputStreamReader(ipProc.getInputStream(), "UTF-8"));
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] neighborLine = line.split("\\s+");

                    // We don't have a validated ARP entry for this case.
                    if (neighborLine.length <= 4) {
                        continue;
                    }

                    String ip = neighborLine[0];
                    InetAddress addr = InetAddress.getByName(ip);
                    if (addr.isLinkLocalAddress() || addr.isLoopbackAddress()) {
                        continue;
                    }

                    String macAddress = neighborLine[4];
                    String state = neighborLine[neighborLine.length - 1];

                    // Determine if the ARP entry is valid.
                    // https://github.com/sivasankariit/iproute2/blob/master/ip/ipneigh.c
                    if (!NEIGHBOR_FAILED.equals(state) && !NEIGHBOR_INCOMPLETE.equals(state)) {
                        pairs.add(new Pair<>(ip, macAddress));
                    }
                }
            } else {
                reader = new BufferedReader(new InputStreamReader(new FileInputStream(ARP_TABLE), "UTF-8"));
                reader.readLine(); // Skip header.
                String line;

                while ((line = reader.readLine()) != null) {
                    String[] arpLine = line.split("\\s+");
                    String ip = arpLine[0];
                    String flag = arpLine[2];
                    String macAddress = arpLine[3];

                    if (!ARP_INCOMPLETE.equals(flag) && !ARP_INACTIVE.equals(macAddress)) {
                        pairs.add(new Pair<>(ip, macAddress));
                    }
                }
            }

            numHosts.addAndGet(pairs.size());
            for (Pair<String, String> pair : pairs) {
                String ip = pair.first;
                String macAddress = pair.second;
                executor.execute(() -> {
                    Host host;
                    try {
                        host = new Host(ip, macAddress, db);
                    } catch (IOException e) {
                        host = new Host(ip, macAddress);
                    }

                    MainAsyncResponse activity1 = delegate.get();
                    try {
                        InetAddress add = InetAddress.getByName(ip);
                        String hostname = add.getCanonicalHostName();
                        host.setHostname(hostname);

                        if (activity1 != null) {
                            activity1.processFinish(host, numHosts);
                        }
                    } catch (UnknownHostException e) {
                        numHosts.decrementAndGet();
                        activity1.processFinish(e);
                        return;
                    }

                    try {
                        NbtAddress[] netbios = NbtAddress.getAllByAddress(ip);
                        for (NbtAddress addr : netbios) {
                            if (addr.getNameType() == NETBIOS_FILE_SERVER) {
                                host.setHostname(addr.getHostName());
                                return;
                            }
                        }
                    } catch (UnknownHostException e) {
                        // It's common that many discovered hosts won't have a NetBIOS entry.
                    }
                });
            }
        } catch (Exception e) {
            if (activity != null) {
                activity.processFinish(e);
            }

        } finally {
            executor.shutdown();
            if (activity != null) {
                activity.processFinish(true);
            }

            try {
                if (reader != null) {
                    reader.close();
                }
            } catch (IOException ignored) {
                // Something's really wrong if we can't close the stream...
            }
        }
    }
}
