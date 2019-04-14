import jpcap.*;
import jpcap.packet.*;

import java.io.IOException;
import java.util.ArrayList;
import java.net.InetAddress;
import java.util.Scanner;

public class Main {
    //定义默认最大抓包数
    private static final int max = 4096;
    //定义发送的报文的源地址
    private static final String src = "10.132.29.197";
    //定义发送的报文的目的地址
    private static final String dst = "192.168.253.134";

    //显示所有网络设备信息
    private static void showDeviceList(NetworkInterface[] devices) {
        System.out.println("本机上所有适配器如下：");
        for (int i = 0; i < devices.length; i++) {
            //网络适配器名称
            System.out.println("Adapter " + (i + 1) + "：" + devices[i].description);
            //MAC地址
            System.out.print("    MAC address: ");
            for (byte b : devices[i].mac_address) {
                System.out.print(Integer.toHexString(b & 0xff) + ":");
            }
            System.out.println();
            //IP地址
            for (NetworkInterfaceAddress a : devices[i].addresses) {
                System.out.println("    IPv6/IPv4 address: " + a.address);
            }
            System.out.println();
        }
    }

    //网络接口监听
    private static JpcapCaptor openDevice(NetworkInterface[] devices, int choice) throws java.io.IOException{
        JpcapCaptor captor = null;
        try{
            captor = JpcapCaptor.openDevice(devices[choice], 65535, false, 3000);

        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("打开网络接口失败！");

        }
        return captor;
    }

    //数据包捕获线程
    private static class AThread implements Runnable{
        Thread thread;
        JpcapCaptor captor;
        Packet[] packet;
        //线程中断标志
        volatile boolean cancel;

        AThread(JpcapCaptor captor) throws IOException{
            this.captor = captor;
            this.packet = new Packet[max];
            this.cancel = false;
            thread = new Thread(this);
        }

        @Override
        public void run() {
            packet = new Packet[max];
            for(int i = 0; i < max && cancel == false; i++){
                packet[i] = captor.getPacket();
            }
        }

        public void cancel(){
            cancel = true;
        }

        public Packet[] getPacket(){
            return packet;
        }

    }

    private static void showPacket(Packet[] packet){
        for(int i = 0; packet[i] != null && i < max; i++){
            System.out.println("Packet " + (i+1) + " : " + packet[i]);
        }
    }

    private static Packet[] readPacket(JpcapCaptor captor, String filename){
        Packet[] packet = new Packet[max];
        try {
            captor = JpcapCaptor.openFile(filename);
        } catch (IOException e) {
            e.printStackTrace();
        }
        for(int i = 0;;i++){
            packet[i] = captor.getPacket();
            if(packet[i] == null)
                break;
        }
        return packet;
    }

    private static void savePacket(JpcapCaptor capter, Packet[] packet) {
        JpcapWriter writer = null;
        try {
            writer = JpcapWriter.openDumpFile(capter, "./savePacket");
        } catch (IOException e) {
            e.printStackTrace();
        }
        for(int i = 0 ; packet[i] != null; i++){
            writer.writePacket(packet[i]);
        }

        writer.close();
    }

    private static void analyzePacket(Packet[] packet){

        ArrayList<UDPPacket> udpPacketArray = new ArrayList<UDPPacket>();
        ArrayList<ICMPPacket> icmpPacketArray = new ArrayList<ICMPPacket>();
        ArrayList<ARPPacket> arpPacketArray = new ArrayList<ARPPacket>();
        ArrayList<TCPPacket> tcpPacketArray = new ArrayList<TCPPacket>();
        ArrayList<Packet> unknownPacketArray = new ArrayList<Packet>();

        int count, count1, count2, count3, count4, count5;
        count = count1 = count2 = count3 = count4 = count5 = 0;

        for(int i = 0; packet[i] != null && i < max; i++) {
            count++;

            if (packet[i] instanceof UDPPacket) {
                UDPPacket udp = (UDPPacket) packet[i];
                udpPacketArray.add(udp);
                count1++;
            }else if(packet[i] instanceof ICMPPacket){
                ICMPPacket icmp = (ICMPPacket) packet[i];
                icmpPacketArray.add(icmp);
                count2++;
            }else if(packet[i] instanceof ARPPacket){
                ARPPacket arp = (ARPPacket) packet[i];
                arpPacketArray.add(arp);
                count3++;
            }else if(packet[i] instanceof TCPPacket){
                TCPPacket tcp = (TCPPacket) packet[i];
                tcpPacketArray.add(tcp);
                count4++;
            }else{
                unknownPacketArray.add(packet[i]);
                count5++;
            }
        }

        System.out.println();
        System.out.println("所有数据包数：" + count);
        System.out.println("UDP数据包数：" + count1);
        System.out.println("ICMP数据包数：" + count2);
        System.out.println("ARP数据包数：" + count3);
        System.out.println("TCP数据包数：" + count4);
        System.out.println("其他数据包数：" + count5);

    }

    private static void showPacketDetail(Packet[] packet){
        for(int i = 0; packet[i] != null && i < max; i++) {
            if(packet[i] instanceof UDPPacket){
                UDPPacket udp = (UDPPacket) packet[i];
                String data = new String(udp.data);
                System.out.println("Packet " + (i+1) + " : UDP" );
                System.out.println("    source ip : " + udp.src_ip.toString());
                System.out.println("    destination ip : " + udp.dst_ip.toString());
                System.out.println("    source port : " + String.valueOf(udp.src_port));
                System.out.println("    destination port : " + String.valueOf(udp.dst_port));
                System.out.println("    offset : " + String.valueOf(udp.offset));
                System.out.println("    data : " + data);
            }else if(packet[i] instanceof TCPPacket){
                TCPPacket tcp = (TCPPacket) packet[i];
                String data = new String(tcp.data);
                System.out.println("Packet " + (i+1) + " : TCP" );
                System.out.println("    source ip : " + tcp.src_ip.toString());
                System.out.println("    destination ip : " + tcp.dst_ip.toString());
                System.out.println("    source port : " + String.valueOf(tcp.src_port));
                System.out.println("    destination port : " + String.valueOf(tcp.dst_port));
                System.out.println("    offset : " + String.valueOf(tcp.offset));
                System.out.println("    data : " + data );
            }else if(packet[i] instanceof ARPPacket){
                ARPPacket arp = (ARPPacket) packet[i];
                byte[] b = new byte[4];
                String s1 = "";
                String s2 = "";

                b = arp.target_protoaddr;
                s1 += String.valueOf((b[0] & 0xff) + "." + ( b[1] & 0xff) + "." +
                        (b[2] & 0xff) + "." + (b[3] & 0xff));
                b = arp.sender_protoaddr;
                s2 += String.valueOf((b[0] & 0xff) + "." + ( b[1] & 0xff) + "." +
                        (b[2] & 0xff) + "." + (b[3] & 0xff));

                System.out.println("Packet " + (i+1) + " : ARP" );
                System.out.println("    sender address: " + s2);
                System.out.println("    target address: " + s1);
            }else if(packet[i] instanceof ICMPPacket){
                ICMPPacket icmp = (ICMPPacket) packet[i];

                System.out.println("Packet " + (i+1) + " : ICMP");
                System.out.println("    ICMP packet.");
            }else{
                System.out.println("Packet " + (i+1) + " : " );
                System.out.println("    no information.");
            }

        }
    }

    private static IPPacket generateIpPacket() throws java.io.IOException{

        Scanner scanner = new Scanner(System.in);
        System.out.print("请输入要发送的数据: ");
        String data = scanner.next();

        //构造ether帧（frame）
        EthernetPacket ether = new EthernetPacket();
        //设置帧类型为IP
        ether.frametype = EthernetPacket.ETHERTYPE_IP;
        //设置源、目的MAC地址
        ether.src_mac = "30:52:cb:f0:6f:f6".getBytes();
        ether.dst_mac = "00:0c:29:3c:0a:f1".getBytes();

        //构造IP报文
        IPPacket ipPacket = new IPPacket();
        ipPacket.setIPv4Parameter(0,false,false,false,0,false,false,
                false,0,0,128,230,InetAddress.getByName(src),
                InetAddress.getByName(dst));
        ipPacket.data = (data).getBytes();
        ipPacket.datalink = ether;

        return ipPacket;
    }

    private static TCPPacket generateTcpPacket() throws java.io.IOException{
        Scanner scanner = new Scanner(System.in);
        System.out.print("请输入要发送的数据: ");
        String data = scanner.next();

        //构造ether帧（frame）
        EthernetPacket ether = new EthernetPacket();
        //设置帧类型为IP
        ether.frametype = EthernetPacket.ETHERTYPE_IP;
        //设置源、目的MAC地址
        ether.src_mac = "30:52:cb:f0:6f:f6".getBytes();
        ether.dst_mac = "00:0c:29:3c:0a:f1".getBytes();

        //构造TCP报文
        TCPPacket tcpPacket = new TCPPacket(12, 34, 56, 78, false, false,
                false, false, true, true, true, true, 10, 0);
        //设置IP头
        tcpPacket.setIPv4Parameter(0,false,false,false,0,false,false,
                false,0,65,128,IPPacket.IPPROTO_TCP,InetAddress.getByName(src),
                InetAddress.getByName(dst));
        //设置报文数据
        tcpPacket.data = (data).getBytes();

        //设置数据链路层
        tcpPacket.datalink = ether;

        return tcpPacket;
    }

    private static ARPPacket generateArpPacket() throws java.io.IOException{

        //构造ether帧（frame）
        EthernetPacket ether = new EthernetPacket();
        //设置帧类型为IP
        ether.frametype = EthernetPacket.ETHERTYPE_ARP;
        //设置源、目的MAC地址
        ether.src_mac = "30:52:cb:f0:6f:f6".getBytes();
        ether.dst_mac = new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255};

        //构造ARP报文
        ARPPacket arpPacket = new ARPPacket();
        arpPacket.hardtype = ARPPacket.HARDTYPE_ETHER;//硬件类型
        arpPacket.prototype = ARPPacket.PROTOTYPE_IP;//协议类型
        arpPacket.operation = ARPPacket.ARP_REQUEST;//指明为ARP请求报文(另一种为回复报文)
        arpPacket.hlen = 6;//物理地址长度
        arpPacket.plen = 4;//协议地址长度
        arpPacket.sender_hardaddr = ether.src_mac;//发送端为本机mac地址
        arpPacket.sender_protoaddr = InetAddress.getByName(src).getAddress();//本机IP地址
        arpPacket.target_hardaddr = ether.dst_mac; //目的端mac地址为广播地址
        arpPacket.target_protoaddr = InetAddress.getByName(dst).getAddress();//目的IP地址
        arpPacket.datalink = ether;//设置arp报文数据链路层

        return arpPacket;
    }

    private static UDPPacket generateUdpPacket() throws java.io.IOException{

        Scanner scanner = new Scanner(System.in);
        System.out.print("请输入要发送的数据: ");
        String data = scanner.next();

        //构造以太帧（frame）
        EthernetPacket ether = new EthernetPacket();
        //设置帧类型为IP
        ether.frametype = EthernetPacket.ETHERTYPE_IP;
        //设置源、目的MAC地址
        ether.src_mac = "30:52:cb:f0:6f:f6".getBytes();
        ether.dst_mac = "00:0c:29:3c:0a:f1".getBytes();

        //构造UDP报文
        UDPPacket udpPacket = new UDPPacket(12, 34);
        udpPacket.src_ip = InetAddress.getByName(src);
        udpPacket.dst_ip = InetAddress.getByName(dst);
        udpPacket.data = data.getBytes();

        //设置IP头
        udpPacket.setIPv4Parameter(0,false,false,false,0,false,false,
                false,0,65,128,IPPacket.IPPROTO_UDP,InetAddress.getByName(src),
                InetAddress.getByName(dst));
        udpPacket.datalink = ether;

        return udpPacket;
    }

    private static ICMPPacket generateIcmpPacket() throws java.io.IOException{

        //构造以太帧（frame）
        EthernetPacket ether = new EthernetPacket();
        //设置帧类型为IP
        ether.frametype = EthernetPacket.ETHERTYPE_IP;
        //设置源、目的MAC地址
        ether.src_mac = "30:52:cb:f0:6f:f6".getBytes();
        ether.dst_mac = new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255};

        //生成ICMP报文
        ICMPPacket icmpPacket = new ICMPPacket();
        icmpPacket.type = ICMPPacket.ICMP_ECHO;//发送回显请求报文
        icmpPacket.data = "test".getBytes();

        //设置IPV4头
        icmpPacket.setIPv4Parameter(0,false,false,false,0,false,false,
                false,0,65,128,IPPacket.IPPROTO_ICMP,InetAddress.getByName(src),
                InetAddress.getByName(dst));

        //设置以太帧头部
        icmpPacket.datalink = ether;

        return icmpPacket;

    }

    public static void main(String[] args) throws java.io.IOException{

        //获取用户输入
        Scanner scanner = new Scanner(System.in);

        //存放数据包
        Packet[] packet = new Packet[max];

        //初始化数据包捕获的线程
        AThread t = null;

        //获取网络设备并显示
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        showDeviceList(devices);

        //输入选择的监控的网卡
        System.out.print("输入选择监听的适配器序号:");
        int card = scanner.nextInt();
        card = card -1;
        System.out.println();

        //打开选择的网络接口
        JpcapCaptor captor = openDevice(devices, card);

        menu:
        while(true) {
            //功能菜单
            System.out.println("请选择使用的功能编号：");
            System.out.println("1. 捕获当前网卡的数据包");
            System.out.println("2. 停止捕获网络数据包");
            System.out.println("3. 导入本地的网络数据包");
            System.out.println("4. 显示当前捕获的数据包");
            System.out.println("5. 保存当前的网络数据包");
            System.out.println("6. 分析数据包的协议分布");
            System.out.println("7. 查看数据包详细信息");
            System.out.println("8. 发送数据包给目标主机");
            System.out.println("9. 退出");
            System.out.print("你的选择：");
            //用户选择
            int choice = scanner.nextInt();

            //功能执行
            switch (choice){
                case 1: System.out.println("正在捕获数据包...");
                        t = new AThread(captor);
                        Thread capThread = new Thread(t);
                        capThread.start();
                        break;
                case 2: System.out.println("已停止捕获数据包");
                        t.cancel();
                        break;
                case 3: packet = readPacket(captor, "./savePacket");
                        System.out.println("已导入本地数据包");
                        break;
                case 4: System.out.println("显示当前捕获的数据包如下：");
                        if(t == null){
                            System.out.println("数据包捕获功能未开启");
                            break;
                        }
                        packet = t.getPacket();
                        showPacket(packet);
                        break;
                case 5: savePacket(captor, packet);
                        System.out.println("已保存数据包到默认位置");
                        break;
                case 6: System.out.println("数据包的协议分布如下：");
                        analyzePacket(packet);
                        break;
                case 7: System.out.println("数据包详细信息如下：");
                        showPacketDetail(packet);
                        break;
                case 8: System.out.print("请选择发送的协议类型(IP、TCP、UDP、ICMP、ARP): ");
                        JpcapSender sender = JpcapSender.openDevice(devices[card]);
                        String type = scanner.next().toUpperCase();
                        if(type.equals("IP")){
                            sender.sendPacket(generateIpPacket());
                        }else if(type.equals("TCP")) {
                            sender.sendPacket(generateTcpPacket());
                        }else if(type.equals("UDP")) {
                            sender.sendPacket(generateUdpPacket());
                        }else if(type.equals("ICMP")) {
                            sender.sendPacket(generateIcmpPacket());
                        }else if(type.equals("ARP")) {
                            sender.sendPacket(generateArpPacket());
                        }else {
                            System.out.println("输入协议类型错误");
                            break;
                        }
                        sender.close();
                        System.out.println("已发送数据包给目标地址");
                        break;
                case 9: break menu;
            }
            System.out.println();
        }

        //关闭
        captor.close();

    }

}
