#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import Ether, IP, UDP, BOOTP, DHCP
from scapy.all import *
import subprocess
import psutil
import os
import socket
from datetime import datetime
import threading
import signal
import time
import sys

PacketCount = 0
ServerIP = "192.168.99.9"
ClientIP = "192.168.99.99"


def myexit():
    os._exit(0)


def get_netcard():
    netcard_info = []
    info = psutil.net_if_addrs()
    for k, v in info.items():
        for item in v:
            # print(k, item)
            if item.family == socket.AddressFamily.AF_INET:
                print(f"{item.address} -- {k}")
        netcard_info.append(k)
    return netcard_info


def printCount(mac):
    now = datetime.now()
    global PacketCount
    PacketCount += 1
    seq = f"[{PacketCount}]"
    print(f"{seq:<8} Assigned IP:{ClientIP} MAC:{mac} {now}")


opOffer = [
    ("message-type", 2),
    ("subnet_mask", "255.255.255.0"),
    ("router", ServerIP),
    ("NetBIOS_node_type", 8),
    ("lease_time", 86400),
    ("server_id", ServerIP),
    "end",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
]
opAck = [
    ("message-type", 5),
    ("subnet_mask", "255.255.255.0"),
    ("router", ServerIP),
    ("NetBIOS_node_type", 8),
    ("lease_time", 86400),
    ("server_id", ServerIP),
    "end",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
    "pad",
]
offerPack = (
    Ether()
    / IP(src=ServerIP, dst="255.255.255.255")
    / UDP(sport=67, dport=68)
    / BOOTP(
        op=2,
        htype=1,
        hlen=6,
        yiaddr=ClientIP,
        siaddr=ServerIP,
        options=b"c\x82Sc",
    )
    / DHCP(options=opOffer)
)
ackPack = (
    Ether()
    / IP(src=ServerIP, dst="255.255.255.255")
    / UDP(sport=67, dport=68)
    / BOOTP(
        op=2,
        htype=1,
        hlen=6,
        yiaddr=ClientIP,
        siaddr=ServerIP,
        options=b"c\x82Sc",
    )
    / DHCP(options=opAck)
)


def f(x, interface):
    # x.show()
    # print(x.summary())
    # print(x[0].src)
    # print(x[Ether].fields)
    # print(x[IP].fields)
    # print(x[UDP].fields)
    # print(x[BOOTP].fields)
    # print(x[DHCP].fields)
    dhcp_option = 0
    for i in x[DHCP].fields["options"]:
        if i[0] == "message-type":
            dhcp_option = i[1]
    # print(dhcp_option)
    if dhcp_option == 1:
        print("[ -*- Dis -*- ]")
        # print(x[3].xid)
        # print(offerPack[3].xid)
        offerPack[0].dst = x[0].src
        offerPack[3].xid = x[3].xid
        offerPack[3].chaddr = x[3].chaddr
        # offerPack.show2()
        sendp(offerPack, iface=interface, verbose=False)
        print("[ -*- Req -*- ]")
    elif dhcp_option == 3:
        print("[ -*- Off -*- ]")
        mac = x[0].src
        # print(x[3].xid)
        # print(offerPack[3].xid)
        ackPack[0].dst = x[0].src
        ackPack[3].xid = x[3].xid
        ackPack[3].chaddr = x[3].chaddr
        # x.show()
        # ackPack.show2()
        sendp(ackPack, iface=interface, verbose=False)
        print("[ -*- Ack -*- ]")
        printCount(mac)


def startDhcpServer(iface):
    sniff(filter="udp portrange 67-68", prn=lambda x: f(x, iface), iface=iface)


def printTips():
    print("")
    print(">>> 请关闭本机使用的其他DHCP服务\n")
    print(f">>> 请将有线网卡设置为 静态IP:{ServerIP} 子网掩码:255.255.255.0\n")
    print(">>> 用网线连接电脑和被测设备 并且网卡指示灯闪烁\n")
    print(">>> 如长时间未见分配IP 请插拔一下网线\n")


def selectIfaceLinux():
    cmd = subprocess.run("ifconfig", shell=True, capture_output=True)
    rt = (cmd.stdout).decode("utf8")
    err = (cmd.stderr).decode("utf8")
    ifaces = rt.split("\n\n")
    if err:
        print("*" * 10 + "\n" + rt + "\n" + "*" * 10 + "\n")
        print("*" * 10 + "\n" + err + "\n" + "*" * 10 + "\n")
        print(">>> " + "执行ifconfig命令失败" + "\n")
        return None
    else:
        for i in ifaces:
            if f"inet {ServerIP}" in i:
                iface = i.split(":")[0].strip()
                print(">>> " + f"iface is {iface}" + "\n")
                return iface
        print(">>> " + f"找不到 IP {ServerIP} 的有线网卡 请检查网络配置后重试" + "\n")
        return None


def selectIfaceWindows():
    cmd = subprocess.run("ipconfig /all", shell=True, capture_output=True)
    rt = (cmd.stdout).decode("gbk")
    err = (cmd.stderr).decode("gbk")
    ifaces = rt.split("\r\n\r\n")
    if err:
        print("*" * 10 + "\n" + rt + "\n" + "*" * 10 + "\n")
        print("*" * 10 + "\n" + err + "\n" + "*" * 10 + "\n")
        print(">>> " + "执行ifconfig命令失败" + "\n")
        return None
    else:
        for i in range(len(ifaces)):
            if ServerIP in ifaces[i] and "Ethernet adapter" in ifaces[i - 1]:
                iface = ifaces[i - 1]
                iface = iface.replace("Ethernet adapter", "").replace(":", "").strip()
                print(">>> " + f"iface is {iface}" + "\n")
                return iface
        print(">>> " + f"找不到 IP {ServerIP} 的有线网卡 请检查网络配置后重试" + "\n")
        return None


def printLogo():
    a = """
'########::'##::::'##::'######::'########::
 ##.... ##: ##:::: ##:'##... ##: ##.... ##:
 ##:::: ##: ##:::: ##: ##:::..:: ##:::: ##:
 ##:::: ##: #########: ##::::::: ########::
 ##:::: ##: ##.... ##: ##::::::: ##.....:::
 ##:::: ##: ##:::: ##: ##::: ##: ##::::::::
 ########:: ##:::: ##:. ######:: ##::::::::
........:::..:::::..:::......:::..:::::::::"""
    print(a)


def graceful_exit(signum, frame):
    print("\n收到终止信号,开始清理...")
    # 执行清理操作（如关闭文件、释放资源）
    time.sleep(1)  # 模拟清理耗时
    print("清理完成,退出程序")
    sys.exit(0)


if __name__ == "__main__":
    printLogo()

    # 注册信号处理器
    signal.signal(signal.SIGINT, graceful_exit)  # Ctrl+C
    signal.signal(signal.SIGTERM, graceful_exit)  # kill 命令
    print("程序运行中,按 Ctrl+C 退出...")

    print("version: 1.0.1")
    input(f"请将需要使用的网卡IP地址设置为:{ServerIP},回车确认: ")
    iface = ""
    print("")
    ifaces = get_netcard()
    print("")
    for i in range(len(ifaces)):
        print(f"[{i}]: {ifaces[i]}")
    print("")
    num = input("请输入需要使用的网卡前的序号,回车确认: ")
    try:
        numint = int(num)
        iface = ifaces[numint]
        print(f"您选择了: {iface}")
        print("DHCP服务已启动,如长时间未见分配IP, 请插拔一下网线\n")
    except:
        print("输入有误,即将退出\n")
        time.sleep(5)
        myexit()
    thread = threading.Thread(target=startDhcpServer, args=(iface,))
    thread.daemon = True
    thread.start()

    while True:
        pass
