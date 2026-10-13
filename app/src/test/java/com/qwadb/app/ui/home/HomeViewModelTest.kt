package com.qwadb.app.ui.home

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HomeViewModelTest {
    @Test
    fun parseWlanIp_extractsIpFromIpAddrOutput() {
        val output = """
            3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 3000
                link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
                inet 192.168.1.5/24 brd 192.168.1.255 scope global wlan0
                   valid_lft forever preferred_lft forever
                inet6 fe80::aabb:ccff:fedd:eeff/64 scope link
                   valid_lft forever preferred_lft forever
        """.trimIndent()

        assertEquals("192.168.1.5", parseWlanIp(output))
    }

    @Test
    fun parseWlanIp_extractsIpFromIfconfigOutput() {
        val output = """
            wlan0     Link encap:Ethernet  HWaddr aa:bb:cc:dd:ee:ff
                      inet addr:10.0.0.42  Bcast:10.0.0.255  Mask:255.255.255.0
                      inet6 addr: fe80::aabb:ccff:fedd:eeff/64 Scope:Link
                      UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
        """.trimIndent()

        assertEquals("10.0.0.42", parseWlanIp(output))
    }

    @Test
    fun parseWlanIp_ignoresInet6AndInvalidOctets() {
        // inet6 不应被 IPv4 正则误匹配
        assertNull(parseWlanIp("inet6 fe80::aabb:ccff:fedd:eeff/64 scope link"))
        // 非法八位组（>255）应被拒绝
        assertNull(parseWlanIp("inet 999.1.2.3/24 brd 192.168.1.255"))
        assertNull(parseWlanIp("no addresses here"))
        assertNull(parseWlanIp(""))
    }
}
