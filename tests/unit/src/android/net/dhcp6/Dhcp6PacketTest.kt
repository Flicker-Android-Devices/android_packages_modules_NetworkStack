/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net.dhcp6

import androidx.test.filters.SmallTest
import androidx.test.runner.AndroidJUnit4
import com.android.net.module.util.HexDump
import com.android.net.module.util.dhcp6.Dhcp6AdvertisePacket
import com.android.net.module.util.dhcp6.Dhcp6ConfirmPacket
import com.android.net.module.util.dhcp6.Dhcp6DeclinePacket
import com.android.net.module.util.dhcp6.Dhcp6InfoRequestPacket
import com.android.net.module.util.dhcp6.Dhcp6Packet
import com.android.net.module.util.dhcp6.Dhcp6ReleasePacket
import com.android.net.module.util.dhcp6.Dhcp6ReplyPacket
import com.android.net.module.util.dhcp6.Dhcp6SolicitPacket
import com.android.net.module.util.structs.IaAddressOption
import com.android.testutils.assertThrows
import java.net.Inet6Address
import java.net.InetAddress
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
@SmallTest
class Dhcp6PacketTest {
    @Test
    fun testDecodeDhcp6SolicitPacket() {
        val solicitHex =
                // Solicit, Transaction ID
                "01000F51" +
                // client identifier option(option_len=12)
                "0001000C0003001B024CCBFFFE5F6EA9" +
                // elapsed time option(option_len=2)
                "000800020000" +
                // IA_PD option(option_len=41, including IA prefix option)
                "00190029DE3570F50000000000000000" +
                // IA prefix option(option_len=25)
                "001A001900000000000000004000000000000000000000000000000000"
        val bytes = HexDump.hexStringToByteArray(solicitHex)
        val packet = Dhcp6Packet.decode(bytes, bytes.size)
        assertTrue(packet is Dhcp6SolicitPacket)
    }

    @Test
    fun testDecodeDhcp6SolicitPacket_incorrectOptionLength() {
        val solicitHex =
                // Solicit, Transaction ID
                "01000F51" +
                // client identifier option(option_len=12)
                "0001000C0003001B024CCBFFFE5F6EA9" +
                // elapsed time option(wrong option_len=4)
                "000800040000" +
                // IA_PD option(option_len=41, including IA prefix option)
                "00190029DE3570F50000000000000000" +
                // IA prefix option(option_len=25)
                "001A001900000000000000004000000000000000000000000000000000"
        val bytes = HexDump.hexStringToByteArray(solicitHex)
        assertThrows(Dhcp6Packet.ParseException::class.java) {
                Dhcp6Packet.decode(bytes, bytes.size)
        }
    }

    @Test
    fun testDecodeDhcp6SolicitPacket_lastTruncatedOption() {
        val solicitHex =
                // Solicit, Transaction ID
                "01000F51" +
                // client identifier option(option_len=12)
                "0001000C0003001B024CCBFFFE5F6EA9" +
                // elapsed time option(option_len=2)
                "000800020000" +
                // IA_PD option(option_len=41, including IA prefix option)
                "00190029DE3570F50000000000000000" +
                // IA prefix option(option_len=25, missing one byte)
                "001A0019000000000000000040000000000000000000000000000000"
        val bytes = HexDump.hexStringToByteArray(solicitHex)
        assertThrows(Dhcp6Packet.ParseException::class.java) {
                Dhcp6Packet.decode(bytes, bytes.size)
        }
    }

    @Test
    fun testDecodeDhcp6SolicitPacket_middleTruncatedOption() {
        val solicitHex =
                // Solicit, Transaction ID
                "01000F51" +
                // client identifier option(option_len=12, missing one byte)
                "0001000C0003001B024CCBFFFE5F6E" +
                // elapsed time option(option_len=2)
                "000800020000" +
                // IA_PD option(option_len=41, including IA prefix option)
                "00190029DE3570F50000000000000000" +
                // IA prefix option(option_len=25)
                "001A001900000000000000004000000000000000000000000000000000"
        val bytes = HexDump.hexStringToByteArray(solicitHex)
        assertThrows(Dhcp6Packet.ParseException::class.java) {
                Dhcp6Packet.decode(bytes, bytes.size)
        }
    }

    @Test
    fun testDecodeDhcp6AdvertisePacket() {
        val advertiseHex =
                // Advertise, Transaction ID
                "0200078A" +
                // server identifier option(option_len=10)
                "0002000A0003000186C9B26AED4D" +
                // client identifier option(option_len=12)
                "0001000C0003001B024CCBFFFE5F6EA9" +
                // IA_PD option(option_len=70, including IA prefix option)
                "001900460CDDCA0C000000CF0000014C" +
                // IA prefix option(option_len=25, prefix="2401:fa00:49c:412::/64")
                "001A00190000019F0000064F402401FA00049C04810000000000000000" +
                // IA prefix option(option_len=25, prefix="fdfd:9ed6:7950:2::/64")
                "001A00190000019F0000A8C040FDFD9ED6795000010000000000000000"
        val bytes = HexDump.hexStringToByteArray(advertiseHex)
        val packet = Dhcp6Packet.decode(bytes, bytes.size)
        assertTrue(packet is Dhcp6AdvertisePacket)
    }

    @Test
    fun testDecodeDhcp6SolicitPacket_unsupportedOption() {
        val advertiseHex =
                // Advertise, Transaction ID
                "0200078A" +
                // server identifier option(option_len=10)
                "0002000A0003000186C9B26AED4D" +
                // client identifier option(option_len=12)
                "0001000C0003001B024CCBFFFE5F6EA9" +
                // SOL_MAX_RT (don't support this option yet)
                "005200040000003C" +
                // IA_PD option(option_len=70, including IA prefix option)
                "001900460CDDCA0C000000CF0000014C" +
                // IA prefix option(option_len=25, prefix="2401:fa00:49c:412::/64")
                "001A00190000019F0000064F402401FA00049C04810000000000000000" +
                // IA prefix option(option_len=25, prefix="fdfd:9ed6:7950:2::/64")
                "001A00190000019F0000A8C040FDFD9ED6795000010000000000000000"
        val bytes = HexDump.hexStringToByteArray(advertiseHex)
        // The unsupported option will be skipped normally and won't throw ParseException.
        val packet = Dhcp6Packet.decode(bytes, bytes.size)
        assertTrue(packet is Dhcp6AdvertisePacket)
    }

    @Test
    fun testDecodeDhcp6ReplyPacket() {
        val replyHex =
            // Reply, Transaction ID
            "07000A47" +
            // server identifier option(option_len=10)
            "0002000A0003000186C9B26AED4D" +
            // client identifier option(option_len=12)
            "0001000C0003001B02FBBAFFFEB7BC71" +
            // SOL_MAX_RT (don't support this option yet)
            "005200040000003c" +
            // Rapid Commit
            "000e0000" +
            // DNS recursive server (don't support this opton yet)
            "00170010fdfd9ed6795000000000000000000001" +
            // IA_PD option(option_len=70, including IA prefix option)
            "0019004629cc56c7000000d300000152" +
            // IA prefix option(option_len=25, prefix="2401:fa00:49c:412::/64", preferred=400,
            // valid=1623)
            "001a00190000019000000657402401fa00049c04120000000000000000" +
            // IA prefix option(option_len=25, prefix="fdfd:9ed6:7950:2::/64", preferred=423,
            // valid=43200)
            "001a0019000001a70000a8c040fdfd9ed6795000020000000000000000"
        val bytes = HexDump.hexStringToByteArray(replyHex)
        val packet = Dhcp6Packet.decode(bytes, bytes.size)
        assertTrue(packet is Dhcp6ReplyPacket)
        assertEquals(400, packet.prefixDelegation.minimalPreferredLifetime)
        assertEquals(1623, packet.prefixDelegation.minimalValidLifetime)
    }

    @Test
    fun testGetMinimalPreferredValidLifetime() {
        val replyHex =
            // Reply, Transaction ID
            "07000A47" +
            // server identifier option(option_len=10)
            "0002000A0003000186C9B26AED4D" +
            // client identifier option(option_len=12)
            "0001000C0003001B02FBBAFFFEB7BC71" +
            // SOL_MAX_RT (don't support this option yet)
            "005200040000003c" +
            // Rapid Commit
            "000e0000" +
            // DNS recursive server (don't support this opton yet)
            "00170010fdfd9ed6795000000000000000000001" +
            // IA_PD option(option_len=70, including IA prefix option)
            "0019004629cc56c7000000d300000152" +
            // IA prefix option(option_len=25, prefix="2401:fa00:49c:412::/64", preferred=0,
            // valid=0)
            "001a00190000000000000000402401fa00049c04120000000000000000" +
            // IA prefix option(option_len=25, prefix="fdfd:9ed6:7950:2::/64", preferred=423,
            // valid=43200)
            "001a0019000001a70000a8c040fdfd9ed6795000020000000000000000"
        val bytes = HexDump.hexStringToByteArray(replyHex)
        val packet = Dhcp6Packet.decode(bytes, bytes.size)
        assertTrue(packet is Dhcp6ReplyPacket)
        assertEquals(423, packet.prefixDelegation.minimalPreferredLifetime)
        assertEquals(43200, packet.prefixDelegation.minimalValidLifetime)
    }

    @Test
    fun testStatusCodeOptionWithStatusMessage() {
        val replyHex =
            // Reply, Transaction ID
            "07000A47" +
            // server identifier option(option_len=10)
            "0002000A0003000186C9B26AED4D" +
            // client identifier option(option_len=12)
            "0001000C0003001B02FBBAFFFEB7BC71" +
            // SOL_MAX_RT (don't support this option yet)
            "005200040000003c" +
            // Rapid Commit
            "000e0000" +
            // DNS recursive server (don't support this opton yet)
            "00170010fdfd9ed6795000000000000000000001" +
            // IA_PD option (t1=t2=0, empty prefix)
            "0019000c000000000000000000000000" +
            // Status code option: status code=NoPrefixAvail
            "000d00150006" +
            // Status code option: status message="no prefix available"
            "6e6f2070726566697820617661696c61626c65"
        val bytes = HexDump.hexStringToByteArray(replyHex)
        val packet = Dhcp6Packet.decode(bytes, bytes.size)
        assertTrue(packet is Dhcp6ReplyPacket)
        assertEquals(0, packet.getPrefixDelegation().iaid)
        assertEquals(0, packet.getPrefixDelegation().t1)
        assertEquals(0, packet.getPrefixDelegation().t2)
        assertEquals(Dhcp6Packet.STATUS_NO_PREFIX_AVAIL, packet.getStatusCode())
    }

    @Test
    fun testStatusCodeOptionWithoutStatusMessage() {
        val replyHex =
            // Reply, Transaction ID
            "07000A47" +
            // server identifier option(option_len=10)
            "0002000A0003000186C9B26AED4D" +
            // client identifier option(option_len=12)
            "0001000C0003001B02FBBAFFFEB7BC71" +
            // SOL_MAX_RT (don't support this option yet)
            "005200040000003c" +
            // Rapid Commit
            "000e0000" +
            // DNS recursive server (don't support this opton yet)
            "00170010fdfd9ed6795000000000000000000001" +
            // IA_PD option (t1=t2=0, empty prefix)
            "0019000c000000000000000000000000" +
            // Status code option: status code=NoPrefixAvail
            "000d00020006"
        val bytes = HexDump.hexStringToByteArray(replyHex)
        val packet = Dhcp6Packet.decode(bytes, bytes.size)
        assertTrue(packet is Dhcp6ReplyPacket)
        assertEquals(0, packet.getPrefixDelegation().iaid)
        assertEquals(0, packet.getPrefixDelegation().t1)
        assertEquals(0, packet.getPrefixDelegation().t2)
        assertEquals(Dhcp6Packet.STATUS_NO_PREFIX_AVAIL, packet.getStatusCode())
    }

    @Test
    fun testStatusCodeOptionInIaPdWithStatusMessage() {
        val replyHex =
            // Reply, Transaction ID
            "07000A47" +
            // server identifier option(option_len=10)
            "0002000A0003000186C9B26AED4D" +
            // client identifier option(option_len=12)
            "0001000C0003001B02FBBAFFFEB7BC71" +
            // SOL_MAX_RT (don't support this option yet)
            "005200040000003c" +
            // Rapid Commit
            "000e0000" +
            // DNS recursive server (don't support this opton yet)
            "00170010fdfd9ed6795000000000000000000001" +
            // IA_PD option (t1=t2=0, status code=NoPrefixAvail,
            // status message="no prefix available")
            "00190025000000000000000000000000000d00150006" +
            "6e6f2070726566697820617661696c61626c65"
        val bytes = HexDump.hexStringToByteArray(replyHex)
        val packet = Dhcp6Packet.decode(bytes, bytes.size)
        assertTrue(packet is Dhcp6ReplyPacket)
        assertEquals(0, packet.getPrefixDelegation().iaid)
        assertEquals(0, packet.getPrefixDelegation().t1)
        assertEquals(0, packet.getPrefixDelegation().t2)
        assertEquals(Dhcp6Packet.STATUS_NO_PREFIX_AVAIL, packet.getPrefixDelegation().statusCode)
    }

    @Test
    fun testStatusCodeOptionInIaPdWithoutStatusMessage() {
        val replyHex =
            // Reply, Transaction ID
            "07000A47" +
            // server identifier option(option_len=10)
            "0002000A0003000186C9B26AED4D" +
            // client identifier option(option_len=12)
            "0001000C0003001B02FBBAFFFEB7BC71" +
            // SOL_MAX_RT (don't support this option yet)
            "005200040000003c" +
            // Rapid Commit
            "000e0000" +
            // DNS recursive server (don't support this opton yet)
            "00170010fdfd9ed6795000000000000000000001" +
            // IA_PD option (t1=t2=0, status code=NoPrefixAvail)
            "00190012000000000000000000000000000d00020006"
        val bytes = HexDump.hexStringToByteArray(replyHex)
        val packet = Dhcp6Packet.decode(bytes, bytes.size)
        assertTrue(packet is Dhcp6ReplyPacket)
        assertEquals(0, packet.getPrefixDelegation().iaid)
        assertEquals(0, packet.getPrefixDelegation().t1)
        assertEquals(0, packet.getPrefixDelegation().t2)
        assertEquals(Dhcp6Packet.STATUS_NO_PREFIX_AVAIL, packet.getPrefixDelegation().statusCode)
    }

    @Test
    fun testStatusCodeOptionWithTruncatedStatusMessage() {
        val replyHex =
            // Reply, Transaction ID
            "07000A47" +
            // server identifier option(option_len=10)
            "0002000A0003000186C9B26AED4D" +
            // client identifier option(option_len=12)
            "0001000C0003001B02FBBAFFFEB7BC71" +
            // SOL_MAX_RT (don't support this option yet)
            "005200040000003c" +
            // Rapid Commit
            "000e0000" +
            // DNS recursive server (don't support this opton yet)
            "00170010fdfd9ed6795000000000000000000001" +
            // Status code option: len=21, status code=NoPrefixAvail
            "000d00150006" +
            // Status code option: truncated status message="no prefix available"
            "6e6f2070726566697820617661696c6162"
        val bytes = HexDump.hexStringToByteArray(replyHex)
        assertThrows(Dhcp6Packet.ParseException::class.java) {
            Dhcp6Packet.decode(bytes, bytes.size)
        }
    }

    @Test
    fun testStatusCodeOptionInIaPdWithTruncatedStatusMessage() {
        val replyHex =
            // Reply, Transaction ID
            "07000A47" +
            // server identifier option(option_len=10)
            "0002000A0003000186C9B26AED4D" +
            // client identifier option(option_len=12)
            "0001000C0003001B02FBBAFFFEB7BC71" +
            // SOL_MAX_RT (don't support this option yet)
            "005200040000003c" +
            // Rapid Commit
            "000e0000" +
            // DNS recursive server (don't support this opton yet)
            "00170010fdfd9ed6795000000000000000000001" +
            // IA_PD option (t1=t2=0, empty prefix)
            "00190025000000000000000000000000" +
            // Status code option: len=21, status code=NoPrefixAvail
            "000d00150006" +
            // truncated status message="no prefix available")
            "6e6f2070726566697820617661696c6162"
        val bytes = HexDump.hexStringToByteArray(replyHex)
        assertThrows(Dhcp6Packet.ParseException::class.java) {
            Dhcp6Packet.decode(bytes, bytes.size)
        }
    }

    @Test
    fun testDecodeDhcp6SolicitPacket_iaNa() {
        val solicitHex =
            // Solicit, Transaction ID
            "01000F51" +
            // client identifier option(option_len=12)
            "0001000C0003001B024CCBFFFE5F6EA9" +
            // elapsed time option(option_len=2)
            "000800020000" +
            // IA_NA option(option_len=40, including IA Address option)
            "00030028000000010000070800000B40" +
            // IA Address option(option_len=24)
            "0005001820010DB800000000000000000000000100000E1000001C20"
        val bytes = HexDump.hexStringToByteArray(solicitHex)
        val packet = Dhcp6Packet.decode(bytes, bytes.size)
        assertTrue(packet is Dhcp6SolicitPacket)
        assertNotNull(packet.addressAssignment)
        assertEquals(1, packet.addressAssignment.iaid)
        assertEquals(1800, packet.addressAssignment.t1)
        assertEquals(2880, packet.addressAssignment.t2)
        assertEquals(1, packet.addressAssignment.iaAddresses.size)
        assertEquals("2001:db8::1", packet.addressAssignment.iaAddresses[0].address.hostAddress)
        assertEquals(3600, packet.addressAssignment.iaAddresses[0].preferred)
        assertEquals(7200, packet.addressAssignment.iaAddresses[0].valid)
    }

    @Test
    fun testDecodeDhcp6AdvertisePacket_iaNa() {
        val advertiseHex =
            // Advertise, Transaction ID
            "0200078A" +
            // server identifier option(option_len=10)
            "0002000A0003000186C9B26AED4D" +
            // client identifier option(option_len=12)
            "0001000C0003001B024CCBFFFE5F6EA9" +
            // Preference option(option_len=1, pref=255)
            "00070001FF" +
            // IA_NA option(option_len=40)
            "00030028000000010000070800000B40" +
            // IA Address option(option_len=24)
            "0005001820010DB800000000000000000000000100000E1000001C20" +
            // DNS recursive name servers option(option_len=16)
            "0017001020014860486000000000000000008888"
        val bytes = HexDump.hexStringToByteArray(advertiseHex)
        val packet = Dhcp6Packet.decode(bytes, bytes.size)
        assertTrue(packet is Dhcp6AdvertisePacket)
        assertEquals(255, packet.preference.toInt() and 0xff)
        assertNotNull(packet.addressAssignment)
        assertEquals(1, packet.addressAssignment.iaAddresses.size)
        assertEquals("2001:db8::1", packet.addressAssignment.iaAddresses[0].address.hostAddress)
        assertEquals(1, packet.dnsServers.size)
        assertEquals("2001:4860:4860::8888", packet.dnsServers[0].hostAddress)
    }

    @Test
    fun testDecodeDhcp6ReplyPacket_iaNa() {
        val replyHex =
            // Reply, Transaction ID
            "07000A47" +
            // server identifier option(option_len=10)
            "0002000A0003000186C9B26AED4D" +
            // client identifier option(option_len=12)
            "0001000C0003001B02FBBAFFFEB7BC71" +
            // IA_NA option(option_len=40)
            "00030028000000010000070800000B40" +
            // IA Address option(option_len=24)
            "0005001820010DB800000000000000000000000100000E1000001C20" +
            // DNS servers option(option_len=16)
            "0017001020014860486000000000000000008888"
        val bytes = HexDump.hexStringToByteArray(replyHex)
        val packet = Dhcp6Packet.decode(bytes, bytes.size)
        assertTrue(packet is Dhcp6ReplyPacket)
        assertNotNull(packet.addressAssignment)
        assertEquals(1, packet.addressAssignment.iaid)
        assertEquals(1800, packet.addressAssignment.t1)
        assertEquals(2880, packet.addressAssignment.t2)
        assertEquals(1, packet.addressAssignment.iaAddresses.size)
        assertEquals("2001:db8::1", packet.addressAssignment.iaAddresses[0].address.hostAddress)
        assertEquals(3600, packet.addressAssignment.iaAddresses[0].preferred)
        assertEquals(7200, packet.addressAssignment.iaAddresses[0].valid)
        assertEquals(1, packet.dnsServers.size)
        assertEquals("2001:4860:4860::8888", packet.dnsServers[0].hostAddress)
    }

    @Test
    fun testBuildAndDecodeDhcp6Solicit_iaNa() {
        val clientDuid = byteArrayOf(0, 3, 0, 1, 1, 2, 3, 4, 5, 6)
        val addr = InetAddress.getByName("2001:db8::1") as Inet6Address
        val iaAddr = IaAddressOption(addr, 3600, 7200)
        val oro = shortArrayOf(23, 24)
        val buf = Dhcp6Packet.buildSolicitPacket(
            0x123456, 0, clientDuid, null, 1, listOf(iaAddr), null, oro
        )
        val packet = Dhcp6Packet.decode(buf.array(), buf.limit())
        assertTrue(packet is Dhcp6SolicitPacket)
        assertEquals(0x123456, packet.transId)
        assertNotNull(packet.addressAssignment)
        assertEquals(1, packet.addressAssignment.iaid)
        assertEquals(1, packet.addressAssignment.iaAddresses.size)
        assertEquals(addr, packet.addressAssignment.iaAddresses[0].address)
    }

    @Test
    fun testBuildAndDecodeDhcp6DeclinePacket() {
        val clientDuid = byteArrayOf(0, 3, 0, 1, 1, 2, 3, 4, 5, 6)
        val serverDuid = byteArrayOf(0, 3, 0, 1, 6, 5, 4, 3, 2, 1)
        val declinedAddr = InetAddress.getByName("2001:db8::2") as Inet6Address
        val buf = Dhcp6Packet.buildDeclinePacket(
            0x654321, 0, clientDuid, serverDuid, 1, declinedAddr
        )
        val packet = Dhcp6Packet.decode(buf.array(), buf.limit())
        assertTrue(packet is Dhcp6DeclinePacket)
        assertEquals(0x654321, packet.transId)
        assertNotNull(packet.addressAssignment)
        assertEquals(1, packet.addressAssignment.iaAddresses.size)
        assertEquals(declinedAddr, packet.addressAssignment.iaAddresses[0].address)
    }

    @Test
    fun testBuildAndDecodeDhcp6ConfirmPacket() {
        val clientDuid = byteArrayOf(0, 3, 0, 1, 1, 2, 3, 4, 5, 6)
        val addr = InetAddress.getByName("2001:db8::3") as Inet6Address
        val iaAddr = IaAddressOption(addr, 1800, 3600)
        val buf = Dhcp6Packet.buildConfirmPacket(
            0xabcdef, 0, clientDuid, 1, listOf(iaAddr)
        )
        val packet = Dhcp6Packet.decode(buf.array(), buf.limit())
        assertTrue(packet is Dhcp6ConfirmPacket)
        assertEquals(0xabcdef, packet.transId)
        assertNotNull(packet.addressAssignment)
        assertEquals(1, packet.addressAssignment.iaAddresses.size)
        assertEquals(addr, packet.addressAssignment.iaAddresses[0].address)
    }

    @Test
    fun testBuildAndDecodeDhcp6ReleasePacket() {
        val clientDuid = byteArrayOf(0, 3, 0, 1, 1, 2, 3, 4, 5, 6)
        val serverDuid = byteArrayOf(0, 3, 0, 1, 6, 5, 4, 3, 2, 1)
        val addr = InetAddress.getByName("2001:db8::4") as Inet6Address
        val iaAddr = IaAddressOption(addr, 0, 0)
        val buf = Dhcp6Packet.buildReleasePacket(
            0x112233, 0, clientDuid, serverDuid, 1, listOf(iaAddr), null
        )
        val packet = Dhcp6Packet.decode(buf.array(), buf.limit())
        assertTrue(packet is Dhcp6ReleasePacket)
        assertEquals(0x112233, packet.transId)
        assertNotNull(packet.addressAssignment)
        assertEquals(1, packet.addressAssignment.iaAddresses.size)
        assertEquals(addr, packet.addressAssignment.iaAddresses[0].address)
    }

    @Test
    fun testBuildAndDecodeDhcp6InfoRequestPacket() {
        val clientDuid = byteArrayOf(0, 3, 0, 1, 1, 2, 3, 4, 5, 6)
        val oro = shortArrayOf(23, 24)
        val buf = Dhcp6Packet.buildInfoRequestPacket(0x334455, 0, clientDuid, oro)
        val packet = Dhcp6Packet.decode(buf.array(), buf.limit())
        assertTrue(packet is Dhcp6InfoRequestPacket)
        assertEquals(0x334455, packet.transId)
    }

    @Test
    fun testDomainListEncodeAndDecode() {
        val domains = listOf("example.com", "sub.domain.org")
        val encoded = Dhcp6Packet.encodeDomainList(domains)
        assertNotNull(encoded)
        val decoded = Dhcp6Packet.decodeDomainList(java.nio.ByteBuffer.wrap(encoded))
        assertEquals(domains, decoded)
    }

    @Test
    fun testDomainListDecode_withCompression() {
        val raw = byteArrayOf(
            3, 'e'.code.toByte(), 'n'.code.toByte(), 'g'.code.toByte(),
            5, 'a'.code.toByte(), 'p'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0,
            9, 'm'.code.toByte(), 'a'.code.toByte(), 'r'.code.toByte(), 'k'.code.toByte(),
            'e'.code.toByte(), 't'.code.toByte(), 'i'.code.toByte(), 'n'.code.toByte(), 'g'.code.toByte(),
            0xc0.toByte(), 4
        )
        val decoded = Dhcp6Packet.decodeDomainList(java.nio.ByteBuffer.wrap(raw))
        assertEquals(listOf("eng.apple.com", "marketing.apple.com"), decoded)
    }
}
