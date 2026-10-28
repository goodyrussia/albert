package com.albert.smartvpn.engine

import android.os.ParcelFileDescriptor
import android.util.Log
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.TreeMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

object Tun2Socks {
    private const val TAG = "Tun2Socks"

    private const val TCP_FIN = 0x01
    private const val TCP_SYN = 0x02
    private const val TCP_RST = 0x04
    private const val TCP_PSH = 0x08
    private const val TCP_ACK = 0x10

    // Optimized for 1400 MTU (20B IPv4 + 20B TCP + 1360B Payload = 1400B)
    private const val MAX_TCP_PAYLOAD = 1360
    private const val DNS_CACHE_TTL_MS = 300_000L // 5 minutes

    private val isRunning = AtomicBoolean(false)
    private val txBytes = AtomicLong(0L)
    private val rxBytes = AtomicLong(0L)
    private val txPackets = AtomicLong(0L)
    private val rxPackets = AtomicLong(0L)

    @Volatile private var activePfd: ParcelFileDescriptor? = null
    @Volatile private var tunInput: FileInputStream? = null
    @Volatile private var tunOutput: FileOutputStream? = null
    private val writeLock = Any()

    private data class CachedDnsEntry(val responsePayload: ByteArray, val expiresAtMs: Long)

    private val sessions = ConcurrentHashMap<String, TcpSession>()
    private val dnsCache = ConcurrentHashMap<String, CachedDnsEntry>()
    private val workerPool = Executors.newCachedThreadPool()
    private var readerThread: Thread? = null

    fun startTunnel(pfd: ParcelFileDescriptor, socksHost: String, socksPort: Int): Boolean {
        if (isRunning.get()) stopTunnel()
        return try {
            activePfd = pfd
            startInternal(pfd.fileDescriptor, socksHost, socksPort)
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to start Tun2Socks: ${t.message}", t)
            isRunning.set(false)
            false
        }
    }

    fun startTunnel(fd: Int, socksHost: String, socksPort: Int): Boolean {
        if (fd < 0) return false
        if (isRunning.get()) stopTunnel()
        return try {
            val pfd = ParcelFileDescriptor.fromFd(fd)
            activePfd = pfd
            startInternal(pfd.fileDescriptor, socksHost, socksPort)
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to start Tun2Socks from fd: ${t.message}", t)
            isRunning.set(false)
            false
        }
    }

    private fun startInternal(fileDesc: FileDescriptor, socksHost: String, socksPort: Int): Boolean {
        val fis = FileInputStream(fileDesc)
        val fos = FileOutputStream(fileDesc)
        tunInput = fis
        tunOutput = fos
        isRunning.set(true)

        readerThread = Thread({
            val buffer = ByteArray(65536)
            while (isRunning.get()) {
                try {
                    val len = fis.read(buffer)
                    if (len <= 0) {
                        if (len < 0) break
                        continue
                    }
                    txPackets.incrementAndGet()
                    txBytes.addAndGet(len.toLong())
                    val packet = buffer.copyOfRange(0, len)
                    handleOutgoingIpPacket(packet, socksHost, socksPort)
                } catch (_: Throwable) {
                    if (!isRunning.get()) break
                }
            }
        }, "SmartVPN-PureTunReader").apply {
            priority = Thread.MAX_PRIORITY
            isDaemon = true
            start()
        }

        VpnStateBridge.addLog("TUN interface bridged to SOCKS5 ($socksHost:$socksPort)")
        return true
    }

    fun stopTunnel() {
        if (!isRunning.getAndSet(false)) return
        try {
            readerThread?.interrupt()
        } catch (_: Throwable) {}
        readerThread = null

        val allSessions = ArrayList(sessions.values)
        sessions.clear()
        for (s in allSessions) {
            s.closeQuietly()
        }

        try { tunInput?.close() } catch (_: Throwable) {}
        try { tunOutput?.close() } catch (_: Throwable) {}
        tunInput = null
        tunOutput = null
        activePfd = null
    }

    fun getStats(): LongArray {
        return longArrayOf(
            txPackets.get(),
            txBytes.get(),
            rxPackets.get(),
            rxBytes.get()
        )
    }

    private fun writeToTun(packet: ByteArray) {
        val out = tunOutput ?: return
        if (!isRunning.get()) return
        synchronized(writeLock) {
            try {
                out.write(packet)
                rxPackets.incrementAndGet()
                rxBytes.addAndGet(packet.size.toLong())
            } catch (_: Throwable) {}
        }
    }

    private fun handleOutgoingIpPacket(packet: ByteArray, socksHost: String, socksPort: Int) {
        if (packet.size < 20) return
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || packet.size < ihl) return

        val totalLen = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
        val actualLen = minOf(totalLen, packet.size)
        if (actualLen < ihl) return

        val protocol = packet[9].toInt() and 0xFF
        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)

        when (protocol) {
            6 -> handleTcpPacket(packet, ihl, actualLen, srcIp, dstIp, socksHost, socksPort)
            17 -> handleUdpPacket(packet, ihl, actualLen, srcIp, dstIp, socksHost, socksPort)
        }
    }

    private fun extractDnsCacheKey(udpPayload: ByteArray): String? {
        if (udpPayload.size < 17) return null
        // Skip 2-byte Transaction ID; use Flags + Counts + Question section as cache key
        return try {
            udpPayload.copyOfRange(4, minOf(udpPayload.size, 96)).joinToString(",") { "%02x".format(it) }
        } catch (_: Throwable) {
            null
        }
    }

    private fun handleUdpPacket(
        packet: ByteArray,
        ihl: Int,
        actualLen: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
        socksHost: String,
        socksPort: Int
    ) {
        if (actualLen < ihl + 8) return
        val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
        val payloadOffset = ihl + 8
        if (actualLen <= payloadOffset) return

        // Reject non-DNS UDP (e.g. QUIC UDP:443) immediately with ICMP Port Unreachable
        // so browsers/apps fall back to TCP/TLS in < 1ms instead of hanging for 5 seconds.
        if (dstPort != 53 && dstPort != 5353) {
            val icmpUnreachable = buildIcmpPortUnreachable(srcIp, dstIp, packet, ihl)
            if (icmpUnreachable != null) {
                writeToTun(icmpUnreachable)
            }
            return
        }

        val udpPayload = packet.copyOfRange(payloadOffset, actualLen)
        val cacheKey = extractDnsCacheKey(udpPayload)

        if (cacheKey != null) {
            val cached = dnsCache[cacheKey]
            if (cached != null) {
                if (System.currentTimeMillis() < cached.expiresAtMs && cached.responsePayload.size >= 2) {
                    val fastReply = cached.responsePayload.copyOf()
                    fastReply[0] = udpPayload[0]
                    fastReply[1] = udpPayload[1]
                    val replyPacket = buildIpv4UdpPacket(
                        srcIp = dstIp,
                        dstIp = srcIp,
                        srcPort = dstPort,
                        dstPort = srcPort,
                        payload = fastReply
                    )
                    writeToTun(replyPacket)
                    return
                } else {
                    dnsCache.remove(cacheKey)
                }
            }
        }

        workerPool.execute {
            try {
                val replyPayload = forwardUdpViaSocks5InTcp(
                    socksHost = socksHost,
                    socksPort = socksPort,
                    dstIp = dstIp,
                    dstPort = dstPort,
                    payload = udpPayload
                )
                if (replyPayload != null && replyPayload.size >= 2) {
                    if (cacheKey != null) {
                        if (dnsCache.size > 1024) dnsCache.clear()
                        dnsCache[cacheKey] = CachedDnsEntry(
                            responsePayload = replyPayload.copyOf(),
                            expiresAtMs = System.currentTimeMillis() + DNS_CACHE_TTL_MS
                        )
                    }
                    val replyPacket = buildIpv4UdpPacket(
                        srcIp = dstIp,
                        dstIp = srcIp,
                        srcPort = dstPort,
                        dstPort = srcPort,
                        payload = replyPayload
                    )
                    writeToTun(replyPacket)
                }
            } catch (_: Throwable) {}
        }
    }

    private fun forwardUdpViaSocks5InTcp(
        socksHost: String,
        socksPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray? {
        return try {
            Socket().use { sock ->
                sock.tcpNoDelay = true
                sock.soTimeout = 3500
                sock.connect(InetSocketAddress(socksHost, socksPort), 2500)
                val ins = DataInputStream(BufferedInputStream(sock.getInputStream()))
                val outs = BufferedOutputStream(sock.getOutputStream())

                // Batch SOCKS5 Greeting + CMD 0x05 + Frame to save local round-trips
                outs.write(byteArrayOf(0x05, 0x01, 0x00))
                outs.flush()
                val ver = ins.read()
                val method = ins.read()
                if (ver != 5 || method == -1) return null

                outs.write(
                    byteArrayOf(
                        0x05, 0x05, 0x00, 0x01,
                        0, 0, 0, 0,
                        0, 0
                    )
                )
                outs.flush()

                val respHeader = ByteArray(10)
                ins.readFully(respHeader)
                if (respHeader[1].toInt() != 0) return null

                val frame = ByteArrayOutputStream(10 + payload.size)
                frame.write((payload.size ushr 8) and 0xFF)
                frame.write(payload.size and 0xFF)
                frame.write(10)
                frame.write(1)
                frame.write(dstIp)
                frame.write((dstPort ushr 8) and 0xFF)
                frame.write(dstPort and 0xFF)
                frame.write(payload)

                outs.write(frame.toByteArray())
                outs.flush()

                val replyLen = ins.readUnsignedShort()
                val replyHdrLen = ins.readUnsignedByte()
                if (replyHdrLen >= 4 && replyLen in 1..65535) {
                    val skipBytes = ByteArray(replyHdrLen - 3)
                    ins.readFully(skipBytes)
                    val replyData = ByteArray(replyLen)
                    ins.readFully(replyData)
                    replyData
                } else {
                    null
                }
            }
        } catch (_: Throwable) {
            null
        }
    }

    private fun handleTcpPacket(
        packet: ByteArray,
        ihl: Int,
        actualLen: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
        socksHost: String,
        socksPort: Int
    ) {
        if (actualLen < ihl + 20) return
        val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)

        val seqNum = readUInt32(packet, ihl + 4)
        val ackNum = readUInt32(packet, ihl + 8)
        val dataOffset = ((packet[ihl + 12].toInt() ushr 4) and 0x0F) * 4
        val flags = packet[ihl + 13].toInt() and 0xFF

        val tcpHeaderEnd = ihl + dataOffset
        if (actualLen < tcpHeaderEnd) return
        val payloadLen = actualLen - tcpHeaderEnd

        val key = "${ipToString(srcIp)}:$srcPort->${ipToString(dstIp)}:$dstPort"

        if ((flags and TCP_RST) != 0) {
            sessions.remove(key)?.closeQuietly()
            return
        }

        if ((flags and TCP_SYN) != 0 && (flags and TCP_ACK) == 0) {
            sessions.remove(key)?.closeQuietly()
            val session = TcpSession(
                key = key,
                clientIp = srcIp,
                clientPort = srcPort,
                remoteIp = dstIp,
                remotePort = dstPort,
                socksHost = socksHost,
                socksPort = socksPort,
                initialClientSeq = seqNum
            )
            sessions[key] = session
            session.onSynReceived()
            return
        }

        val session = sessions[key]
        if (session == null) {
            val rstSeq = if ((flags and TCP_ACK) != 0) ackNum else 0L
            val rstPkt = buildIpv4TcpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                seq = rstSeq,
                ack = (seqNum + payloadLen.toLong()) and 0xFFFFFFFFL,
                flags = TCP_RST or TCP_ACK,
                payload = ByteArray(0)
            )
            writeToTun(rstPkt)
            return
        }

        if (payloadLen > 0) {
            val payload = packet.copyOfRange(tcpHeaderEnd, actualLen)
            session.onDataReceived(seqNum, payload)
        }

        if ((flags and TCP_FIN) != 0) {
            session.onFinReceived((seqNum + payloadLen.toLong()) and 0xFFFFFFFFL)
        }
    }

    private class TcpSession(
        val key: String,
        val clientIp: ByteArray,
        val clientPort: Int,
        val remoteIp: ByteArray,
        val remotePort: Int,
        val socksHost: String,
        val socksPort: Int,
        initialClientSeq: Long
    ) {
        @Volatile var clientNextSeq: Long = (initialClientSeq + 1L) and 0xFFFFFFFFL
        @Volatile var mySeq: Long = (System.nanoTime() and 0x7FFFFFFFL)
        private val closed = AtomicBoolean(false)
        @Volatile private var socksSocket: Socket? = null
        private val outboundQueue = LinkedBlockingQueue<ByteArray>(2048)
        private val outOfOrderBuffer = TreeMap<Long, ByteArray>()
        private val seqLock = Any()

        fun onSynReceived() {
            // MSS = 1360 (0x0550) + NOP + Window Scale = 7 (128x window multiplier = 8MB receive window)
            val synAckOptions = byteArrayOf(
                0x02, 0x04, 0x05, 0x50,
                0x01,
                0x03, 0x03, 0x07
            )
            val synAck = buildIpv4TcpPacket(
                srcIp = remoteIp,
                dstIp = clientIp,
                srcPort = remotePort,
                dstPort = clientPort,
                seq = mySeq,
                ack = clientNextSeq,
                flags = TCP_SYN or TCP_ACK,
                payload = ByteArray(0),
                tcpOptions = synAckOptions
            )
            mySeq = (mySeq + 1L) and 0xFFFFFFFFL
            writeToTun(synAck)

            workerPool.execute { runSocksLoop() }
        }

        fun onDataReceived(seqNum: Long, data: ByteArray) {
            if (closed.get() || data.isEmpty()) return
            synchronized(seqLock) {
                val diff = ((seqNum - clientNextSeq) shl 32) shr 32
                if (diff == 0L) {
                    clientNextSeq = (clientNextSeq + data.size.toLong()) and 0xFFFFFFFFL
                    outboundQueue.offer(data)

                    // Drain any contiguous out-of-order segments immediately
                    while (outOfOrderBuffer.isNotEmpty()) {
                        val firstSeq = outOfOrderBuffer.firstKey()
                        val oooDiff = ((firstSeq - clientNextSeq) shl 32) shr 32
                        if (oooDiff <= 0L) {
                            val seg = outOfOrderBuffer.remove(firstSeq) ?: continue
                            val overlap = (-oooDiff).toInt()
                            if (overlap < seg.size) {
                                val slice = if (overlap > 0) seg.copyOfRange(overlap, seg.size) else seg
                                clientNextSeq = (clientNextSeq + slice.size.toLong()) and 0xFFFFFFFFL
                                outboundQueue.offer(slice)
                            }
                        } else {
                            break
                        }
                    }
                    sendAck(TCP_ACK)
                } else if (diff < 0L) {
                    // Partial overlap retransmission
                    val overlap = (-diff).toInt()
                    if (overlap in 1 until data.size) {
                        val slice = data.copyOfRange(overlap, data.size)
                        clientNextSeq = (clientNextSeq + slice.size.toLong()) and 0xFFFFFFFFL
                        outboundQueue.offer(slice)
                    }
                    sendAck(TCP_ACK)
                } else if (diff in 1L..262144L && outOfOrderBuffer.size < 64) {
                    outOfOrderBuffer[seqNum] = data
                    sendAck(TCP_ACK)
                } else {
                    sendAck(TCP_ACK)
                }
            }
        }

        fun onFinReceived(finSeq: Long) {
            if (closed.get()) return
            synchronized(seqLock) {
                if (finSeq == clientNextSeq) {
                    clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
                }
            }
            sendAck(TCP_FIN or TCP_ACK)
            mySeq = (mySeq + 1L) and 0xFFFFFFFFL
            closeQuietly()
        }

        private fun sendAck(flags: Int) {
            val ackPkt = buildIpv4TcpPacket(
                srcIp = remoteIp,
                dstIp = clientIp,
                srcPort = remotePort,
                dstPort = clientPort,
                seq = mySeq,
                ack = clientNextSeq,
                flags = flags,
                payload = ByteArray(0)
            )
            writeToTun(ackPkt)
        }

        private fun runSocksLoop() {
            var sock: Socket? = null
            try {
                sock = Socket().apply {
                    tcpNoDelay = true
                    keepAlive = true
                    sendBufferSize = 524288
                    receiveBufferSize = 524288
                    connect(InetSocketAddress(socksHost, socksPort), 10000)
                }
                socksSocket = sock

                val ins = DataInputStream(BufferedInputStream(sock.getInputStream(), 65536))
                val outs = BufferedOutputStream(sock.getOutputStream(), 65536)

                // SOCKS5 Greeting
                outs.write(byteArrayOf(0x05, 0x01, 0x00))
                outs.flush()
                if (ins.read() != 5 || ins.read() == -1) {
                    sendRstAndClose()
                    return
                }

                // SOCKS5 CONNECT to remoteIp:remotePort
                val req = ByteArray(10)
                req[0] = 0x05
                req[1] = 0x01
                req[2] = 0x00
                req[3] = 0x01
                System.arraycopy(remoteIp, 0, req, 4, 4)
                req[8] = ((remotePort ushr 8) and 0xFF).toByte()
                req[9] = (remotePort and 0xFF).toByte()
                outs.write(req)
                outs.flush()

                val ver = ins.read()
                val rep = ins.read()
                ins.read() // RSV
                val atyp = ins.read()
                if (ver != 5 || rep != 0) {
                    sendRstAndClose()
                    return
                }
                when (atyp) {
                    1 -> ins.readFully(ByteArray(6))
                    3 -> {
                        val l = ins.read()
                        if (l > 0) ins.readFully(ByteArray(l + 2))
                    }
                    4 -> ins.readFully(ByteArray(18))
                }

                // High-speed batched uplink writer (App -> SOCKS5)
                workerPool.execute {
                    val batchList = ArrayList<ByteArray>(32)
                    try {
                        while (!closed.get() && isRunning.get()) {
                            val first = outboundQueue.poll(500, TimeUnit.MILLISECONDS) ?: continue
                            if (first.isEmpty()) break
                            outs.write(first)

                            batchList.clear()
                            outboundQueue.drainTo(batchList, 31)
                            var hitStop = false
                            for (chunk in batchList) {
                                if (chunk.isEmpty()) {
                                    hitStop = true
                                    break
                                }
                                outs.write(chunk)
                            }
                            outs.flush()
                            if (hitStop) break
                        }
                    } catch (_: Throwable) {
                    }
                }

                // High-speed downlink reader (SOCKS5 -> App)
                val readBuf = ByteArray(65536)
                while (!closed.get() && isRunning.get()) {
                    val n = ins.read(readBuf)
                    if (n == -1) break
                    if (n > 0) {
                        var offset = 0
                        while (offset < n) {
                            val segLen = minOf(MAX_TCP_PAYLOAD, n - offset)
                            val payload = readBuf.copyOfRange(offset, offset + segLen)
                            val isLastChunk = (offset + segLen >= n)
                            val segFlags = if (isLastChunk) (TCP_PSH or TCP_ACK) else TCP_ACK
                            val dataPkt = buildIpv4TcpPacket(
                                srcIp = remoteIp,
                                dstIp = clientIp,
                                srcPort = remotePort,
                                dstPort = clientPort,
                                seq = mySeq,
                                ack = clientNextSeq,
                                flags = segFlags,
                                payload = payload
                            )
                            mySeq = (mySeq + segLen.toLong()) and 0xFFFFFFFFL
                            writeToTun(dataPkt)
                            offset += segLen
                        }
                    }
                }

                if (!closed.get()) {
                    sendAck(TCP_FIN or TCP_ACK)
                    mySeq = (mySeq + 1L) and 0xFFFFFFFFL
                }
            } catch (_: Throwable) {
                sendRstAndClose()
            } finally {
                closeQuietly()
            }
        }

        private fun sendRstAndClose() {
            if (!closed.get()) {
                sendAck(TCP_RST or TCP_ACK)
            }
            closeQuietly()
        }

        fun closeQuietly() {
            if (closed.getAndSet(true)) return
            sessions.remove(key)
            synchronized(seqLock) { outOfOrderBuffer.clear() }
            outboundQueue.clear()
            outboundQueue.offer(ByteArray(0))
            try { socksSocket?.close() } catch (_: Throwable) {}
            socksSocket = null
        }
    }

    private fun buildIcmpPortUnreachable(
        clientIp: ByteArray,
        dstIp: ByteArray,
        originalPacket: ByteArray,
        ihl: Int
    ): ByteArray? {
        val quotedLen = minOf(originalPacket.size, ihl + 8)
        if (quotedLen < 20) return null
        val icmpLen = 8 + quotedLen
        val totalLen = 20 + icmpLen
        val pkt = ByteArray(totalLen)

        pkt[0] = 0x45
        pkt[1] = 0x00
        writeUInt16(pkt, 2, totalLen)
        writeUInt16(pkt, 4, 0)
        writeUInt16(pkt, 6, 0x4000)
        pkt[8] = 64
        pkt[9] = 1 // ICMP
        writeUInt16(pkt, 10, 0)
        System.arraycopy(dstIp, 0, pkt, 12, 4)
        System.arraycopy(clientIp, 0, pkt, 16, 4)
        writeUInt16(pkt, 10, computeChecksum(pkt, 0, 20))

        val icmpOff = 20
        pkt[icmpOff] = 3 // Destination Unreachable
        pkt[icmpOff + 1] = 3 // Port Unreachable
        writeUInt16(pkt, icmpOff + 2, 0)
        writeUInt32(pkt, icmpOff + 4, 0L)
        System.arraycopy(originalPacket, 0, pkt, icmpOff + 8, quotedLen)
        writeUInt16(pkt, icmpOff + 2, computeChecksum(pkt, icmpOff, icmpLen))
        return pkt
    }

    private fun ipToString(ip: ByteArray): String =
        "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}.${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"

    private fun readUInt32(buf: ByteArray, offset: Int): Long {
        return ((buf[offset].toLong() and 0xFFL) shl 24) or
            ((buf[offset + 1].toLong() and 0xFFL) shl 16) or
            ((buf[offset + 2].toLong() and 0xFFL) shl 8) or
            (buf[offset + 3].toLong() and 0xFFL)
    }

    private fun writeUInt16(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = ((value ushr 8) and 0xFF).toByte()
        buf[offset + 1] = (value and 0xFF).toByte()
    }

    private fun writeUInt32(buf: ByteArray, offset: Int, value: Long) {
        buf[offset] = ((value ushr 24) and 0xFFL).toByte()
        buf[offset + 1] = ((value ushr 16) and 0xFFL).toByte()
        buf[offset + 2] = ((value ushr 8) and 0xFFL).toByte()
        buf[offset + 3] = (value and 0xFFL).toByte()
    }

    private fun computeChecksum(buf: ByteArray, offset: Int, length: Int, initialSum: Long = 0L): Int {
        var sum = initialSum
        var i = 0
        while (i + 1 < length) {
            val word = ((buf[offset + i].toInt() and 0xFF) shl 8) or (buf[offset + i + 1].toInt() and 0xFF)
            sum += word.toLong()
            i += 2
        }
        if (i < length) {
            val last = (buf[offset + i].toInt() and 0xFF) shl 8
            sum += last.toLong()
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    private fun pseudoHeaderSum(srcIp: ByteArray, dstIp: ByteArray, protocol: Int, length: Int): Long {
        var sum = 0L
        sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
        sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
        sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
        sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
        sum += protocol
        sum += length
        return sum
    }

    private fun buildIpv4TcpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray,
        tcpOptions: ByteArray = ByteArray(0)
    ): ByteArray {
        val tcpHeaderLen = 20 + tcpOptions.size
        val totalLen = 20 + tcpHeaderLen + payload.size
        val pkt = ByteArray(totalLen)

        pkt[0] = 0x45
        pkt[1] = 0x00
        writeUInt16(pkt, 2, totalLen)
        writeUInt16(pkt, 4, 0)
        writeUInt16(pkt, 6, 0x4000)
        pkt[8] = 64
        pkt[9] = 6 // TCP
        writeUInt16(pkt, 10, 0)
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        val ipSum = computeChecksum(pkt, 0, 20)
        writeUInt16(pkt, 10, ipSum)

        val tcpOff = 20
        writeUInt16(pkt, tcpOff, srcPort)
        writeUInt16(pkt, tcpOff + 2, dstPort)
        writeUInt32(pkt, tcpOff + 4, seq)
        writeUInt32(pkt, tcpOff + 8, ack)
        pkt[tcpOff + 12] = (((tcpHeaderLen / 4) shl 4) and 0xF0).toByte()
        pkt[tcpOff + 13] = (flags and 0xFF).toByte()
        writeUInt16(pkt, tcpOff + 14, 65535)
        writeUInt16(pkt, tcpOff + 16, 0)
        writeUInt16(pkt, tcpOff + 18, 0)

        if (tcpOptions.isNotEmpty()) {
            System.arraycopy(tcpOptions, 0, pkt, tcpOff + 20, tcpOptions.size)
        }
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, pkt, tcpOff + tcpHeaderLen, payload.size)
        }

        val tcpSegmentLen = tcpHeaderLen + payload.size
        val pSum = pseudoHeaderSum(srcIp, dstIp, 6, tcpSegmentLen)
        val tcpSum = computeChecksum(pkt, tcpOff, tcpSegmentLen, pSum)
        writeUInt16(pkt, tcpOff + 16, tcpSum)

        return pkt
    }

    private fun buildIpv4UdpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)

        pkt[0] = 0x45
        pkt[1] = 0x00
        writeUInt16(pkt, 2, totalLen)
        writeUInt16(pkt, 4, 0)
        writeUInt16(pkt, 6, 0x4000)
        pkt[8] = 64
        pkt[9] = 17 // UDP
        writeUInt16(pkt, 10, 0)
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        val ipSum = computeChecksum(pkt, 0, 20)
        writeUInt16(pkt, 10, ipSum)

        val udpOff = 20
        writeUInt16(pkt, udpOff, srcPort)
        writeUInt16(pkt, udpOff + 2, dstPort)
        writeUInt16(pkt, udpOff + 4, udpLen)
        writeUInt16(pkt, udpOff + 6, 0)
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, pkt, udpOff + 8, payload.size)
        }

        val pSum = pseudoHeaderSum(srcIp, dstIp, 17, udpLen)
        val udpSum = computeChecksum(pkt, udpOff, udpLen, pSum)
        writeUInt16(pkt, udpOff + 6, if (udpSum == 0) 0xFFFF else udpSum)

        return pkt
    }
}
