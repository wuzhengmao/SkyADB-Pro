package com.qwadb.app.adb

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.PKCS8EncodedKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.pkcs.RSAPrivateKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AdbKeyConverterTest {
    private val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    /** 桌面 adb 生成的 adbkey：PKCS#1（`-----BEGIN RSA PRIVATE KEY-----`）。 */
    @OptIn(ExperimentalEncodingApi::class)
    private fun pkcs1Pem(): String {
        val privateKeyInfo = PrivateKeyInfo.getInstance(keyPair.private.encoded)
        val rsaPrivate = RSAPrivateKey.getInstance(privateKeyInfo.parsePrivateKey())
        return "-----BEGIN RSA PRIVATE KEY-----\n" +
            Base64.encode(rsaPrivate.encoded) + "\n" +
            "-----END RSA PRIVATE KEY-----"
    }

    /** Kadb 存储格式：PKCS#8（`-----BEGIN PRIVATE KEY-----`）。 */
    @OptIn(ExperimentalEncodingApi::class)
    private fun pkcs8Pem(): String {
        return "-----BEGIN PRIVATE KEY-----\n" +
            Base64.encode(keyPair.private.encoded) + "\n" +
            "-----END PRIVATE KEY-----"
    }

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun toPkcs8Pem_convertsPkcs1AdbKeyIntoParseablePkcs8() {
        val converted = AdbKeyConverter.toPkcs8Pem(pkcs1Pem()).decodeToString()

        assertTrue(converted.startsWith("-----BEGIN PRIVATE KEY-----"))
        assertTrue(converted.endsWith("-----END PRIVATE KEY-----"))
        assertTrue(!converted.contains("RSA PRIVATE KEY"))

        // 转换结果必须能被标准 JCA 按 PKCS#8 解析
        val body = converted
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\r", "")
            .replace("\n", "")
        val parsed = KeyFactory.getInstance("RSA")
            .generatePrivate(PKCS8EncodedKeySpec(Base64.decode(body)))
        assertEquals("RSA", parsed.algorithm)
    }

    @Test
    fun toPkcs8Pem_passesPkcs8ThroughAndRoundTripsFingerprint() {
        val converted = AdbKeyConverter.toPkcs8Pem(pkcs8Pem())
        val fingerprint = AdbKeyConverter.deviceDialogFingerprint(converted)

        // 与原始 PKCS#1 转换结果应得到相同指纹（同一把钥匙）
        val fingerprintFromPkcs1 =
            AdbKeyConverter.deviceDialogFingerprint(AdbKeyConverter.toPkcs8Pem(pkcs1Pem()))
        assertEquals(fingerprintFromPkcs1, fingerprint)
    }

    @Test
    fun adbPubkeyBlob_hasAdbWireFormatStructure() {
        val blob = AdbKeyConverter.adbPubkeyBlob(AdbKeyConverter.toPkcs8Pem(pkcs1Pem()))
        val buffer = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN)

        assertEquals(AdbKeyConverter.AdbPubkeyBlobSize, blob.size)
        assertEquals(64, buffer.getInt()) // modulus_size_words
        val n0inv = buffer.getInt().toLong() and 0xffffffffL
        val publicKey = keyPair.public as java.security.interfaces.RSAPublicKey
        val n0 = publicKey.modulus.toLong() and 0xffffffffL
        // n0inv = -1 / N[0] mod 2^32，即 N[0] * n0inv ≡ -1 (mod 2^32)
        assertEquals(0xffffffffL, (n0 * n0inv) and 0xffffffffL)
        // 模数：256 字节小端
        val modulus = ByteArray(256)
        buffer.get(modulus)
        assertEquals(publicKey.modulus, java.math.BigInteger(1, modulus.reversedArray()))
        // rr = (2^2048)^2 mod N：256 字节小端
        val rr = ByteArray(256)
        buffer.get(rr)
        val expectedRr = java.math.BigInteger.ONE.shiftLeft(2048)
            .modPow(java.math.BigInteger.valueOf(2), publicKey.modulus)
        assertEquals(expectedRr, java.math.BigInteger(1, rr.reversedArray()))
        assertEquals(65537, buffer.getInt()) // exponent
    }

    @Test
    fun deviceDialogFingerprint_matchesDialogFormatAndIsMd5OfBlob() {
        val pem = AdbKeyConverter.toPkcs8Pem(pkcs1Pem())
        val fingerprint = AdbKeyConverter.deviceDialogFingerprint(pem)

        // 与设备弹窗一致的格式：无前缀、冒号分隔的 16 组两位大写十六进制
        val groups = fingerprint.split(":")
        assertEquals(16, groups.size)
        assertTrue(groups.all { it.length == 2 && it.toLongOrNull(16) != null })

        // 指纹 = MD5(ADB 公钥 blob)，与 AOSP getFingerprints 相同
        val expected = MessageDigest.getInstance("MD5")
            .digest(AdbKeyConverter.adbPubkeyBlob(pem))
            .joinToString(":") { byte -> "%02X".format(byte.toInt() and 0xff) }
        assertEquals(expected, fingerprint)
    }

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun toPkcs8Pem_rejectsEncryptedKeys() {
        val encryptedPem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
            Base64.encode("encrypted key payload".toByteArray()) + "\n" +
            "-----END ENCRYPTED PRIVATE KEY-----"

        assertThrows(AdbKeyConverter.AdbKeyFormatException::class.java) {
            AdbKeyConverter.toPkcs8Pem(encryptedPem)
        }
    }

    @Test
    fun toPkcs8Pem_rejectsGarbageAndPubKeyFiles() {
        assertThrows(AdbKeyConverter.AdbKeyFormatException::class.java) {
            AdbKeyConverter.toPkcs8Pem("QAAAAAQb... user@host") // adbkey.pub 的内容
        }
        assertThrows(AdbKeyConverter.AdbKeyFormatException::class.java) {
            AdbKeyConverter.toPkcs8Pem("not a key at all")
        }
    }
}
