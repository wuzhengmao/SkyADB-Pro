package com.qwadb.app.adb

import java.io.StringReader
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.pkcs.RSAPrivateKey
import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter

/**
 * PC 端 adbkey（`~/.android/adbkey`）与 Kadb 密钥存储之间的格式转换。
 *
 * 桌面 adb 生成的是 PKCS#1（`-----BEGIN RSA PRIVATE KEY-----`），
 * 而 Kadb 只接受 PKCS#8（`-----BEGIN PRIVATE KEY-----`），导入前需要转换。
 */
object AdbKeyConverter {
    private const val Pkcs8Begin = "-----BEGIN PRIVATE KEY-----"
    private const val Pkcs8End = "-----END PRIVATE KEY-----"

    /** RSA 模数字节数（2048 位）。 */
    private const val ModulusSize = 256

    /** 模数长度（以 32 位字为单位）。 */
    private const val ModulusSizeWords = 64

    /** ADB 公钥 blob 总字节数：3 个 int + 2 段模数字节。 */
    const val AdbPubkeyBlobSize = 3 * 4 + 2 * ModulusSize

    /** 无法识别的 PEM 内容（格式错误 / 加密 / 非 RSA 等）。 */
    class AdbKeyFormatException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** 把 PKCS#1 或 PKCS#8 PEM 私钥统一转换为 Kadb 接受的 PKCS#8 PEM。 */
    @OptIn(ExperimentalEncodingApi::class)
    fun toPkcs8Pem(pemText: String): ByteArray {
        val text = pemText.removePrefix("﻿").trim()
        val parsed = runCatching {
            PEMParser(StringReader(text)).use { it.readObject() }
        }.getOrElse { error -> throw AdbKeyFormatException("PEM 解析失败", error) }

        val privateKey = when (parsed) {
            is PEMKeyPair -> runCatching {
                JcaPEMKeyConverter().getKeyPair(parsed).private
            }.getOrElse { error -> throw AdbKeyFormatException("RSA 私钥解析失败", error) }
            is PrivateKeyInfo -> runCatching {
                JcaPEMKeyConverter().getPrivateKey(parsed)
            }.getOrElse { error -> throw AdbKeyFormatException("私钥解析失败", error) }
            is PEMEncryptedKeyPair -> throw AdbKeyFormatException("不支持加密的私钥")
            else -> throw AdbKeyFormatException("不是 PEM 私钥文件")
        }
        if (privateKey.algorithm != "RSA") {
            throw AdbKeyFormatException("仅支持 RSA 私钥")
        }
        val encoded = privateKey.encoded
            ?: throw AdbKeyFormatException("无法编码私钥")
        val base64 = Base64.encode(encoded)
        return (Pkcs8Begin + "\n" + base64 + "\n" + Pkcs8End).toByteArray()
    }

    /**
     * 设备授权弹窗显示的指纹：对 ADB 专有公钥格式（adbkey.pub 中 base64 段解码后的内容）
     * 取 MD5，冒号分隔的十六进制。与 AOSP `AdbDebuggingManager.getFingerprints` 完全一致，
     * 可直接和弹窗中显示的字符串比对。
     */
    @OptIn(ExperimentalEncodingApi::class)
    fun deviceDialogFingerprint(pkcs8Pem: ByteArray): String {
        val digest = MessageDigest.getInstance("MD5").digest(adbPubkeyBlob(pkcs8Pem))
        return digest.joinToString(":") { byte -> "%02X".format(byte.toInt() and 0xff) }
    }

    /**
     * 把 RSA 公钥编码为 ADB 专有格式（[AdbPubkeyBlobSize] 字节），
     * 与 AOSP `libcrypto_utils` 的 `android_pubkey_encode` 一致。
     */
    fun adbPubkeyBlob(pkcs8Pem: ByteArray): ByteArray {
        val publicKey = parseRsaPublicKey(pkcs8Pem)
        val modulus = publicKey.modulus
        val buffer = ByteBuffer.allocate(AdbPubkeyBlobSize).order(ByteOrder.LITTLE_ENDIAN)
        // 模数长度（以 32 位字为单位）
        buffer.putInt(ModulusSizeWords)
        // n0inv = -1 / N[0] mod 2^32
        val r32 = BigInteger.ONE.shiftLeft(32)
        buffer.putInt(r32.subtract(modulus.mod(r32).modInverse(r32)).toInt())
        // 模数，小端 256 字节
        buffer.put(littleEndianPadded(modulus, ModulusSize))
        // rr = (2^(rsa_size))^2 mod N
        val rr = BigInteger.ONE.shiftLeft(ModulusSize * 8).modPow(BigInteger.valueOf(2), modulus)
        buffer.put(littleEndianPadded(rr, ModulusSize))
        // 公钥指数
        buffer.putInt(publicKey.publicExponent.toInt())
        return buffer.array()
    }

    /** 大端整数转指定长度的小端字节数组（右侧补零）。 */
    private fun littleEndianPadded(value: BigInteger, size: Int): ByteArray {
        val out = ByteArray(size)
        val bytes = value.toByteArray().reversedArray()
        System.arraycopy(bytes, 0, out, 0, minOf(bytes.size, size))
        return out
    }

    /** 从 PKCS#8 PEM 解析 RSA 公钥。 */
    @OptIn(ExperimentalEncodingApi::class)
    private fun parseRsaPublicKey(pkcs8Pem: ByteArray): RSAPublicKey {
        val text = pkcs8Pem.decodeToString()
            .replace(Pkcs8Begin, "")
            .replace(Pkcs8End, "")
            .replace("\r", "")
            .replace("\n", "")
            .trim()
        val keyFactory = KeyFactory.getInstance("RSA")
        val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(Base64.decode(text)))
        val rsaPrivate = privateKey as? RSAPrivateCrtKey
        return if (rsaPrivate != null) {
            keyFactory.generatePublic(
                RSAPublicKeySpec(rsaPrivate.modulus, rsaPrivate.publicExponent),
            ) as RSAPublicKey
        } else {
            // 非 CRT 形式的 RSA 私钥兜底解析（Kadb 同款路径）
            val privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.encoded)
            val bcKey = RSAPrivateKey.getInstance(privateKeyInfo.parsePrivateKey())
            keyFactory.generatePublic(
                RSAPublicKeySpec(bcKey.modulus, bcKey.publicExponent),
            ) as RSAPublicKey
        }
    }
}
