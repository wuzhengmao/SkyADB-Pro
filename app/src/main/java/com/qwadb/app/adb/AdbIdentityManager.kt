package com.qwadb.app.adb

import android.content.Context
import android.util.Log
import com.flyfishxu.kadb.cert.KadbCert
import com.flyfishxu.kadb.cert.KadbCertException
import com.flyfishxu.kadb.cert.KadbCertPolicy
import com.flyfishxu.kadb.cert.OkioFilePrivateKeyStore
import com.qwadb.app.diagnostics.DiagnosticLogger
import com.qwadb.app.diagnostics.DiagnosticModule
import java.io.File
import okio.Path.Companion.toPath

/** 导入 adbkey 私钥的结果。 */
sealed interface AdbKeyImportResult {
    data class Success(val fingerprintSha256: String) : AdbKeyImportResult
    data object InvalidKey : AdbKeyImportResult
    data class Failure(val cause: Throwable) : AdbKeyImportResult
}

/** Kadb 主机身份持久化配置。 */
object AdbIdentityManager {
    private const val Tag = "SkyadbIdentity"

    fun initialize(context: Context) {
        val keyFile = File(context.filesDir, "adb_identity/adbkey.pem")
        KadbCert.configure(
            store = OkioFilePrivateKeyStore(keyFile.absolutePath.toPath()),
            policy = KadbCertPolicy(autoHealInvalidPrivateKey = true),
        )
        runCatching {
            KadbCert.ensureReady()
        }.onFailure { error ->
            Log.w(Tag, "ADB identity initialization failed", error)
            DiagnosticLogger.record(
                module = DiagnosticModule.App,
                operation = "初始化 ADB 身份",
                message = "ADB 身份初始化失败",
                suggestion = "请重启应用后重试连接；如果目标设备弹出授权窗口，请重新允许调试授权。",
                cause = error,
            )
        }
    }

    /** 导入 PC 端 adbkey 私钥（PKCS#1 / PKCS#8 PEM），替换当前密钥。 */
    fun importAdbKey(pemBytes: ByteArray): AdbKeyImportResult {
        val pkcs8Pem = try {
            AdbKeyConverter.toPkcs8Pem(pemBytes.decodeToString())
        } catch (error: AdbKeyConverter.AdbKeyFormatException) {
            return AdbKeyImportResult.InvalidKey
        }
        return try {
            val snapshot = KadbCert.importPrivateKey(pkcs8Pem)
            AdbKeyImportResult.Success(snapshot.fingerprintSha256)
        } catch (error: KadbCertException.PrivateKeyParseFailed) {
            AdbKeyImportResult.InvalidKey
        } catch (error: Throwable) {
            AdbKeyImportResult.Failure(error)
        }
    }

    /** 重新生成一套全新的默认密钥，返回新指纹。 */
    fun regenerateIdentity(): String = KadbCert.rotate().fingerprintSha256

    /** 当前私钥的 PKCS#8 PEM 内容，无密钥时返回 null。 */
    fun exportPrivateKeyPem(): ByteArray? =
        runCatching { KadbCert.exportPrivateKeyOrNull() }.getOrNull()
}
