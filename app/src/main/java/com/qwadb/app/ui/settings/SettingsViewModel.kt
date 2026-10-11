package com.qwadb.app.ui.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.core.content.FileProvider
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import com.qwadb.app.AppServices
import com.qwadb.app.BuildConfig
import com.qwadb.app.R
import com.qwadb.app.adb.AdbIdentityManager
import com.qwadb.app.adb.AdbKeyImportResult
import com.qwadb.app.adb.AdbKeyConverter
import com.qwadb.app.data.AppSettingsStore
import com.qwadb.app.data.RecentDeviceStore
import com.qwadb.app.data.ThemeMode
import com.qwadb.app.diagnostics.DiagnosticLogger
import com.qwadb.app.diagnostics.DiagnosticModule
import com.qwadb.app.discovery.NetworkInfoProvider
import com.qwadb.app.discovery.ScanRangeParser
import com.qwadb.app.download.DownloadResult
import com.qwadb.app.i18n.AppLanguage
import com.qwadb.app.i18n.appString
import com.qwadb.app.scrcpy.MirrorQualityPreset
import com.qwadb.app.validation.NetworkInputValidator
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import timber.log.Timber

data class SettingsUiState(
    val defaultPort: String = "5555",
    val connectionTimeoutSeconds: String = "10",
    val commandTimeoutSeconds: String = "30",
    val scanRanges: String = "",
    val themeMode: ThemeMode = ThemeMode.System,
    val mirrorQualityPreset: MirrorQualityPreset = MirrorQualityPreset.Balanced,
    val mirrorCustomResolution: String = "1920x1080",
    val mirrorCustomFps: String = "30",
    val mirrorCustomBitrateMbps: String = "4",
    val cameraResolution: String = "1280x720",
    val cameraFps: String = "30",
    val cameraBitrateMbps: String = "4",
    val statusRefreshIntervalMs: String = "5000",
    val language: AppLanguage = AppLanguage.FollowSystem,
    val currentVersion: String = BuildConfig.VERSION_NAME,
    val updateStatus: UpdateCheckStatus = UpdateCheckStatus.Idle,
    val updateDownload: UpdateDownloadStatus = UpdateDownloadStatus.Idle,
    val defaultPortError: String? = null,
    val connectionTimeoutError: String? = null,
    val commandTimeoutError: String? = null,
    val scanRangesError: String? = null,
    val mirrorCustomResolutionError: String? = null,
    val mirrorCustomFpsError: String? = null,
    val mirrorCustomBitrateError: String? = null,
    val cameraResolutionError: String? = null,
    val cameraFpsError: String? = null,
    val cameraBitrateError: String? = null,
    val statusRefreshIntervalError: String? = null,
    val adbKeyFingerprintMd5: String? = null,
    val adbKeyMessage: String? = null,
    val adbKeyMessageIsError: Boolean = false,
    val adbKeyBusy: Boolean = false,
    val adbKeyConfirm: AdbKeyConfirm = AdbKeyConfirm.None,
)

/** ADB 密钥操作前的确认对话框。 */
sealed interface AdbKeyConfirm {
    data object None : AdbKeyConfirm
    data object Import : AdbKeyConfirm
    data object Regenerate : AdbKeyConfirm
}

class SettingsViewModel(
    private val settingsStore: AppSettingsStore = AppServices.settingsStore,
    private val recentDeviceStore: RecentDeviceStore = AppServices.recentDeviceStore,
    private val networkInfoProvider: NetworkInfoProvider = AppServices.networkInfoProvider,
) : ViewModel() {
    private val state = MutableStateFlow(SettingsUiState(language = AppLanguage.current()))
    val uiState: StateFlow<SettingsUiState> = state.asStateFlow()
    private var defaultScanRangeSaved = false
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    init {
        viewModelScope.launch {
            settingsStore.settings.collect { settings ->
                val scanRanges = settings.scanRanges.ifBlank { currentDefaultScanRange() }
                state.value = state.value.copy(
                    defaultPort = settings.defaultPort.toString(),
                    connectionTimeoutSeconds = settings.connectionTimeoutSeconds.toString(),
                    commandTimeoutSeconds = settings.commandTimeoutSeconds.toString(),
                    scanRanges = scanRanges,
                    themeMode = settings.themeMode,
                    mirrorQualityPreset = settings.mirrorQualityPreset,
                    mirrorCustomResolution = settings.mirrorCustomResolution,
                    mirrorCustomFps = settings.mirrorCustomFps.toString(),
                    mirrorCustomBitrateMbps = settings.mirrorCustomBitrateMbps.toString(),
                    cameraResolution = settings.cameraResolution,
                    cameraFps = settings.cameraFps.toString(),
                    cameraBitrateMbps = settings.cameraBitrateMbps.toString(),
                    statusRefreshIntervalMs = settings.statusRefreshIntervalMs.toString(),
                    defaultPortError = null,
                    connectionTimeoutError = null,
                    commandTimeoutError = null,
                    scanRangesError = null,
                )
                if (!defaultScanRangeSaved && settings.scanRanges.isBlank() && scanRanges.isNotBlank()) {
                    defaultScanRangeSaved = true
                    settingsStore.updateScanRanges(scanRanges)
                }
            }
        }
        refreshAdbKeyFingerprints()
    }

    fun onDefaultPortChanged(value: String) {
        val filtered = value.filter { it.isDigit() }.take(5)
        val error = NetworkInputValidator.portError(filtered)?.resolve(AppServices.context)
        state.value = state.value.copy(defaultPort = filtered, defaultPortError = error)
        val port = filtered.toIntOrNull()
        if (port != null && error == null) {
            viewModelScope.launch {
                settingsStore.updateDefaultPort(port)
            }
        }
    }

    fun onConnectionTimeoutChanged(value: String) {
        updateTimeout(
            value = value,
            onState = { text, error ->
                state.value = state.value.copy(
                    connectionTimeoutSeconds = text,
                    connectionTimeoutError = error,
                )
            },
            onSave = settingsStore::updateConnectionTimeoutSeconds,
        )
    }

    fun onCommandTimeoutChanged(value: String) {
        updateTimeout(
            value = value,
            onState = { text, error ->
                state.value = state.value.copy(
                    commandTimeoutSeconds = text,
                    commandTimeoutError = error,
                )
            },
            onSave = settingsStore::updateCommandTimeoutSeconds,
        )
    }

    fun onScanRangesChanged(value: String) {
        val normalized = value
            .lineSequence()
            .joinToString("\n") { line -> line.trim().take(32) }
        val error = ScanRangeParser.validationError(normalized)?.resolve(AppServices.context)
        state.value = state.value.copy(scanRanges = normalized, scanRangesError = error)
        if (error == null) {
            viewModelScope.launch {
                settingsStore.updateScanRanges(normalized)
            }
        }
    }

    fun onThemeModeSelected(themeMode: ThemeMode) {
        state.value = state.value.copy(themeMode = themeMode)
        viewModelScope.launch {
            settingsStore.updateThemeMode(themeMode)
        }
    }

    fun onMirrorQualityPresetSelected(preset: MirrorQualityPreset) {
        state.value = state.value.copy(mirrorQualityPreset = preset)
        viewModelScope.launch {
            settingsStore.updateMirrorQualityPreset(preset)
        }
    }

    fun onMirrorCustomResolutionChanged(value: String) {
        updateResolution(
            value = value,
            onState = { text, error ->
                state.value = state.value.copy(
                    mirrorCustomResolution = text,
                    mirrorCustomResolutionError = error,
                )
            },
            onSave = settingsStore::updateMirrorCustomResolution,
        )
    }

    fun onMirrorCustomFpsChanged(value: String) {
        updateFps(
            value = value,
            onState = { text, error ->
                state.value = state.value.copy(
                    mirrorCustomFps = text,
                    mirrorCustomFpsError = error,
                )
            },
            onSave = settingsStore::updateMirrorCustomFps,
        )
    }

    fun onMirrorCustomBitrateMbpsChanged(value: String) {
        updateBitrate(
            value = value,
            onState = { text, error ->
                state.value = state.value.copy(
                    mirrorCustomBitrateMbps = text,
                    mirrorCustomBitrateError = error,
                )
            },
            onSave = settingsStore::updateMirrorCustomBitrateMbps,
        )
    }

    fun onCameraResolutionChanged(value: String) {
        updateResolution(
            value = value,
            onState = { text, error ->
                state.value = state.value.copy(
                    cameraResolution = text,
                    cameraResolutionError = error,
                )
            },
            onSave = settingsStore::updateCameraResolution,
        )
    }

    fun onCameraFpsChanged(value: String) {
        updateFps(
            value = value,
            onState = { text, error ->
                state.value = state.value.copy(
                    cameraFps = text,
                    cameraFpsError = error,
                )
            },
            onSave = settingsStore::updateCameraFps,
        )
    }

    fun onCameraBitrateMbpsChanged(value: String) {
        updateBitrate(
            value = value,
            onState = { text, error ->
                state.value = state.value.copy(
                    cameraBitrateMbps = text,
                    cameraBitrateError = error,
                )
            },
            onSave = settingsStore::updateCameraBitrateMbps,
        )
    }

    fun onStatusRefreshIntervalChanged(value: String) {
        val filtered = value.filter { it.isDigit() }.take(5)
        val intervalMs = filtered.toIntOrNull()
        val error = when {
            filtered.isBlank() -> appString(R.string.settings_status_refresh_required)
            intervalMs == null ||
                intervalMs !in StatusRefreshIntervalMinMs..StatusRefreshIntervalMaxMs -> {
                appString(R.string.settings_status_refresh_range)
            }
            else -> null
        }
        state.value = state.value.copy(
            statusRefreshIntervalMs = filtered,
            statusRefreshIntervalError = error,
        )
        if (intervalMs != null && error == null) {
            viewModelScope.launch {
                settingsStore.updateStatusRefreshIntervalMs(intervalMs)
            }
        }
    }

    fun onLanguageSelected(language: AppLanguage) {
        state.value = state.value.copy(language = language)
        AppLanguage.apply(language)
    }

    fun onClearRecentDevicesClicked() {
        viewModelScope.launch {
            recentDeviceStore.clear()
        }
    }

    fun onAdbKeyImportClicked() {
        state.value = state.value.copy(adbKeyConfirm = AdbKeyConfirm.Import, adbKeyMessage = null)
    }

    fun onAdbKeyRegenerateClicked() {
        state.value = state.value.copy(adbKeyConfirm = AdbKeyConfirm.Regenerate, adbKeyMessage = null)
    }

    fun onAdbKeyConfirmDismissed() {
        state.value = state.value.copy(adbKeyConfirm = AdbKeyConfirm.None)
    }

    /** 用户通过文件选择器选中的 adbkey 私钥，读取并导入替换当前密钥。 */
    fun onAdbKeyFileSelected(uri: Uri) {
        state.value = state.value.copy(adbKeyBusy = true, adbKeyMessage = null)
        viewModelScope.launch {
            val bytes = readPickedFile(uri)
            val result = if (bytes == null) {
                AdbKeyImportResult.InvalidKey
            } else {
                withContext(Dispatchers.IO) { AdbIdentityManager.importAdbKey(bytes) }
            }
            when (result) {
                is AdbKeyImportResult.Success -> {
                    refreshAdbKeyFingerprints()
                    state.value = state.value.copy(
                        adbKeyBusy = false,
                        adbKeyMessage = appString(R.string.settings_adbkey_import_success),
                        adbKeyMessageIsError = false,
                    )
                }
                AdbKeyImportResult.InvalidKey -> state.value = state.value.copy(
                    adbKeyBusy = false,
                    adbKeyMessage = appString(R.string.settings_adbkey_import_invalid),
                    adbKeyMessageIsError = true,
                )
                is AdbKeyImportResult.Failure -> {
                    DiagnosticLogger.record(
                        module = DiagnosticModule.App,
                        operation = "导入 ADB 密钥",
                        message = "adbkey 导入失败",
                        suggestion = "请确认所选文件为未加密的 RSA 私钥（adbkey）后重试。",
                        cause = result.cause,
                    )
                    state.value = state.value.copy(
                        adbKeyBusy = false,
                        adbKeyMessage = appString(R.string.settings_adbkey_import_failed),
                        adbKeyMessageIsError = true,
                    )
                }
            }
        }
    }

    /** 确认重新生成密钥：放弃当前密钥，生成全新默认密钥。 */
    fun onAdbKeyRegenerateConfirmed() {
        state.value = state.value.copy(
            adbKeyConfirm = AdbKeyConfirm.None,
            adbKeyBusy = true,
            adbKeyMessage = null,
        )
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) { AdbIdentityManager.regenerateIdentity() }
            }.onSuccess {
                refreshAdbKeyFingerprints()
                state.value = state.value.copy(
                    adbKeyBusy = false,
                    adbKeyMessage = appString(R.string.settings_adbkey_regenerate_success),
                    adbKeyMessageIsError = false,
                )
            }.onFailure { error ->
                DiagnosticLogger.record(
                    module = DiagnosticModule.App,
                    operation = "重新生成 ADB 密钥",
                    message = "ADB 密钥重新生成失败",
                    suggestion = "请重启应用后重试。",
                    cause = error,
                )
                state.value = state.value.copy(
                    adbKeyBusy = false,
                    adbKeyMessage = appString(R.string.settings_adbkey_regenerate_failed),
                    adbKeyMessageIsError = true,
                )
            }
        }
    }

    /** 把当前私钥写入用户选择的目标位置。 */
    fun onAdbKeyExportTo(uri: Uri) {
        state.value = state.value.copy(adbKeyBusy = true, adbKeyMessage = null)
        viewModelScope.launch {
            val pem = withContext(Dispatchers.IO) { AdbIdentityManager.exportPrivateKeyPem() }
            val written = pem != null && withContext(Dispatchers.IO) {
                runCatching {
                    AppServices.context.contentResolver.openOutputStream(uri).use { output ->
                        requireNotNull(output)
                        output.write(pem)
                    }
                }.isSuccess
            }
            state.value = state.value.copy(
                adbKeyBusy = false,
                adbKeyMessage = appString(
                    if (written) R.string.settings_adbkey_export_success
                    else R.string.settings_adbkey_export_failed,
                ),
                adbKeyMessageIsError = !written,
            )
        }
    }

    /** 从 Uri 读取文件内容，超过 [MaxAdbKeyFileBytes] 或读取失败返回 null。 */
    private suspend fun readPickedFile(uri: Uri): ByteArray? = withContext(Dispatchers.IO) {
        runCatching {
            AppServices.context.contentResolver.openInputStream(uri)?.use { input ->
                val buffer = ByteArrayOutputStream()
                val chunk = ByteArray(8192)
                var total = 0
                while (true) {
                    val read = input.read(chunk)
                    if (read < 0) break
                    total += read
                    if (total > MaxAdbKeyFileBytes) return@withContext null
                    buffer.write(chunk, 0, read)
                }
                buffer.toByteArray()
            }
        }.getOrNull()
    }

    /** 重新读取设备弹窗指纹，失败时延迟重试一次。 */
    private fun refreshAdbKeyFingerprints() {
        viewModelScope.launch {
            repeat(2) { attempt ->
                val md5 = withContext(Dispatchers.IO) {
                    AdbIdentityManager.exportPrivateKeyPem()?.let { pem ->
                        runCatching { AdbKeyConverter.deviceDialogFingerprint(pem) }
                            .onFailure { error ->
                                Timber.w(error, "计算设备弹窗指纹失败")
                            }
                            .getOrNull()
                    }
                }
                state.value = state.value.copy(adbKeyFingerprintMd5 = md5)
                if (md5 != null) return@launch
                if (attempt == 0) {
                    Timber.w("设备弹窗指纹读取失败，1 秒后重试")
                    delay(1_000)
                }
            }
        }
    }

    /** 检查 GitHub Releases 是否有新版本。 */
    fun checkForUpdates() {
        state.value = state.value.copy(updateStatus = UpdateCheckStatus.Checking, updateDownload = UpdateDownloadStatus.Idle)
        viewModelScope.launch {
            val status = withContext(Dispatchers.IO) {
                runCatching {
                    val request = Request.Builder()
                        .url(UpdateCheckUrl)
                        .header("Accept", "application/vnd.github+json")
                        .get()
                        .build()
                    httpClient.newCall(request).execute().use { response ->
                        if (!response.isSuccessful) error("HTTP ${response.code}")
                        val body = response.body.string().orEmpty()
                        val latest = JSONObject(body).optString("tag_name").trim()
                            .removePrefix("v")
                        if (latest.isEmpty()) error("tag_name missing")
                        when {
                            latest == BuildConfig.VERSION_NAME -> UpdateCheckStatus.Latest
                            isNewerVersion(latest, BuildConfig.VERSION_NAME) -> {
                                UpdateCheckStatus.UpdateAvailable(latest)
                            }
                            else -> UpdateCheckStatus.Latest
                        }
                    }
                }.getOrElse { UpdateCheckStatus.Failed }
            }
            state.value = state.value.copy(updateStatus = status)
        }
    }

    /** 下载最新版 APK 到应用缓存目录，下载完成后可触发安装。 */
    fun downloadUpdate() {
        val latestVersion = (state.value.updateStatus as? UpdateCheckStatus.UpdateAvailable)?.latestVersion
            ?: return
        if (state.value.updateDownload is UpdateDownloadStatus.Downloading) return
        state.value = state.value.copy(updateDownload = UpdateDownloadStatus.Downloading(0f))
        viewModelScope.launch {
            val apkUrl = withContext(Dispatchers.IO) {
                runCatching {
                    val request = Request.Builder()
                        .url(UpdateCheckUrl)
                        .header("Accept", "application/vnd.github+json")
                        .get()
                        .build()
                    httpClient.newCall(request).execute().use { response ->
                        if (!response.isSuccessful) error("HTTP ${response.code}")
                        val json = JSONObject(response.body.string().orEmpty())
                        val assets = json.optJSONArray("assets")
                        (0 until (assets?.length() ?: 0)).asSequence()
                            .map { assets!!.getJSONObject(it) }
                            .mapNotNull { obj ->
                                obj.optString("name").takeIf { it.endsWith(".apk", ignoreCase = true) }
                                    ?.let { obj.optString("browser_download_url") }
                            }
                            .firstOrNull()
                            ?: fallbackApkUrl(latestVersion)
                    }
                }.getOrElse { fallbackApkUrl(latestVersion) }
            }
            val result = AppServices.downloadManager.download(
                url = apkUrl,
                preferredFileName = "SkyADB-Pro-$latestVersion-release.apk",
                onProgress = { task ->
                    state.value = state.value.copy(
                        updateDownload = UpdateDownloadStatus.Downloading(task.progress.coerceIn(0f, 1f)),
                    )
                },
            )
            state.value = when (result) {
                is DownloadResult.Success -> state.value.copy(
                    updateDownload = UpdateDownloadStatus.Downloaded(result.localPath),
                )
                is DownloadResult.Failure -> state.value.copy(
                    updateDownload = UpdateDownloadStatus.Failed,
                )
                DownloadResult.Canceled -> state.value.copy(
                    updateDownload = UpdateDownloadStatus.Idle,
                )
            }
        }
    }

    /** 触发系统安装器安装已下载的更新 APK。 */
    fun installDownloadedUpdate() {
        val localPath = (state.value.updateDownload as? UpdateDownloadStatus.Downloaded)?.localPath
            ?: return
        val file = File(localPath)
        if (!file.isFile) {
            state.value = state.value.copy(updateDownload = UpdateDownloadStatus.Failed)
            return
        }
        val context = AppServices.context
        // 未授予"安装未知来源应用"权限时，引导用户去系统设置开启后再点击安装
        if (!context.packageManager.canRequestPackageInstalls()) {
            runCatching {
                context.startActivity(
                    Intent(
                        Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        Uri.parse("package:${context.packageName}"),
                    ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
            }
            return
        }
        runCatching {
            val uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                file,
            )
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(intent)
        }
    }

    /** 兜底构造 GitHub Releases 的 APK 下载地址。 */
    private fun fallbackApkUrl(version: String): String =
        "https://github.com/CN-QiuWan/SkyADB-Pro/releases/download/v$version/SkyADB-Pro-$version-release.apk"

    /**
     * 简单版本号比较：按 '.' 分段比较数字，candidate > current 返回 true。
     * 兼容预发布后缀（如 0.2.2-1）：主版本按数字比较，主版本相同时带后缀的视为更旧。
     */
    private fun isNewerVersion(candidate: String, current: String): Boolean {
        val (cMain, cSuffix) = splitVersion(candidate)
        val (bMain, bSuffix) = splitVersion(current)
        val maxLen = maxOf(cMain.size, bMain.size)
        for (i in 0 until maxLen) {
            val av = cMain.getOrElse(i) { 0 }
            val bv = bMain.getOrElse(i) { 0 }
            if (av != bv) return av > bv
        }
        return cSuffix.isEmpty() && bSuffix.isNotEmpty()
    }

    /** 把 "0.2.2-1" 拆成主版本数字段 [0,2,2] 与后缀 "-1"。 */
    private fun splitVersion(version: String): Pair<List<Int>, String> {
        val dashIndex = version.indexOf('-')
        val main = if (dashIndex >= 0) version.substring(0, dashIndex) else version
        val suffix = if (dashIndex >= 0) version.substring(dashIndex) else ""
        return main.split('.').mapNotNull { it.toIntOrNull() } to suffix
    }

    private fun updateTimeout(
        value: String,
        onState: (String, String?) -> Unit,
        onSave: suspend (Int) -> Unit,
    ) {
        val filtered = value.filter { it.isDigit() }.take(3)
        val seconds = filtered.toIntOrNull()
        val error = when {
            filtered.isBlank() -> appString(R.string.settings_timeout_required)
            seconds == null || seconds !in 1..300 -> appString(R.string.settings_timeout_range)
            else -> null
        }
        onState(filtered, error)
        if (seconds != null && error == null) {
            viewModelScope.launch {
                onSave(seconds)
            }
        }
    }

    /** 分辨率输入：允许 1920x1080 形式，校验通过后保存。 */
    private fun updateResolution(
        value: String,
        onState: (String, String?) -> Unit,
        onSave: suspend (String) -> Unit,
    ) {
        val trimmed = value.trim().filter { it.isLetterOrDigit() || it == 'x' || it == 'X' || it == '×' }
        val error = if (com.qwadb.app.scrcpy.parseResolutionSize(trimmed, 0) > 0) {
            null
        } else {
            appString(R.string.settings_resolution_invalid)
        }
        onState(trimmed, error)
        if (error == null && trimmed.isNotBlank()) {
            viewModelScope.launch {
                onSave(trimmed)
            }
        }
    }

    /** 帧率输入：1..120。 */
    private fun updateFps(
        value: String,
        onState: (String, String?) -> Unit,
        onSave: suspend (Int) -> Unit,
    ) {
        val filtered = value.filter { it.isDigit() }.take(3)
        val fps = filtered.toIntOrNull()
        val error = when {
            filtered.isBlank() -> appString(R.string.settings_fps_range)
            fps == null || fps !in 1..120 -> appString(R.string.settings_fps_range)
            else -> null
        }
        onState(filtered, error)
        if (fps != null && error == null) {
            viewModelScope.launch {
                onSave(fps)
            }
        }
    }

    /** 码率输入（Mbps）：1..100。 */
    private fun updateBitrate(
        value: String,
        onState: (String, String?) -> Unit,
        onSave: suspend (Int) -> Unit,
    ) {
        val filtered = value.filter { it.isDigit() }.take(3)
        val mbps = filtered.toIntOrNull()
        val error = when {
            filtered.isBlank() -> appString(R.string.settings_bitrate_range)
            mbps == null || mbps !in 1..100 -> appString(R.string.settings_bitrate_range)
            else -> null
        }
        onState(filtered, error)
        if (mbps != null && error == null) {
            viewModelScope.launch {
                onSave(mbps)
            }
        }
    }

    private fun currentDefaultScanRange(): String {
        return networkInfoProvider.currentLocalNetworks()
            .firstOrNull()
            ?.subnetLabel
            .orEmpty()
    }
}

/** 系统状态刷新间隔范围（毫秒）。 */
const val StatusRefreshIntervalMinMs = 500
const val StatusRefreshIntervalMaxMs = 10_000

/** 导入的 adbkey 文件大小上限（RSA 私钥通常约 1.7 KB）。 */
const val MaxAdbKeyFileBytes = 1_048_576

/** 版本更新检查状态。 */
sealed interface UpdateCheckStatus {
    data object Idle : UpdateCheckStatus
    data object Checking : UpdateCheckStatus
    data object Latest : UpdateCheckStatus
    data class UpdateAvailable(val latestVersion: String) : UpdateCheckStatus
    data object Failed : UpdateCheckStatus
}

/** 更新 APK 下载状态。 */
sealed interface UpdateDownloadStatus {
    data object Idle : UpdateDownloadStatus
    data class Downloading(val progress: Float) : UpdateDownloadStatus
    data class Downloaded(val localPath: String) : UpdateDownloadStatus
    data object Failed : UpdateDownloadStatus
}

private const val UpdateCheckUrl = "https://api.github.com/repos/CN-QiuWan/SkyADB-Pro/releases/latest"
