package com.qwadb.app.diagnostics

import android.content.Context
import java.io.File
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * 诊断日志：内存态供 UI 展示，同时持久化到
 * `filesDir/diagnostics/diagnostic.log`（每次追加一行），重启应用后仍可查看。
 */
object DiagnosticLogger {
    private const val MaxLogs = 500
    private const val MaxLoadedFromDisk = 300
    private const val MaxFileBytes = 512 * 1024L
    private const val MaxRotatedLines = 400
    private const val MaxTargetLength = 160
    private const val MaxTextLength = 500
    private const val MaxErrorMessageLength = 300

    private val lock = Any()
    private val logsState = MutableStateFlow<List<DiagnosticLog>>(emptyList())
    private var nextId = 1L

    @Volatile private var logFile: File? = null
    @Volatile private var fileExecutor: ExecutorService? = null

    val logs: StateFlow<List<DiagnosticLog>> = logsState.asStateFlow()

    /** 初始化持久化并加载历史日志；应在 Application.onCreate 中最先调用。 */
    fun initialize(context: Context) {
        synchronized(lock) {
            if (fileExecutor != null) return
            val file = File(context.filesDir, "diagnostics/diagnostic.log")
            logFile = file
            fileExecutor = Executors.newSingleThreadExecutor { runnable ->
                Thread(runnable, "diagnostic-log")
            }
            val history = runCatching { readTailLines(file, MaxLoadedFromDisk) }
                .getOrDefault(emptyList())
                .mapNotNull(DiagnosticLogCodec::decode)
            if (history.isEmpty()) return
            var id = maxOf(nextId, (logsState.value.maxOfOrNull { it.id } ?: 0L) + 1L)
            // 文件内为从旧到新，内存列表为最新在前
            val loadedNewestFirst = history.asReversed().map { decoded ->
                DiagnosticLog(
                    id = id++,
                    timeMillis = decoded.timeMillis,
                    module = decoded.module,
                    operation = decoded.operation,
                    target = decoded.target,
                    message = decoded.message,
                    suggestion = decoded.suggestion,
                    level = decoded.level,
                    errorClass = decoded.errorClass,
                    errorMessage = decoded.errorMessage,
                )
            }
            nextId = id
            logsState.value = (logsState.value + loadedNewestFirst).take(MaxLogs)
        }
    }

    fun record(
        module: DiagnosticModule,
        operation: String,
        target: String? = null,
        message: String,
        suggestion: String,
        level: DiagnosticLevel = DiagnosticLevel.Error,
        cause: Throwable? = null,
    ) {
        val entry = synchronized(lock) {
            val normalizedTarget = target?.trim()?.take(MaxTargetLength)?.takeIf { it.isNotBlank() }
            val normalizedMessage = message.trim().take(MaxTextLength)
            val previous = logsState.value.firstOrNull()
            if (
                previous != null &&
                System.currentTimeMillis() - previous.timeMillis < 1_000 &&
                previous.module == module &&
                previous.operation == operation &&
                previous.target == normalizedTarget &&
                previous.message == normalizedMessage
            ) {
                return
            }

            val log = DiagnosticLog(
                id = nextId++,
                timeMillis = System.currentTimeMillis(),
                module = module,
                operation = operation.trim().take(MaxTargetLength),
                target = normalizedTarget,
                message = normalizedMessage,
                suggestion = suggestion.trim().take(MaxTextLength),
                level = level,
                errorClass = cause?.javaClass?.name,
                errorMessage = cause?.message?.trim()?.take(MaxErrorMessageLength),
            )
            logsState.value = (listOf(log) + logsState.value).take(MaxLogs)
            log
        }
        persist(entry)
    }

    /** 记录一条信息级日志（关键流程步骤留痕，无建议文案）。 */
    fun recordInfo(
        module: DiagnosticModule,
        operation: String,
        target: String? = null,
        message: String,
    ) {
        record(
            module = module,
            operation = operation,
            target = target,
            message = message,
            suggestion = "",
            level = DiagnosticLevel.Info,
        )
    }

    fun clear() {
        synchronized(lock) {
            logsState.value = emptyList()
        }
        val file = logFile
        val executor = fileExecutor
        if (file != null && executor != null) {
            executor.execute { runCatching { file.delete() } }
        }
    }

    private fun persist(log: DiagnosticLog) {
        val file = logFile ?: return
        val executor = fileExecutor ?: return
        val line = DiagnosticLogCodec.encode(log)
        executor.execute {
            runCatching {
                file.parentFile?.mkdirs()
                file.appendText(line + "\n")
                rotateIfNeeded(file)
            }
        }
    }

    /** 超过大小上限时保留最近若干行，重写文件。 */
    private fun rotateIfNeeded(file: File) {
        if (file.length() <= MaxFileBytes) return
        val kept = file.readLines().takeLast(MaxRotatedLines)
        file.writeText(kept.joinToString(separator = "\n", postfix = "\n"))
    }

    private fun readTailLines(file: File, maxLines: Int): List<String> {
        if (!file.isFile) return emptyList()
        return file.readLines().takeLast(maxLines)
    }
}
