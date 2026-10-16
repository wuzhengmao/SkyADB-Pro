package com.qwadb.app.diagnostics

/**
 * 诊断日志的持久化编解码：每行一条记录、制表符分隔字段，
 * 字段内的制表符 / 换行 / 反斜杠做转义，保证一行一条、可安全追加与截断。
 */
internal object DiagnosticLogCodec {
    private const val FieldCount = 9

    /** 磁盘上的记录（不含运行时自增 id）。 */
    data class DecodedLog(
        val timeMillis: Long,
        val level: DiagnosticLevel,
        val module: DiagnosticModule,
        val operation: String,
        val target: String?,
        val message: String,
        val suggestion: String,
        val errorClass: String?,
        val errorMessage: String?,
    )

    fun encode(log: DiagnosticLog): String {
        return listOf(
            log.timeMillis.toString(),
            log.level.name,
            log.module.name,
            log.operation,
            log.target.orEmpty(),
            log.message,
            log.suggestion,
            log.errorClass.orEmpty(),
            log.errorMessage.orEmpty(),
        ).joinToString("\t") { escape(it) }
    }

    /** 解码一行；内容损坏 / 未知模块时返回 null（跳过该行，不影响其余记录）。 */
    fun decode(line: String): DecodedLog? {
        if (line.isBlank()) return null
        val fields = line.split('\t').map { unescape(it) }
        if (fields.size != FieldCount) return null
        val timeMillis = fields[0].toLongOrNull() ?: return null
        val level = DiagnosticLevel.entries.firstOrNull { it.name == fields[1] }
            ?: DiagnosticLevel.Error
        val module = DiagnosticModule.entries.firstOrNull { it.name == fields[2] } ?: return null
        return DecodedLog(
            timeMillis = timeMillis,
            level = level,
            module = module,
            operation = fields[3],
            target = fields[4].takeIf { it.isNotEmpty() },
            message = fields[5],
            suggestion = fields[6],
            errorClass = fields[7].takeIf { it.isNotEmpty() },
            errorMessage = fields[8].takeIf { it.isNotEmpty() },
        )
    }

    private fun escape(value: String): String = buildString(value.length) {
        for (ch in value) {
            when (ch) {
                '\\' -> append("\\\\")
                '\t' -> append("\\t")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                else -> append(ch)
            }
        }
    }

    private fun unescape(value: String): String = buildString(value.length) {
        var i = 0
        while (i < value.length) {
            val ch = value[i]
            if (ch == '\\' && i + 1 < value.length) {
                when (value[i + 1]) {
                    '\\' -> { append('\\'); i += 2 }
                    't' -> { append('\t'); i += 2 }
                    'n' -> { append('\n'); i += 2 }
                    'r' -> { append('\r'); i += 2 }
                    else -> { append(ch); i += 1 }
                }
            } else {
                append(ch)
                i += 1
            }
        }
    }
}
