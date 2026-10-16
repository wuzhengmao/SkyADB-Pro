package com.qwadb.app.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DiagnosticLogCodecTest {
    private fun sampleLog(
        level: DiagnosticLevel = DiagnosticLevel.Error,
        target: String? = "usb-otg:ABC123",
        message: String = "无法连接到设备",
        suggestion: String = "请确认设备仍通过 USB 连接后重试。",
        errorClass: String? = "java.io.IOException",
        errorMessage: String? = "connection reset",
    ) = DiagnosticLog(
        id = 7,
        timeMillis = 1_760_000_000_000,
        module = DiagnosticModule.UsbOtg,
        operation = "自动开启远程连接",
        target = target,
        message = message,
        suggestion = suggestion,
        level = level,
        errorClass = errorClass,
        errorMessage = errorMessage,
    )

    @Test
    fun encodeDecode_roundTripsAllFields() {
        val decoded = DiagnosticLogCodec.decode(DiagnosticLogCodec.encode(sampleLog()))

        requireNotNull(decoded)
        assertEquals(1_760_000_000_000, decoded.timeMillis)
        assertEquals(DiagnosticLevel.Error, decoded.level)
        assertEquals(DiagnosticModule.UsbOtg, decoded.module)
        assertEquals("自动开启远程连接", decoded.operation)
        assertEquals("usb-otg:ABC123", decoded.target)
        assertEquals("无法连接到设备", decoded.message)
        assertEquals("请确认设备仍通过 USB 连接后重试。", decoded.suggestion)
        assertEquals("java.io.IOException", decoded.errorClass)
        assertEquals("connection reset", decoded.errorMessage)
    }

    @Test
    fun encodeEscape_keepsSingleLineForSpecialCharacters() {
        val log = sampleLog(
            message = "第一行\n第二行\t带制表符\\与反斜杠",
            suggestion = "含\r回车",
        )

        val encoded = DiagnosticLogCodec.encode(log)
        assertEquals(1, encoded.lines().size)

        val decoded = DiagnosticLogCodec.decode(encoded)
        requireNotNull(decoded)
        assertEquals("第一行\n第二行\t带制表符\\与反斜杠", decoded.message)
        assertEquals("含\r回车", decoded.suggestion)
    }

    @Test
    fun decode_skipsCorruptedAndUnknownLines() {
        assertNull(DiagnosticLogCodec.decode(""))
        assertNull(DiagnosticLogCodec.decode("   "))
        assertNull(DiagnosticLogCodec.decode("只\t有\t几\t列"))
        assertNull(DiagnosticLogCodec.decode("not-a-number\tInfo\tUsbOtg\ta\t\tb\t\t\t"))
        assertNull(DiagnosticLogCodec.decode("1\tInfo\tUnknownModule\ta\t\tb\t\t\t"))
    }

    @Test
    fun decode_defaultsUnknownLevelToError() {
        val encoded = DiagnosticLogCodec.encode(sampleLog(level = DiagnosticLevel.Info))
        // 模拟旧版本写入的未知级别
        val legacy = encoded.replace("\tInfo\t", "\tWeird\t")

        val decoded = DiagnosticLogCodec.decode(legacy)
        requireNotNull(decoded)
        assertEquals(DiagnosticLevel.Error, decoded.level)
    }

    @Test
    fun decode_infoEntry_withEmptyOptionalFields() {
        val log = sampleLog(
            level = DiagnosticLevel.Info,
            target = null,
            suggestion = "",
            errorClass = null,
            errorMessage = null,
        )

        val decoded = DiagnosticLogCodec.decode(DiagnosticLogCodec.encode(log))
        requireNotNull(decoded)
        assertEquals(DiagnosticLevel.Info, decoded.level)
        assertNull(decoded.target)
        assertEquals("", decoded.suggestion)
        assertNull(decoded.errorClass)
        assertNull(decoded.errorMessage)
    }
}
