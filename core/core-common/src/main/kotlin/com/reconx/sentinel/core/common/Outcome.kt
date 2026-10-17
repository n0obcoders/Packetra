package com.reconx.sentinel.core.common

/**
 * A small, explicit result type used across engines so that failures are
 * values rather than thrown exceptions. Every engine returns [Outcome] so
 * callers must handle the error path.
 */
sealed interface Outcome<out T> {
    data class Ok<out T>(val value: T) : Outcome<T>
    data class Err(val message: String, val cause: Throwable? = null) : Outcome<Nothing>

    fun getOrNull(): T? = (this as? Ok)?.value

    companion object {
        inline fun <T> catching(block: () -> T): Outcome<T> =
            try { Ok(block()) } catch (t: Throwable) { Err(t.message ?: t.javaClass.simpleName, t) }
    }
}

inline fun <T, R> Outcome<T>.map(transform: (T) -> R): Outcome<R> = when (this) {
    is Outcome.Ok -> Outcome.Ok(transform(value))
    is Outcome.Err -> this
}
