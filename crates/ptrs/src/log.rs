#[macro_export]
macro_rules! trace {
    ($($tts:tt)*) => {
        #[cfg(any(test, feature="debug"))]
        tracing::trace!($($tts)*)
    }
}

#[macro_export]
macro_rules! debug {
    ($($tts:tt)*) => {
        #[cfg(any(test, feature="debug"))]
        tracing::debug!($($tts)*)
    }
}

#[macro_export]
macro_rules! warn {
    ($($tts:tt)*) => {
        tracing::warn!($($tts)*)
    }
}

#[macro_export]
macro_rules! info {
    ($($tts:tt)*) => {
        tracing::info!($($tts)*)
    }
}

#[macro_export]
macro_rules! error {
    ($($tts:tt)*) => {
        tracing::error!($($tts)*)
    }
}

#[macro_export]
macro_rules! trace_span {
    ($($tts:tt)*) => {
        #[cfg(any(test, feature="debug"))]
        tracing::trace_span!($($tts)*)
    }
}

#[macro_export]
macro_rules! debug_span {
    ($($tts:tt)*) => {
        #[cfg(any(test, feature="debug"))]
        tracing::debug_span!($($tts)*)
    }
}

#[macro_export]
macro_rules! warn_span {
    ($($tts:tt)*) => {
        tracing::warn_span!($($tts)*)
    }
}

#[macro_export]
macro_rules! info_span {
    ($($tts:tt)*) => {
        tracing::info_span!($($tts)*)
    }
}

#[macro_export]
macro_rules! error_span {
    ($($tts:tt)*) => {
        tracing::error_span!($($tts)*)
    }
}
