//! Tracing utilities for RVM debugging and execution monitoring

/// Initialize tracing subscriber for RVM debugging with tree-like hierarchical display
#[cfg(feature = "rvm-tracing")]
pub fn init_rvm_tracing() {
    use std::string::ToString;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    struct TreeLayer;

    impl<S> tracing_subscriber::Layer<S> for TreeLayer
    where
        S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            // Calculate nesting level from span context
            let scope = ctx.event_scope(event);
            let mut level = 0;

            if let Some(scope) = scope {
                level = scope.count().saturating_sub(1);
            }

            // Create tree-like indentation
            let tree_prefix = match level {
                0 => "".to_string(),
                1 => "├── ".to_string(),
                2 => "│   ├── ".to_string(),
                3 => "│   │   ├── ".to_string(),
                4 => "│   │   │   ├── ".to_string(),
                5 => "│   │   │   │   ├── ".to_string(),
                _ => {
                    let mut prefix = std::string::String::new();
                    for _ in 0..level.saturating_sub(1) {
                        prefix.push_str("│   ");
                    }
                    prefix.push_str("├── ");
                    prefix
                }
            };

            // Add color for log level
            let level_color = match *event.metadata().level() {
                tracing::Level::ERROR => "\x1b[31m", // Red
                tracing::Level::WARN => "\x1b[33m",  // Yellow
                tracing::Level::INFO => "\x1b[32m",  // Green
                tracing::Level::DEBUG => "\x1b[36m", // Cyan
                tracing::Level::TRACE => "\x1b[37m", // White
            };
            let reset_color = "\x1b[0m";

            // Print the tree-formatted message
            std::print!(
                "{}{}{:5}{} ",
                tree_prefix,
                level_color,
                event.metadata().level(),
                reset_color
            );

            // Create a visitor to extract the message
            struct MessageVisitor {
                message: std::string::String,
            }

            impl tracing::field::Visit for MessageVisitor {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.message = std::format!("{:?}", value);
                        // Remove surrounding quotes if it's a string
                        if self.message.starts_with('"') && self.message.ends_with('"') {
                            self.message = self.message[1..self.message.len() - 1].to_string();
                        }
                    } else {
                        if !self.message.is_empty() {
                            self.message.push_str(", ");
                        }
                        self.message
                            .push_str(&std::format!("{}={:?}", field.name(), value));
                    }
                }

                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    if field.name() == "message" {
                        self.message = value.to_string();
                    } else {
                        if !self.message.is_empty() {
                            self.message.push_str(", ");
                        }
                        self.message
                            .push_str(&std::format!("{}={}", field.name(), value));
                    }
                }
            }

            let mut visitor = MessageVisitor {
                message: std::string::String::new(),
            };
            event.record(&mut visitor);

            std::println!("{}", visitor.message);
        }

        fn on_enter(&self, id: &tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
            if let Some(span) = ctx.span(id) {
                if let Some(_name) = span.name().strip_prefix("loop_") {
                    // Don't show enter/exit for loop spans to reduce noise
                }
            }
        }
    }

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,regorus::rvm=debug".into());

    let _ = tracing_subscriber::registry()
        .with(TreeLayer)
        .with(filter)
        .try_init();
}

#[cfg(not(feature = "rvm-tracing"))]
pub fn init_rvm_tracing() {
    // No-op when tracing is disabled
}

// When tracing feature is enabled, export tracing crate directly
#[cfg(feature = "rvm-tracing")]
pub use tracing::{debug, info, span, trace, Level};

// When tracing feature is disabled, define macros directly
#[cfg(not(feature = "rvm-tracing"))]
macro_rules! debug {
    ($($args:tt)*) => {};
}

#[cfg(not(feature = "rvm-tracing"))]
macro_rules! info {
    ($($args:tt)*) => {};
}

#[cfg(not(feature = "rvm-tracing"))]
macro_rules! trace {
    ($($args:tt)*) => {};
}

#[cfg(not(feature = "rvm-tracing"))]
macro_rules! span {
    ($level:expr, $name:expr $(, $($field:tt)*)*) => {
        $crate::rvm::tracing_utils::NoopSpan
    };
}

#[cfg(not(feature = "rvm-tracing"))]
pub(crate) use {debug, info, span, trace};

// No-op span type when tracing is disabled
#[cfg(not(feature = "rvm-tracing"))]
pub struct NoopSpan;

#[cfg(not(feature = "rvm-tracing"))]
impl NoopSpan {
    pub fn enter(&self) -> NoopSpanGuard {
        NoopSpanGuard
    }
}

#[cfg(not(feature = "rvm-tracing"))]
pub struct NoopSpanGuard;

// Level type when tracing is disabled
#[cfg(not(feature = "rvm-tracing"))]
pub struct Level;

#[cfg(not(feature = "rvm-tracing"))]
impl Level {
    pub const TRACE: Level = Level;
    pub const DEBUG: Level = Level;
    pub const INFO: Level = Level;
    pub const WARN: Level = Level;
    pub const ERROR: Level = Level;
}
