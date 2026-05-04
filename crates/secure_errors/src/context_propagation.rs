//! Task-local error context propagation.
//!
//! Provides [`ErrorContext`] for storing request-scoped metadata (request ID,
//! actor ID, tenant ID) in a task-local variable. This allows error handling
//! code anywhere in the call stack to access contextual information without
//! passing it through every function signature.

use std::cell::RefCell;

/// Request-scoped context for error enrichment.
///
/// # Examples
///
/// ```
/// use secure_errors::context_propagation::{ErrorContext, set_error_context, get_error_context, clear_error_context};
///
/// let ctx = ErrorContext {
///     request_id: Some("req-123".to_string()),
///     actor_id: Some("user-42".to_string()),
///     tenant_id: None,
/// };
/// set_error_context(ctx);
/// assert!(get_error_context().is_some());
/// clear_error_context();
/// assert!(get_error_context().is_none());
/// ```
#[derive(Debug, Clone, Default)]
pub struct ErrorContext {
    /// The request correlation identifier.
    pub request_id: Option<String>,
    /// The authenticated actor identifier.
    pub actor_id: Option<String>,
    /// The tenant scope of the request.
    pub tenant_id: Option<String>,
}

thread_local! {
    static ERROR_CONTEXT: RefCell<Option<ErrorContext>> = const { RefCell::new(None) };
}

/// Sets the error context for the current task/thread.
pub fn set_error_context(ctx: ErrorContext) {
    ERROR_CONTEXT.with(|cell| {
        *cell.borrow_mut() = Some(ctx);
    });
}

/// Retrieves a clone of the current error context, if set.
#[must_use]
pub fn get_error_context() -> Option<ErrorContext> {
    ERROR_CONTEXT.with(|cell| cell.borrow().clone())
}

/// Clears the error context for the current task/thread.
pub fn clear_error_context() {
    ERROR_CONTEXT.with(|cell| {
        *cell.borrow_mut() = None;
    });
}
