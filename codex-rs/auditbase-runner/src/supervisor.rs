use codex_auditbase_contract::Failure;
use codex_auditbase_contract::FailureCode;
use codex_exec::ThreadEvent;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessDisposition {
    Exited { code: i32 },
    Crashed,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalOutputState {
    Valid,
    Missing,
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunResolution {
    Completed,
    Failed(Failure),
}

impl RunResolution {
    pub fn failure(&self) -> Option<&Failure> {
        match self {
            Self::Completed => None,
            Self::Failed(failure) => Some(failure),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawTerminal {
    Completed,
    TurnFailed,
    StreamError,
}

/// Deterministically classifies already-observed process/event fixtures. It
/// does not spawn a process and is safe to run before hostile-job isolation is
/// available.
pub fn classify_scripted_run(
    events: &[ThreadEvent],
    process: ProcessDisposition,
    final_output: FinalOutputState,
) -> RunResolution {
    match process {
        ProcessDisposition::TimedOut => {
            return failed(
                FailureCode::AuditTimeout,
                "The audit exceeded its configured time limit.",
                true,
            );
        }
        ProcessDisposition::Cancelled => {
            return failed(FailureCode::Cancelled, "The audit was cancelled.", false);
        }
        ProcessDisposition::Crashed => {
            return failed(
                FailureCode::AgentCrash,
                "The isolated audit agent terminated unexpectedly.",
                true,
            );
        }
        ProcessDisposition::Exited { code } if code != 0 => {
            return failed(
                FailureCode::AgentCrash,
                "The isolated audit agent exited unsuccessfully.",
                true,
            );
        }
        ProcessDisposition::Exited { .. } => {}
    }

    let mut thread_started = false;
    let mut turn_started = false;
    let mut terminal = None;
    let mut saw_unrecoverable_stream_error = false;
    let mut structurally_invalid = false;

    for (index, event) in events.iter().enumerate() {
        if terminal.is_some() {
            structurally_invalid = true;
            break;
        }
        match event {
            ThreadEvent::ThreadStarted(_) => {
                if index != 0 || thread_started {
                    structurally_invalid = true;
                    break;
                }
                thread_started = true;
            }
            ThreadEvent::TurnStarted(_) => {
                if !thread_started || turn_started {
                    structurally_invalid = true;
                    break;
                }
                turn_started = true;
            }
            ThreadEvent::TurnCompleted(_) => {
                if !turn_started {
                    structurally_invalid = true;
                    break;
                }
                terminal = Some(if saw_unrecoverable_stream_error {
                    RawTerminal::StreamError
                } else {
                    RawTerminal::Completed
                });
            }
            ThreadEvent::TurnFailed(_) => {
                if !turn_started {
                    structurally_invalid = true;
                    break;
                }
                terminal = Some(RawTerminal::TurnFailed);
            }
            ThreadEvent::Error(error) => {
                if !turn_started {
                    structurally_invalid = true;
                    break;
                }
                if !error.will_retry {
                    // Exec can emit the causal non-retryable error immediately
                    // before its canonical turn.failed terminal. Keep it
                    // pending so that terminal can still close the lifecycle.
                    saw_unrecoverable_stream_error = true;
                }
            }
            ThreadEvent::ItemStarted(_)
            | ThreadEvent::ItemUpdated(_)
            | ThreadEvent::ItemCompleted(_) => {
                if !turn_started {
                    structurally_invalid = true;
                    break;
                }
            }
        }
    }

    if structurally_invalid || !thread_started {
        return invalid_output("The Codex event stream violated its pinned lifecycle.");
    }
    match terminal.or_else(|| saw_unrecoverable_stream_error.then_some(RawTerminal::StreamError)) {
        Some(RawTerminal::TurnFailed) => failed(
            FailureCode::ModelUnavailable,
            "The model turn failed before the audit completed.",
            true,
        ),
        Some(RawTerminal::StreamError) => failed(
            FailureCode::Infrastructure,
            "The Codex event stream ended with an unrecoverable error.",
            true,
        ),
        None => invalid_output("The Codex event stream ended without a terminal event."),
        Some(RawTerminal::Completed) => match final_output {
            FinalOutputState::Valid => RunResolution::Completed,
            FinalOutputState::Missing => {
                invalid_output("The model completed without a structured audit output.")
            }
            FinalOutputState::Invalid => {
                invalid_output("The model produced an invalid structured audit output.")
            }
        },
    }
}

fn invalid_output(message: &str) -> RunResolution {
    failed(FailureCode::InvalidOutput, message, false)
}

fn failed(code: FailureCode, message: &str, retryable: bool) -> RunResolution {
    RunResolution::Failed(Failure {
        code,
        message: message.to_owned(),
        retryable,
    })
}
