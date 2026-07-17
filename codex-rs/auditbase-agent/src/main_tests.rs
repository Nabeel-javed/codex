use super::*;
use pretty_assertions::assert_eq;

#[test]
fn top_cli_forwards_root_config_overrides_and_prompt() {
    const PROMPT: &str = "inspect the repository";
    let cli = TopCli::parse_from([
        "auditbase-agent",
        "--config",
        "model_reasoning_effort=high",
        PROMPT,
    ]);
    let mut inner = cli.inner;
    inner
        .config_overrides
        .prepend_root_overrides(cli.config_overrides);

    assert_eq!(inner.prompt.as_deref(), Some(PROMPT));
    assert_eq!(
        inner.config_overrides.raw_overrides,
        ["model_reasoning_effort=high"]
    );
}
