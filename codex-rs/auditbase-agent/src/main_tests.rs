use super::*;
use pretty_assertions::assert_eq;

#[test]
fn top_cli_forwards_root_config_overrides_and_prompt() {
    const PROMPT: &str = "inspect the repository";
    let cli = TopCli::parse_from([
        "auditbase-agent",
        "--config",
        "reasoning_level=xhigh",
        PROMPT,
    ]);
    let mut inner = cli.inner;
    inner
        .config_overrides
        .prepend_root_overrides(cli.config_overrides);

    assert_eq!(inner.prompt.as_deref(), Some(PROMPT));
    assert_eq!(
        inner.config_overrides.raw_overrides,
        ["reasoning_level=xhigh"]
    );
}
