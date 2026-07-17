use std::collections::BTreeMap;

use codex_exec::ThreadStartedEvent;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;

use crate::RunnerError;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum ProvenanceSchemaVersion {
    #[serde(rename = "auditbase.private-run-provenance.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthClass {
    ApiKey,
    ChatGptSubscription,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    ControlledPublic,
    BenchmarkModelOnly,
    DenyAll,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestedRuntime {
    pub provider_id: String,
    pub model: String,
    pub reasoning_effort: String,
    pub service_tier: Option<String>,
    pub auth_class: AuthClass,
}

/// Values Codex says it configured for the thread. These are necessary drift
/// evidence, but are not proof of what the remote model gateway served.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodexConfiguredRuntime {
    pub provider_id: String,
    pub model: String,
    pub reasoning_effort: String,
    pub service_tier: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectiveRuntime {
    pub provider_id: String,
    pub model: String,
    /// Immutable snapshot attested by the model gateway.
    pub model_snapshot: String,
    pub reasoning_effort: String,
    pub service_tier: Option<String>,
    pub auth_class: AuthClass,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunBudget {
    pub wall_clock_ms: u64,
    pub max_jsonl_bytes: u64,
    pub max_jsonl_line_bytes: u64,
    pub max_jsonl_events: u64,
    pub max_final_output_bytes: u64,
}

/// Private audit record. It must never be sent through the public event or
/// result APIs and deliberately cannot hold credentials.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateRunProvenance {
    pub schema_version: ProvenanceSchemaVersion,
    pub audit_id: String,
    pub requested: RequestedRuntime,
    pub codex_configured: CodexConfiguredRuntime,
    /// Server-reported values carried by a trusted gateway attestation.
    pub effective: EffectiveRuntime,
    pub codex_git_sha: String,
    pub codex_binary_sha256: String,
    pub runtime_image_digest: String,
    pub input_manifest_sha256: String,
    pub config_sha256: String,
    pub prompt_sha256: String,
    pub skill_bundle_sha256: String,
    pub output_schema_sha256: String,
    pub toolchain: BTreeMap<String, String>,
    pub toolchain_sha256: String,
    pub budget: RunBudget,
    pub network_policy: NetworkPolicy,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvenanceEnvelope {
    pub record: PrivateRunProvenance,
    pub fingerprint_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum RunArtifactBindingSchemaVersion {
    #[serde(rename = "auditbase.private-run-artifact-binding.v1")]
    V1,
}

/// Immutable private join between the exact input, run, result and optional
/// evaluation artifact. Store this beside, never inside, the public result.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateRunArtifactBinding {
    pub schema_version: RunArtifactBindingSchemaVersion,
    pub audit_id: String,
    pub provenance_fingerprint_sha256: String,
    pub input_manifest_sha256: String,
    pub result_sha256: String,
    pub evaluation_artifact_sha256: Option<String>,
}

impl PrivateRunProvenance {
    pub fn validate(&self) -> Result<(), RunnerError> {
        require_token(&self.audit_id, "auditId")?;
        require_nonempty(&self.requested.provider_id, "requested.providerId")?;
        require_nonempty(&self.requested.model, "requested.model")?;
        require_nonempty(
            &self.requested.reasoning_effort,
            "requested.reasoningEffort",
        )?;
        require_optional_nonempty(
            self.requested.service_tier.as_deref(),
            "requested.serviceTier",
        )?;
        require_nonempty(
            &self.codex_configured.provider_id,
            "codexConfigured.providerId",
        )?;
        require_nonempty(&self.codex_configured.model, "codexConfigured.model")?;
        require_nonempty(
            &self.codex_configured.reasoning_effort,
            "codexConfigured.reasoningEffort",
        )?;
        require_optional_nonempty(
            self.codex_configured.service_tier.as_deref(),
            "codexConfigured.serviceTier",
        )?;
        require_nonempty(&self.effective.provider_id, "effective.providerId")?;
        require_nonempty(&self.effective.model, "effective.model")?;
        require_nonempty(&self.effective.model_snapshot, "effective.modelSnapshot")?;
        require_nonempty(
            &self.effective.reasoning_effort,
            "effective.reasoningEffort",
        )?;
        require_optional_nonempty(
            self.effective.service_tier.as_deref(),
            "effective.serviceTier",
        )?;

        compare(
            "requested/codexConfigured.providerId",
            &self.requested.provider_id,
            &self.codex_configured.provider_id,
        )?;
        compare(
            "requested/codexConfigured.model",
            &self.requested.model,
            &self.codex_configured.model,
        )?;
        compare(
            "requested/codexConfigured.reasoningEffort",
            &self.requested.reasoning_effort,
            &self.codex_configured.reasoning_effort,
        )?;
        compare_optional(
            "requested/codexConfigured.serviceTier",
            self.requested.service_tier.as_deref(),
            self.codex_configured.service_tier.as_deref(),
        )?;
        compare(
            "codexConfigured/effective.providerId",
            &self.codex_configured.provider_id,
            &self.effective.provider_id,
        )?;
        compare(
            "codexConfigured/effective.model",
            &self.codex_configured.model,
            &self.effective.model,
        )?;
        compare(
            "codexConfigured/effective.reasoningEffort",
            &self.codex_configured.reasoning_effort,
            &self.effective.reasoning_effort,
        )?;
        compare_optional(
            "codexConfigured/effective.serviceTier",
            self.codex_configured.service_tier.as_deref(),
            self.effective.service_tier.as_deref(),
        )?;
        if self.requested.auth_class != self.effective.auth_class {
            return Err(RunnerError::RuntimeMismatch {
                field: "authClass".to_owned(),
                requested: serde_json::to_string(&self.requested.auth_class)
                    .unwrap_or_else(|_| "unknown".to_owned()),
                effective: serde_json::to_string(&self.effective.auth_class)
                    .unwrap_or_else(|_| "unknown".to_owned()),
            });
        }

        require_git_sha(&self.codex_git_sha, "codexGitSha")?;
        require_sha256(&self.codex_binary_sha256, "codexBinarySha256")?;
        require_image_digest(&self.runtime_image_digest, "runtimeImageDigest")?;
        require_sha256(&self.input_manifest_sha256, "inputManifestSha256")?;
        require_sha256(&self.config_sha256, "configSha256")?;
        require_sha256(&self.prompt_sha256, "promptSha256")?;
        require_sha256(&self.skill_bundle_sha256, "skillBundleSha256")?;
        require_sha256(&self.output_schema_sha256, "outputSchemaSha256")?;
        require_sha256(&self.toolchain_sha256, "toolchainSha256")?;

        if self.toolchain.is_empty() {
            return Err(RunnerError::provenance(
                "toolchain",
                "must contain at least one pinned tool",
            ));
        }
        for (name, version) in &self.toolchain {
            require_token(name, "toolchain.name")?;
            require_nonempty(version, &format!("toolchain.{name}"))?;
        }
        let actual_toolchain_hash = canonical_sha256(&self.toolchain)?;
        if self.toolchain_sha256 != actual_toolchain_hash {
            return Err(RunnerError::provenance(
                "toolchainSha256",
                "does not match the canonical toolchain map",
            ));
        }

        if self.budget.wall_clock_ms == 0
            || self.budget.max_jsonl_bytes == 0
            || self.budget.max_jsonl_line_bytes == 0
            || self.budget.max_jsonl_events == 0
            || self.budget.max_final_output_bytes == 0
        {
            return Err(RunnerError::provenance(
                "budget",
                "every budget must be greater than zero",
            ));
        }
        if self.budget.max_jsonl_line_bytes > self.budget.max_jsonl_bytes {
            return Err(RunnerError::provenance(
                "budget.maxJsonlLineBytes",
                "must not exceed maxJsonlBytes",
            ));
        }
        Ok(())
    }

    pub fn fingerprint_sha256(&self) -> Result<String, RunnerError> {
        self.validate()?;
        canonical_sha256(self)
    }

    pub fn into_envelope(self) -> Result<ProvenanceEnvelope, RunnerError> {
        let fingerprint_sha256 = self.fingerprint_sha256()?;
        Ok(ProvenanceEnvelope {
            record: self,
            fingerprint_sha256,
        })
    }
}

impl ProvenanceEnvelope {
    pub fn validate(&self) -> Result<(), RunnerError> {
        let actual = self.record.fingerprint_sha256()?;
        require_sha256(&self.fingerprint_sha256, "fingerprintSha256")?;
        if self.fingerprint_sha256 != actual {
            return Err(RunnerError::provenance(
                "fingerprintSha256",
                "does not match the canonical provenance record",
            ));
        }
        Ok(())
    }
}

impl PrivateRunArtifactBinding {
    pub fn from_result(
        provenance: &ProvenanceEnvelope,
        result: &impl Serialize,
        evaluation_artifact_sha256: Option<String>,
    ) -> Result<Self, RunnerError> {
        provenance.validate()?;
        let binding = Self {
            schema_version: RunArtifactBindingSchemaVersion::V1,
            audit_id: provenance.record.audit_id.clone(),
            provenance_fingerprint_sha256: provenance.fingerprint_sha256.clone(),
            input_manifest_sha256: provenance.record.input_manifest_sha256.clone(),
            result_sha256: canonical_sha256(result)?,
            evaluation_artifact_sha256,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), RunnerError> {
        require_token(&self.audit_id, "auditId")?;
        require_sha256(
            &self.provenance_fingerprint_sha256,
            "provenanceFingerprintSha256",
        )?;
        require_sha256(&self.input_manifest_sha256, "inputManifestSha256")?;
        require_sha256(&self.result_sha256, "resultSha256")?;
        if let Some(digest) = &self.evaluation_artifact_sha256 {
            require_sha256(digest, "evaluationArtifactSha256")?;
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        provenance: &ProvenanceEnvelope,
        result: &impl Serialize,
        evaluation_artifact_sha256: Option<&str>,
    ) -> Result<(), RunnerError> {
        self.validate()?;
        provenance.validate()?;
        if self.audit_id != provenance.record.audit_id {
            return Err(RunnerError::provenance(
                "binding.auditId",
                "does not match the provenance audit ID",
            ));
        }
        if self.provenance_fingerprint_sha256 != provenance.fingerprint_sha256 {
            return Err(RunnerError::provenance(
                "binding.provenanceFingerprintSha256",
                "does not match the supplied provenance envelope",
            ));
        }
        if self.input_manifest_sha256 != provenance.record.input_manifest_sha256 {
            return Err(RunnerError::provenance(
                "binding.inputManifestSha256",
                "does not match the provenance input manifest",
            ));
        }
        let actual_result = canonical_sha256(result)?;
        if self.result_sha256 != actual_result {
            return Err(RunnerError::provenance(
                "binding.resultSha256",
                "does not match the supplied result",
            ));
        }
        if self.evaluation_artifact_sha256.as_deref() != evaluation_artifact_sha256 {
            return Err(RunnerError::provenance(
                "binding.evaluationArtifactSha256",
                "does not match the supplied evaluation artifact",
            ));
        }
        Ok(())
    }
}

pub fn parse_provenance_envelope(bytes: &[u8]) -> Result<ProvenanceEnvelope, RunnerError> {
    let envelope: ProvenanceEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| RunnerError::provenance("json", error.to_string()))?;
    envelope.validate()?;
    Ok(envelope)
}

/// Builds the Codex-configured (not server-effective) provenance layer.
/// Legacy `thread.started` records deserialize, but fail here if any G0B field
/// is absent. Server-effective values must be supplied separately from a
/// trusted gateway attestation.
pub fn configured_runtime_from_thread_started(
    started: &ThreadStartedEvent,
) -> Result<CodexConfiguredRuntime, RunnerError> {
    Ok(CodexConfiguredRuntime {
        provider_id: required_option(
            started.model_provider_id.as_deref(),
            "thread.started.modelProviderId",
        )?,
        model: required_option(started.model.as_deref(), "thread.started.model")?,
        reasoning_effort: required_option(
            started.reasoning_effort.as_deref(),
            "thread.started.reasoningEffort",
        )?,
        service_tier: started.service_tier.clone(),
    })
}

pub fn canonical_sha256(value: &impl Serialize) -> Result<String, RunnerError> {
    let value = serde_json::to_value(value)
        .map_err(|error| RunnerError::provenance("canonicalJson", error.to_string()))?;
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| RunnerError::provenance("canonicalJson", error.to_string()))?;
    let digest = Sha256::digest(bytes);
    Ok(lower_hex(&digest))
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let sorted: BTreeMap<_, _> = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        other => other,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn required_option(value: Option<&str>, field: &str) -> Result<String, RunnerError> {
    let value = value.ok_or_else(|| RunnerError::provenance(field, "is required for G0B"))?;
    require_owned_nonempty(value.to_owned(), field)
}

fn require_owned_nonempty(value: String, field: &str) -> Result<String, RunnerError> {
    require_nonempty(&value, field)?;
    Ok(value)
}

fn require_nonempty(value: &str, field: &str) -> Result<(), RunnerError> {
    if value.trim().is_empty() {
        return Err(RunnerError::provenance(field, "must not be empty"));
    }
    Ok(())
}

fn require_optional_nonempty(value: Option<&str>, field: &str) -> Result<(), RunnerError> {
    if let Some(value) = value {
        require_nonempty(value, field)?;
    }
    Ok(())
}

fn require_token(value: &str, field: &str) -> Result<(), RunnerError> {
    require_nonempty(value, field)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(RunnerError::provenance(
            field,
            "must contain only ASCII letters, numbers, '.', '_' or '-'",
        ));
    }
    Ok(())
}

fn require_sha256(value: &str, field: &str) -> Result<(), RunnerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(RunnerError::provenance(
            field,
            "must be a lowercase 64-character SHA-256 digest",
        ));
    }
    Ok(())
}

fn require_git_sha(value: &str, field: &str) -> Result<(), RunnerError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(RunnerError::provenance(
            field,
            "must be a lowercase 40- or 64-character Git object ID",
        ));
    }
    Ok(())
}

fn require_image_digest(value: &str, field: &str) -> Result<(), RunnerError> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(RunnerError::provenance(
            field,
            "must use the sha256:<digest> form",
        ));
    };
    require_sha256(digest, field)
}

fn compare(field: &str, requested: &str, effective: &str) -> Result<(), RunnerError> {
    if requested != effective {
        return Err(RunnerError::RuntimeMismatch {
            field: field.to_owned(),
            requested: requested.to_owned(),
            effective: effective.to_owned(),
        });
    }
    Ok(())
}

fn compare_optional(
    field: &str,
    requested: Option<&str>,
    effective: Option<&str>,
) -> Result<(), RunnerError> {
    if requested != effective {
        return Err(RunnerError::RuntimeMismatch {
            field: field.to_owned(),
            requested: requested.unwrap_or("<none>").to_owned(),
            effective: effective.unwrap_or("<none>").to_owned(),
        });
    }
    Ok(())
}
