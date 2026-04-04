use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Serialize;
use serde_json::{json, Value};

const DEFAULT_LM_STUDIO_ENDPOINT: &str = "http://127.0.0.1:1234";
const DEFAULT_LM_STUDIO_MODEL: &str = "qwen/qwen3.5-9b";
const DEFAULT_ANALYSIS_TEMPERATURE: f32 = 0.2;
const DEFAULT_ANALYSIS_MAX_TOKENS: u32 = 900;
const DEFAULT_EVENT_SAMPLE_COUNT: usize = 12;
const DEFAULT_RUN_JSON_CHARS: usize = 1200;
const DEFAULT_FEATURES_JSON_CHARS: usize = 1800;
const DEFAULT_PROCESSES_JSON_CHARS: usize = 2400;
const DEFAULT_AGGREGATES_JSON_CHARS: usize = 1200;
const DEFAULT_EVENT_SAMPLE_CHARS: usize = 1800;
const DEFAULT_EXTRA_INSTRUCTIONS_CHARS: usize = 1000;
const DEFAULT_USER_PROMPT_CHARS: usize = 9000;
const DEFAULT_PROMPT_INSTRUCTIONS: &str = "Analyze this ebpf-tracker dataset as a test-learning artifact. Focus on what likely happened in the app, how much of the trace is tooling noise, any anomalies or regressions, and the next concrete follow-up steps. Reply in markdown with these sections: Summary, App Signal, Tooling Noise, Anomalies, Next Steps.";
const TRUNCATED_SUFFIX: &str = "\n... truncated ...";
const ANALYSIS_LOG_PREFIX: &str = "[dataset-analyze]";
const LM_STUDIO_LOG_PREFIX: &str = "[lm-studio]";
const LM_STUDIO_LOG_ROOT_ENV: &str = "LM_STUDIO_LOG_ROOT";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelProvider {
    LmStudio,
    OpenAiCompatible,
}

impl ModelProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            ModelProvider::LmStudio => "lm-studio",
            ModelProvider::OpenAiCompatible => "openai-compatible",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "lm-studio" => Ok(Self::LmStudio),
            "openai-compatible" | "openai" => Ok(Self::OpenAiCompatible),
            _ => Err(format!("unsupported model provider: {raw}")),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AnalyzeConfig {
    pub run_dir: PathBuf,
    pub provider: ModelProvider,
    pub endpoint: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub temperature: f32,
    pub max_tokens: Option<u32>,
    pub instructions_path: Option<PathBuf>,
    pub live_logs: bool,
}

impl Default for AnalyzeConfig {
    fn default() -> Self {
        Self {
            run_dir: PathBuf::new(),
            provider: ModelProvider::LmStudio,
            endpoint: None,
            model: None,
            api_key: None,
            temperature: DEFAULT_ANALYSIS_TEMPERATURE,
            max_tokens: Some(DEFAULT_ANALYSIS_MAX_TOKENS),
            instructions_path: None,
            live_logs: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalyzeSummary {
    pub provider: ModelProvider,
    pub model: String,
    pub output_markdown: PathBuf,
    pub output_json: PathBuf,
}

struct ModelRequest {
    system_prompt: String,
    user_prompt: String,
    temperature: f32,
    max_tokens: Option<u32>,
}

struct ModelResponse {
    model: String,
    text: String,
    raw_json: Value,
}

trait AnalysisModel {
    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, String>;
}

struct LmStudioAdapter {
    endpoint: String,
    model: String,
    api_key: Option<String>,
    client: Client,
}

struct OpenAiCompatibleAdapter {
    provider: ModelProvider,
    endpoint: String,
    model: String,
    api_key: Option<String>,
    client: Client,
}

#[derive(Serialize)]
struct AnalysisRecord {
    provider: ModelProvider,
    endpoint: String,
    model: String,
    created_unix_ms: u64,
    prompt: PromptRecord,
    response_text: String,
    raw_response: Value,
}

#[derive(Serialize)]
struct PromptRecord {
    system: String,
    user: String,
    temperature: f32,
    max_tokens: Option<u32>,
}

struct LmStudioLogTail {
    stop_tx: mpsc::Sender<()>,
    handle: thread::JoinHandle<()>,
}

pub fn analyze_run(config: &AnalyzeConfig) -> Result<AnalyzeSummary, String> {
    if !config.run_dir.is_dir() {
        return Err(format!(
            "dataset run directory not found: {}",
            config.run_dir.display()
        ));
    }

    let analysis_dir = config.run_dir.join("analysis");
    fs::create_dir_all(&analysis_dir).map_err(|err| {
        format!(
            "failed to create analysis dir {}: {err}",
            analysis_dir.display()
        )
    })?;

    let requested_model = resolve_model(config)?;
    let stem = format!(
        "{}--{}",
        config.provider.as_str(),
        sanitize_name(&requested_model)
    );
    let live_log_writer = if config.live_logs {
        Some(open_live_log_file(
            &analysis_dir.join(format!("{stem}.live.log")),
        )?)
    } else {
        None
    };

    let endpoint = resolve_endpoint(config)?;
    emit_live_log(
        live_log_writer.as_ref(),
        ANALYSIS_LOG_PREFIX,
        &format!(
            "phase=prepare provider={} model={} endpoint={} run={}",
            config.provider.as_str(),
            requested_model,
            endpoint,
            config.run_dir.display()
        ),
    );

    let adapter = build_adapter(config)?;
    let request = build_model_request(config)?;
    emit_live_log(
        live_log_writer.as_ref(),
        ANALYSIS_LOG_PREFIX,
        &format!(
            "phase=request_ready prompt_chars={} max_tokens={:?}",
            request.user_prompt.chars().count(),
            request.max_tokens
        ),
    );

    let lm_studio_tail = if config.live_logs && config.provider == ModelProvider::LmStudio {
        start_lm_studio_log_tail(live_log_writer.clone())
    } else {
        Ok(None)
    }?;

    emit_live_log(
        live_log_writer.as_ref(),
        ANALYSIS_LOG_PREFIX,
        "phase=calling_model",
    );
    let response = adapter.complete(&request);
    if let Some(tail) = lm_studio_tail {
        tail.stop();
    }
    let response = response.map_err(|err| {
        emit_live_log(
            live_log_writer.as_ref(),
            ANALYSIS_LOG_PREFIX,
            &format!("phase=failed error={err}"),
        );
        err
    })?;
    emit_live_log(
        live_log_writer.as_ref(),
        ANALYSIS_LOG_PREFIX,
        &format!("phase=response_received response_model={}", response.model),
    );

    let output_markdown = analysis_dir.join(format!("{stem}.md"));
    let output_json = analysis_dir.join(format!("{stem}.json"));

    fs::write(&output_markdown, &response.text).map_err(|err| {
        format!(
            "failed to write analysis markdown {}: {err}",
            output_markdown.display()
        )
    })?;

    let record = AnalysisRecord {
        provider: config.provider,
        endpoint,
        model: response.model.clone(),
        created_unix_ms: current_timestamp_millis(),
        prompt: PromptRecord {
            system: request.system_prompt,
            user: request.user_prompt,
            temperature: request.temperature,
            max_tokens: request.max_tokens,
        },
        response_text: response.text,
        raw_response: response.raw_json,
    };
    write_json_pretty(&output_json, &record)?;
    emit_live_log(
        live_log_writer.as_ref(),
        ANALYSIS_LOG_PREFIX,
        &format!(
            "phase=completed markdown={} json={}",
            output_markdown.display(),
            output_json.display()
        ),
    );

    Ok(AnalyzeSummary {
        provider: config.provider,
        model: response.model,
        output_markdown,
        output_json,
    })
}

fn build_adapter(config: &AnalyzeConfig) -> Result<Box<dyn AnalysisModel>, String> {
    let endpoint = resolve_endpoint(config)?;
    let model = resolve_model(config)?;

    let client = Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|err| format!("failed to build model client: {err}"))?;

    match config.provider {
        ModelProvider::LmStudio => Ok(Box::new(LmStudioAdapter {
            endpoint,
            model,
            api_key: config.api_key.clone(),
            client,
        })),
        ModelProvider::OpenAiCompatible => Ok(Box::new(OpenAiCompatibleAdapter {
            provider: config.provider,
            endpoint,
            model,
            api_key: config.api_key.clone(),
            client,
        })),
    }
}

fn build_model_request(config: &AnalyzeConfig) -> Result<ModelRequest, String> {
    let run_json = trim_for_prompt(
        &read_required(config.run_dir.join("run.json"))?,
        DEFAULT_RUN_JSON_CHARS,
    );
    let features_json = trim_for_prompt(
        &read_required(config.run_dir.join("features.json"))?,
        DEFAULT_FEATURES_JSON_CHARS,
    );
    let processes_json = trim_for_prompt(
        &read_required(config.run_dir.join("processes.json"))?,
        DEFAULT_PROCESSES_JSON_CHARS,
    );
    let aggregates_json = trim_for_prompt(
        &read_required(config.run_dir.join("aggregates.json"))?,
        DEFAULT_AGGREGATES_JSON_CHARS,
    );
    let event_samples = trim_for_prompt(
        &sample_event_lines(
            &config.run_dir.join("events.jsonl"),
            DEFAULT_EVENT_SAMPLE_COUNT,
            DEFAULT_EVENT_SAMPLE_COUNT,
        )?,
        DEFAULT_EVENT_SAMPLE_CHARS,
    );
    let extra_instructions = match &config.instructions_path {
        Some(path) => {
            let text = fs::read_to_string(path).map_err(|err| {
                format!("failed to read instructions file {}: {err}", path.display())
            })?;
            format!(
                "\nAdditional instructions:\n{}\n",
                trim_for_prompt(text.trim(), DEFAULT_EXTRA_INSTRUCTIONS_CHARS)
            )
        }
        None => String::new(),
    };

    let user_prompt = trim_for_prompt(
        &format!(
        "Dataset run directory: {}\n\nRun metadata:\n```json\n{}\n```\n\nDerived features:\n```json\n{}\n```\n\nProcesses:\n```json\n{}\n```\n\nAggregates:\n```json\n{}\n```\n\nEvent samples:\n```jsonl\n{}\n```\n{}",
        config.run_dir.display(),
        run_json.trim(),
        features_json.trim(),
        processes_json.trim(),
        aggregates_json.trim(),
        event_samples.trim(),
        extra_instructions.trim(),
    ),
        DEFAULT_USER_PROMPT_CHARS,
    );

    Ok(ModelRequest {
        system_prompt: DEFAULT_PROMPT_INSTRUCTIONS.to_string(),
        user_prompt,
        temperature: config.temperature,
        max_tokens: config.max_tokens,
    })
}

fn resolve_endpoint(config: &AnalyzeConfig) -> Result<String, String> {
    match config.provider {
        ModelProvider::LmStudio => Ok(normalize_lm_studio_endpoint(
            config
                .endpoint
                .as_deref()
                .unwrap_or(DEFAULT_LM_STUDIO_ENDPOINT),
        )),
        ModelProvider::OpenAiCompatible => config
            .endpoint
            .clone()
            .ok_or_else(|| "openai-compatible provider requires --endpoint".to_string()),
    }
}

fn resolve_model(config: &AnalyzeConfig) -> Result<String, String> {
    match config.provider {
        ModelProvider::LmStudio => Ok(config
            .model
            .clone()
            .unwrap_or_else(|| DEFAULT_LM_STUDIO_MODEL.to_string())),
        ModelProvider::OpenAiCompatible => config
            .model
            .clone()
            .ok_or_else(|| "openai-compatible provider requires --model".to_string()),
    }
}

fn read_required(path: PathBuf) -> Result<String, String> {
    fs::read_to_string(&path)
        .map_err(|err| format!("failed to read dataset file {}: {err}", path.display()))
}

fn open_live_log_file(path: &Path) -> Result<Arc<Mutex<File>>, String> {
    let file = File::create(path).map_err(|err| {
        format!(
            "failed to create analysis live log {}: {err}",
            path.display()
        )
    })?;
    Ok(Arc::new(Mutex::new(file)))
}

fn emit_live_log(writer: Option<&Arc<Mutex<File>>>, prefix: &str, message: &str) {
    let Some(writer) = writer else {
        return;
    };

    let line = format!("[{}] {} {}", current_timestamp_millis(), prefix, message);
    eprintln!("{line}");

    if let Ok(mut file) = writer.lock() {
        let _ = writeln!(file, "{line}");
        let _ = file.flush();
    }
}

fn start_lm_studio_log_tail(
    writer: Option<Arc<Mutex<File>>>,
) -> Result<Option<LmStudioLogTail>, String> {
    let Some(log_path) = latest_lm_studio_log_path()? else {
        emit_live_log(
            writer.as_ref(),
            ANALYSIS_LOG_PREFIX,
            "phase=live_logs_skipped reason=no_lm_studio_log_file",
        );
        return Ok(None);
    };

    emit_live_log(
        writer.as_ref(),
        ANALYSIS_LOG_PREFIX,
        &format!("phase=tailing_lm_studio_log path={}", log_path.display()),
    );

    let (stop_tx, stop_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let Ok(file) = OpenOptions::new().read(true).open(&log_path) else {
            emit_live_log(
                writer.as_ref(),
                ANALYSIS_LOG_PREFIX,
                &format!(
                    "phase=live_logs_skipped reason=failed_to_open path={}",
                    log_path.display()
                ),
            );
            return;
        };

        let mut reader = BufReader::new(file);
        if reader.seek(SeekFrom::End(0)).is_err() {
            emit_live_log(
                writer.as_ref(),
                ANALYSIS_LOG_PREFIX,
                &format!(
                    "phase=live_logs_skipped reason=failed_to_seek path={}",
                    log_path.display()
                ),
            );
            return;
        }

        loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }

            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => thread::sleep(std::time::Duration::from_millis(200)),
                Ok(_) => {
                    let line = line.trim_end_matches(['\r', '\n']);
                    if !line.is_empty() {
                        emit_live_log(writer.as_ref(), LM_STUDIO_LOG_PREFIX, line);
                    }
                }
                Err(err) => {
                    emit_live_log(
                        writer.as_ref(),
                        ANALYSIS_LOG_PREFIX,
                        &format!(
                            "phase=live_logs_failed path={} error={err}",
                            log_path.display()
                        ),
                    );
                    break;
                }
            }
        }
    });

    Ok(Some(LmStudioLogTail { stop_tx, handle }))
}

impl LmStudioLogTail {
    fn stop(self) {
        let _ = self.stop_tx.send(());
        let _ = self.handle.join();
    }
}

fn latest_lm_studio_log_path() -> Result<Option<PathBuf>, String> {
    let root = lm_studio_log_root();
    latest_log_path_in(&root)
}

fn lm_studio_log_root() -> PathBuf {
    if let Some(path) = env::var_os(LM_STUDIO_LOG_ROOT_ENV) {
        return PathBuf::from(path);
    }

    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home).join(".lmstudio").join("server-logs");
    }

    PathBuf::from(".lmstudio").join("server-logs")
}

fn latest_log_path_in(root: &Path) -> Result<Option<PathBuf>, String> {
    if !root.is_dir() {
        return Ok(None);
    }

    let mut latest = None;
    for month_dir in fs::read_dir(root)
        .map_err(|err| format!("failed to read LM Studio log dir {}: {err}", root.display()))?
    {
        let month_dir = month_dir
            .map_err(|err| format!("failed to read LM Studio log dir {}: {err}", root.display()))?;
        let month_path = month_dir.path();
        if !month_path.is_dir() {
            continue;
        }

        for entry in fs::read_dir(&month_path).map_err(|err| {
            format!(
                "failed to read LM Studio month log dir {}: {err}",
                month_path.display()
            )
        })? {
            let entry = entry.map_err(|err| {
                format!(
                    "failed to read LM Studio month log dir {}: {err}",
                    month_path.display()
                )
            })?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("log") {
                continue;
            }

            match &latest {
                Some(current) if path <= *current => {}
                _ => latest = Some(path),
            }
        }
    }

    Ok(latest)
}

fn trim_for_prompt(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }

    let trimmed: String = text.chars().take(max_chars).collect();
    format!("{trimmed}{TRUNCATED_SUFFIX}")
}

fn sample_event_lines(path: &Path, head: usize, tail: usize) -> Result<String, String> {
    let file = File::open(path)
        .map_err(|err| format!("failed to open dataset events {}: {err}", path.display()))?;
    let lines: Vec<String> = BufReader::new(file)
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("failed to read dataset events {}: {err}", path.display()))?;

    if lines.is_empty() {
        return Ok(String::new());
    }

    let mut samples = Vec::new();
    let head_end = head.min(lines.len());
    samples.extend(lines.iter().take(head_end).cloned());

    let tail_start = lines.len().saturating_sub(tail);
    for (index, line) in lines.iter().enumerate().skip(tail_start) {
        if index >= head_end {
            samples.push(line.clone());
        }
    }

    Ok(samples.join("\n"))
}

fn sanitize_name(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            sanitized.push(ch);
        } else {
            sanitized.push('-');
        }
    }

    while sanitized.contains("--") {
        sanitized = sanitized.replace("--", "-");
    }

    sanitized.trim_matches('-').to_string()
}

fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn chat_completions_url(endpoint: &str) -> String {
    let trimmed = endpoint.trim_end_matches('/');
    if trimmed.ends_with("/chat/completions") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/chat/completions")
    }
}

fn normalize_lm_studio_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim_end_matches('/');
    let suffixes = [
        "/api/v1/chat",
        "/api/v1",
        "/v1/chat/completions",
        "/v1",
        "/chat/completions",
    ];

    for suffix in suffixes {
        if let Some(base) = trimmed.strip_suffix(suffix) {
            return base.trim_end_matches('/').to_string();
        }
    }

    trimmed.to_string()
}

fn lm_studio_chat_url(endpoint: &str) -> String {
    format!("{}/api/v1/chat", normalize_lm_studio_endpoint(endpoint))
}

fn extract_chat_content(response: &Value) -> Result<String, String> {
    let Some(choice) = response
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
    else {
        return Err("model response did not include choices[0]".to_string());
    };

    let Some(content) = choice
        .get("message")
        .and_then(|message| message.get("content"))
    else {
        return Err("model response did not include message.content".to_string());
    };

    if let Some(text) = content.as_str() {
        if !text.trim().is_empty() {
            return Ok(text.to_string());
        }
    }

    if let Some(parts) = content.as_array() {
        let mut text = String::new();
        for part in parts {
            if let Some(fragment) = part.get("text").and_then(Value::as_str) {
                text.push_str(fragment);
            }
        }
        if !text.is_empty() {
            return Ok(text);
        }
    }

    if let Some(reasoning) = choice
        .get("message")
        .and_then(|message| message.get("reasoning_content"))
        .and_then(Value::as_str)
    {
        if !reasoning.trim().is_empty() {
            return Err(
                "model response did not include a final answer in message.content; only reasoning_content was returned".to_string(),
            );
        }
    }

    Err("model response content was not a supported text format".to_string())
}

fn extract_lm_studio_content(response: &Value) -> Result<String, String> {
    let Some(output) = response.get("output").and_then(Value::as_array) else {
        return Err("LM Studio response did not include output[]".to_string());
    };

    let mut messages = Vec::new();
    let mut saw_reasoning = false;
    for item in output {
        match item.get("type").and_then(Value::as_str) {
            Some("message") => {
                if let Some(content) = item.get("content").and_then(Value::as_str) {
                    if !content.trim().is_empty() {
                        messages.push(content.to_string());
                    }
                }
            }
            Some("reasoning") => {
                saw_reasoning = saw_reasoning
                    || item
                        .get("content")
                        .and_then(Value::as_str)
                        .is_some_and(|content| !content.trim().is_empty());
            }
            _ => {}
        }
    }

    if !messages.is_empty() {
        return Ok(messages.join("\n\n"));
    }

    if saw_reasoning {
        return Err(
            "LM Studio response did not include a final message; only reasoning output was returned".to_string(),
        );
    }

    Err("LM Studio response output did not include a supported message".to_string())
}

fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let file = File::create(path)
        .map_err(|err| format!("failed to create analysis file {}: {err}", path.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value).map_err(|err| {
        format!(
            "failed to serialize analysis file {}: {err}",
            path.display()
        )
    })?;
    writer
        .write_all(b"\n")
        .map_err(|err| format!("failed to finalize analysis file {}: {err}", path.display()))?;
    writer
        .flush()
        .map_err(|err| format!("failed to flush analysis file {}: {err}", path.display()))?;
    Ok(())
}

fn build_lm_studio_request_body(model: &str, request: &ModelRequest) -> Value {
    let mut body = json!({
        "model": model,
        "system_prompt": request.system_prompt,
        "input": request.user_prompt,
        "temperature": request.temperature,
        "reasoning": "off",
        "store": false,
    });
    if let Some(max_tokens) = request.max_tokens {
        body["max_output_tokens"] = json!(max_tokens);
    }
    body
}

fn build_headers(api_key: Option<&str>) -> Result<HeaderMap, String> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    if let Some(api_key) = api_key {
        let bearer = format!("Bearer {}", api_key.trim());
        let header_value = HeaderValue::from_str(&bearer)
            .map_err(|err| format!("invalid API key header: {err}"))?;
        headers.insert(AUTHORIZATION, header_value);
    }

    Ok(headers)
}

impl AnalysisModel for LmStudioAdapter {
    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, String> {
        let headers = build_headers(self.api_key.as_deref())?;
        let body = build_lm_studio_request_body(&self.model, request);

        let response = self
            .client
            .post(lm_studio_chat_url(&self.endpoint))
            .headers(headers)
            .json(&body)
            .send()
            .map_err(|err| {
                format!(
                    "failed to call lm-studio model endpoint {}: {err}",
                    self.endpoint
                )
            })?;

        let status = response.status();
        let raw_json: Value = response.json().map_err(|err| {
            format!(
                "model endpoint {} returned unreadable JSON: {err}",
                self.endpoint
            )
        })?;

        if !status.is_success() {
            return Err(format!(
                "model endpoint {} returned {}: {}",
                self.endpoint, status, raw_json
            ));
        }

        let text = extract_lm_studio_content(&raw_json)?;
        let model = raw_json
            .get("model_instance_id")
            .and_then(Value::as_str)
            .unwrap_or(&self.model)
            .to_string();

        Ok(ModelResponse {
            model,
            text,
            raw_json,
        })
    }
}

impl AnalysisModel for OpenAiCompatibleAdapter {
    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, String> {
        let headers = build_headers(self.api_key.as_deref())?;

        let mut body = json!({
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": request.system_prompt,
                },
                {
                    "role": "user",
                    "content": request.user_prompt,
                }
            ],
            "temperature": request.temperature,
        });
        if let Some(max_tokens) = request.max_tokens {
            body["max_tokens"] = json!(max_tokens);
        }

        let response = self
            .client
            .post(chat_completions_url(&self.endpoint))
            .headers(headers)
            .json(&body)
            .send()
            .map_err(|err| {
                format!(
                    "failed to call {} model endpoint {}: {err}",
                    self.provider.as_str(),
                    self.endpoint
                )
            })?;

        let status = response.status();
        let raw_json: Value = response.json().map_err(|err| {
            format!(
                "model endpoint {} returned unreadable JSON: {err}",
                self.endpoint
            )
        })?;

        if !status.is_success() {
            return Err(format!(
                "model endpoint {} returned {}: {}",
                self.endpoint, status, raw_json
            ));
        }

        let text = extract_chat_content(&raw_json)?;
        Ok(ModelResponse {
            model: self.model.clone(),
            text,
            raw_json,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_lm_studio_request_body, build_model_request, chat_completions_url,
        extract_chat_content, extract_lm_studio_content, latest_log_path_in, lm_studio_chat_url,
        resolve_endpoint, resolve_model, sample_event_lines, sanitize_name, AnalyzeConfig,
        ModelProvider, ModelRequest, DEFAULT_USER_PROMPT_CHARS, TRUNCATED_SUFFIX,
    };
    use serde_json::json;
    use std::env;
    use std::fs;

    #[test]
    fn lm_studio_defaults_are_resolved() {
        let config = AnalyzeConfig::default();
        assert_eq!(
            resolve_endpoint(&config).expect("lm studio endpoint should default"),
            "http://127.0.0.1:1234"
        );
        assert_eq!(
            resolve_model(&config).expect("lm studio model should default"),
            "qwen/qwen3.5-9b"
        );
    }

    #[test]
    fn lm_studio_endpoint_normalizes_openai_compatible_urls() {
        let config = AnalyzeConfig {
            endpoint: Some("http://127.0.0.1:1234/v1/chat/completions".to_string()),
            ..AnalyzeConfig::default()
        };
        assert_eq!(
            resolve_endpoint(&config).expect("lm studio endpoint should normalize"),
            "http://127.0.0.1:1234"
        );
    }

    #[test]
    fn openai_compatible_requires_explicit_endpoint_and_model() {
        let config = AnalyzeConfig {
            provider: ModelProvider::OpenAiCompatible,
            ..AnalyzeConfig::default()
        };
        assert!(resolve_endpoint(&config).is_err());
        assert!(resolve_model(&config).is_err());
    }

    #[test]
    fn chat_completion_url_appends_path_once() {
        assert_eq!(
            chat_completions_url("http://127.0.0.1:1234/v1"),
            "http://127.0.0.1:1234/v1/chat/completions"
        );
        assert_eq!(
            chat_completions_url("http://127.0.0.1:1234/v1/chat/completions"),
            "http://127.0.0.1:1234/v1/chat/completions"
        );
    }

    #[test]
    fn lm_studio_chat_url_normalizes_native_endpoint() {
        assert_eq!(
            lm_studio_chat_url("http://127.0.0.1:1234/v1"),
            "http://127.0.0.1:1234/api/v1/chat"
        );
        assert_eq!(
            lm_studio_chat_url("http://127.0.0.1:1234/api/v1"),
            "http://127.0.0.1:1234/api/v1/chat"
        );
    }

    #[test]
    fn sanitize_name_keeps_model_file_friendly() {
        assert_eq!(sanitize_name("qwen/qwen3.5-9b"), "qwen-qwen3.5-9b");
    }

    #[test]
    fn extract_chat_content_reads_string_message() {
        let payload = json!({
            "choices": [
                {
                    "message": {
                        "content": "analysis text"
                    }
                }
            ]
        });
        assert_eq!(
            extract_chat_content(&payload).expect("content should be extracted"),
            "analysis text"
        );
    }

    #[test]
    fn extract_chat_content_rejects_reasoning_only_message() {
        let payload = json!({
            "choices": [
                {
                    "message": {
                        "content": "",
                        "reasoning_content": "thoughts"
                    }
                }
            ]
        });

        let error =
            extract_chat_content(&payload).expect_err("reasoning-only responses should fail");
        assert!(error.contains("reasoning_content"));
    }

    #[test]
    fn extract_lm_studio_content_reads_message_output() {
        let payload = json!({
            "output": [
                {
                    "type": "reasoning",
                    "content": "draft"
                },
                {
                    "type": "message",
                    "content": "analysis text"
                }
            ]
        });
        assert_eq!(
            extract_lm_studio_content(&payload).expect("content should be extracted"),
            "analysis text"
        );
    }

    #[test]
    fn extract_lm_studio_content_rejects_reasoning_only_output() {
        let payload = json!({
            "output": [
                {
                    "type": "reasoning",
                    "content": "draft"
                }
            ]
        });

        let error =
            extract_lm_studio_content(&payload).expect_err("reasoning-only output should fail");
        assert!(error.contains("only reasoning"));
    }

    #[test]
    fn lm_studio_request_body_uses_native_chat_fields_and_disables_reasoning() {
        let body = build_lm_studio_request_body(
            "qwen/qwen3.5-9b",
            &ModelRequest {
                system_prompt: "system".to_string(),
                user_prompt: "user".to_string(),
                temperature: 0.2,
                max_tokens: Some(900),
            },
        );

        assert_eq!(body["model"], "qwen/qwen3.5-9b");
        assert_eq!(body["system_prompt"], "system");
        assert_eq!(body["input"], "user");
        assert_eq!(body["reasoning"], "off");
        assert_eq!(body["store"], false);
        assert_eq!(body["max_output_tokens"], 900);
    }

    #[test]
    fn sample_event_lines_keeps_head_and_tail_without_duplication() {
        let path = env::temp_dir().join(format!(
            "ebpf-tracker-analysis-sample-{}.jsonl",
            super::current_timestamp_millis()
        ));
        fs::write(&path, "a\nb\nc\nd\ne\n").expect("sample file should be written");

        let sample = sample_event_lines(&path, 2, 2).expect("samples should be collected");

        assert_eq!(sample, "a\nb\nd\ne");
        fs::remove_file(path).expect("sample file should be removed");
    }

    #[test]
    fn sample_event_lines_keeps_all_lines_when_small() {
        let path = env::temp_dir().join(format!(
            "ebpf-tracker-analysis-sample-small-{}.jsonl",
            super::current_timestamp_millis()
        ));
        fs::write(&path, "a\nb\n").expect("sample file should be written");

        let sample = sample_event_lines(&path, 4, 4).expect("samples should be collected");

        assert_eq!(sample, "a\nb");
        fs::remove_file(path).expect("sample file should be removed");
    }

    #[test]
    fn build_model_request_trims_large_inputs_to_prompt_budget() {
        let dir = env::temp_dir().join(format!(
            "ebpf-tracker-analysis-request-{}",
            super::current_timestamp_millis()
        ));
        fs::create_dir_all(&dir).expect("temp analysis dir should be created");

        let large_json = format!("{{\"blob\":\"{}\"}}\n", "x".repeat(20_000));
        let event_line = format!(
            "{{\"type\":\"syscall\",\"timestamp_unix_ms\":1,\"kind\":\"write\",\"comm\":\"demo\",\"pid\":7,\"bytes\":9,\"file\":\"{}\"}}\n",
            "y".repeat(800)
        );
        let events = event_line.repeat(40);

        fs::write(dir.join("run.json"), &large_json).expect("run metadata should be written");
        fs::write(dir.join("features.json"), &large_json).expect("features should be written");
        fs::write(dir.join("processes.json"), &large_json).expect("processes should be written");
        fs::write(dir.join("aggregates.json"), &large_json).expect("aggregates should be written");
        fs::write(dir.join("events.jsonl"), events).expect("events should be written");

        let request = build_model_request(&AnalyzeConfig {
            run_dir: dir.clone(),
            ..AnalyzeConfig::default()
        })
        .expect("prompt should be built");

        assert!(request.user_prompt.contains(TRUNCATED_SUFFIX));
        assert!(
            request.user_prompt.chars().count()
                <= DEFAULT_USER_PROMPT_CHARS + TRUNCATED_SUFFIX.chars().count()
        );

        fs::remove_dir_all(dir).expect("temp analysis dir should be removed");
    }

    #[test]
    fn latest_log_path_prefers_newest_lm_studio_log_file() {
        let root = env::temp_dir().join(format!(
            "ebpf-tracker-lm-studio-logs-{}",
            super::current_timestamp_millis()
        ));
        let month = root.join("2026-03");
        fs::create_dir_all(&month).expect("log month dir should be created");
        fs::write(month.join("2026-03-24.1.log"), "old\n").expect("old log should be written");
        fs::write(month.join("2026-03-25.1.log"), "new\n").expect("new log should be written");

        let latest = latest_log_path_in(&root)
            .expect("latest log path should resolve")
            .expect("latest log should exist");

        assert_eq!(
            latest.file_name().and_then(|value| value.to_str()),
            Some("2026-03-25.1.log")
        );
        fs::remove_dir_all(root).expect("temp log dir should be removed");
    }
}
