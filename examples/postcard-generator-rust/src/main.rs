use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::thread;

fn main() {
    let title = read_trimmed("input/title.txt");
    let message = read_trimmed("input/message.txt");
    let palette = read_palette("input/palette.txt");
    let template = fs::read_to_string("templates/postcard.html.tpl")
        .expect("failed to read templates/postcard.html.tpl");
    let generated_at = run_command("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]);
    let server_reply = request_stamp_approval(&title, &message);

    fs::create_dir_all("dist").expect("failed to create dist");

    let svg = render_svg(&title, &message, &palette, &server_reply, &generated_at);
    fs::write("dist/postcard.svg", svg).expect("failed to write dist/postcard.svg");

    let summary_json = render_summary_json(&title, &message, &generated_at, &server_reply);
    fs::write("dist/summary.json", &summary_json).expect("failed to write dist/summary.json");

    let html = render_html(
        &template,
        &title,
        &message,
        &generated_at,
        &server_reply,
        &summary_json,
        &palette,
    );
    fs::write("dist/postcard.html", html).expect("failed to write dist/postcard.html");

    println!("generated dist/postcard.html");
    println!("generated dist/postcard.svg");
    println!("generated dist/summary.json");
}

fn read_trimmed(path: &str) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
        .trim()
        .to_string()
}

fn read_palette(path: &str) -> BTreeMap<String, String> {
    let content =
        fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
    let mut palette = BTreeMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (key, value) = trimmed
            .split_once('=')
            .unwrap_or_else(|| panic!("invalid palette line: {trimmed}"));
        palette.insert(key.trim().to_string(), value.trim().to_string());
    }
    palette
}

fn palette_value<'a>(palette: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    palette
        .get(key)
        .map(String::as_str)
        .unwrap_or_else(|| panic!("missing palette key: {key}"))
}

fn run_command(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run {program}: {err}"));
    if !output.status.success() {
        panic!("{program} exited with {}", output.status);
    }
    String::from_utf8(output.stdout)
        .unwrap_or_else(|err| panic!("failed to decode {program} output: {err}"))
        .trim()
        .to_string()
}

fn request_stamp_approval(title: &str, message: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind local listener");
    let addr = listener
        .local_addr()
        .expect("failed to resolve local listener address");
    let title = title.to_string();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("failed to accept client");
        let mut request = [0u8; 512];
        let size = stream.read(&mut request).expect("failed to read request");
        let payload = String::from_utf8_lossy(&request[..size]).trim().to_string();
        let response = format!("Stamp office approved {title} after reading {payload}");
        stream
            .write_all(response.as_bytes())
            .expect("failed to write response");
    });

    let mut client = TcpStream::connect(addr).expect("failed to connect to local listener");
    let preview = format!("{} chars", message.chars().count());
    client
        .write_all(preview.as_bytes())
        .expect("failed to send postcard preview");

    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .expect("failed to read stamp reply");
    server.join().expect("server thread panicked");
    response.trim().to_string()
}

fn render_svg(
    title: &str,
    message: &str,
    palette: &BTreeMap<String, String>,
    server_reply: &str,
    generated_at: &str,
) -> String {
    let paper = palette_value(palette, "paper");
    let ink = palette_value(palette, "ink");
    let accent = palette_value(palette, "accent");
    let stamp = palette_value(palette, "stamp");
    let shadow = palette_value(palette, "shadow");
    let short_reply = truncate(server_reply, 48);
    let short_message = truncate(message, 96);

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 600" role="img" aria-labelledby="title desc">
  <title id="title">{}</title>
  <desc id="desc">{}</desc>
  <defs>
    <linearGradient id="sky" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="{}" />
      <stop offset="100%" stop-color="#ffffff" />
    </linearGradient>
    <filter id="paper-shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="18" stdDeviation="20" flood-color="{}" flood-opacity="0.35"/>
    </filter>
  </defs>
  <rect width="960" height="600" fill="url(#sky)"/>
  <rect x="70" y="70" width="820" height="460" rx="28" fill="{}" filter="url(#paper-shadow)"/>
  <rect x="92" y="92" width="776" height="416" rx="22" fill="none" stroke="{}" stroke-width="4" stroke-dasharray="18 10"/>
  <line x1="610" y1="120" x2="610" y2="480" stroke="{}" stroke-width="2" stroke-dasharray="10 12"/>
  <circle cx="736" cy="180" r="68" fill="none" stroke="{}" stroke-width="10"/>
  <circle cx="736" cy="180" r="46" fill="none" stroke="{}" stroke-width="3" stroke-dasharray="4 9"/>
  <text x="150" y="170" fill="{}" font-family="Georgia, serif" font-size="52" font-weight="700">{}</text>
  <text x="150" y="220" fill="{}" font-family="Georgia, serif" font-size="24">{}</text>
  <text x="150" y="286" fill="{}" font-family="Georgia, serif" font-size="28">{}</text>
  <text x="150" y="330" fill="{}" font-family="Georgia, serif" font-size="28">{}</text>
  <text x="150" y="374" fill="{}" font-family="Georgia, serif" font-size="28">{}</text>
  <text x="150" y="462" fill="{}" font-family="'Courier New', monospace" font-size="18">Stamped {}</text>
  <text x="662" y="172" fill="{}" font-family="'Courier New', monospace" font-size="22" letter-spacing="4">APPROVED</text>
  <text x="660" y="205" fill="{}" font-family="'Courier New', monospace" font-size="14">{}</text>
  <text x="650" y="296" fill="{}" font-family="'Courier New', monospace" font-size="22">TO:</text>
  <text x="650" y="334" fill="{}" font-family="Georgia, serif" font-size="28">Visual Debugger</text>
  <text x="650" y="372" fill="{}" font-family="Georgia, serif" font-size="22">127 Trace Street</text>
  <text x="650" y="406" fill="{}" font-family="Georgia, serif" font-size="22">Docker City, LN</text>
</svg>
"##,
        xml_escape(title),
        xml_escape(message),
        paper,
        shadow,
        paper,
        accent,
        shadow,
        stamp,
        accent,
        ink,
        xml_escape(title),
        ink,
        xml_escape(&short_reply),
        ink,
        xml_escape(&first_line(short_message.as_str(), 0)),
        ink,
        xml_escape(&first_line(short_message.as_str(), 1)),
        ink,
        xml_escape(&first_line(short_message.as_str(), 2)),
        accent,
        xml_escape(generated_at),
        stamp,
        ink,
        xml_escape("LOCAL STAMP"),
        accent,
        ink,
        ink,
        ink
    )
}

fn render_html(
    template: &str,
    title: &str,
    message: &str,
    generated_at: &str,
    server_reply: &str,
    summary_json: &str,
    palette: &BTreeMap<String, String>,
) -> String {
    let replacements = [
        ("{{title}}", html_escape(title)),
        ("{{message}}", html_escape(message)),
        ("{{generated_at}}", html_escape(generated_at)),
        ("{{server_reply}}", html_escape(server_reply)),
        ("{{summary_json}}", html_escape(summary_json)),
        ("{{paper}}", palette_value(palette, "paper").to_string()),
        ("{{ink}}", palette_value(palette, "ink").to_string()),
        ("{{accent}}", palette_value(palette, "accent").to_string()),
        ("{{stamp}}", palette_value(palette, "stamp").to_string()),
        ("{{shadow}}", palette_value(palette, "shadow").to_string()),
    ];

    let mut output = template.to_string();
    for (needle, value) in replacements {
        output = output.replace(needle, &value);
    }
    output
}

fn render_summary_json(
    title: &str,
    message: &str,
    generated_at: &str,
    server_reply: &str,
) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"title\": \"{}\",\n",
            "  \"message\": \"{}\",\n",
            "  \"generated_at\": \"{}\",\n",
            "  \"server_reply\": \"{}\"\n",
            "}}\n"
        ),
        json_escape(title),
        json_escape(message),
        json_escape(generated_at),
        json_escape(server_reply)
    )
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut truncated = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        truncated.push_str("...");
    }
    truncated
}

fn first_line(message: &str, line_index: usize) -> String {
    let words: Vec<&str> = message.split_whitespace().collect();
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in words {
        if current.len() + word.len() + 1 > 30 && !current.is_empty() {
            lines.push(current.trim().to_string());
            current.clear();
        }
        current.push_str(word);
        current.push(' ');
    }
    if !current.is_empty() {
        lines.push(current.trim().to_string());
    }
    lines.get(line_index).cloned().unwrap_or_default()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn xml_escape(value: &str) -> String {
    html_escape(value).replace('\'', "&apos;")
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
