pub fn escape_ma_string(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\\n")
}
