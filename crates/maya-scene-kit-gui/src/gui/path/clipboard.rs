#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub(in crate::gui) fn copy_file_drop_paths_to_system_clipboard(
    paths: &[PathBuf],
) -> Result<(), String> {
    if paths.is_empty() {
        return Err("no resolved files to copy".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        let path_literals = paths
            .iter()
            .map(|path| format!("'{}'", path.to_string_lossy().replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(", ");
        let script = format!(
            "Add-Type -AssemblyName System.Windows.Forms; \
             $paths = New-Object System.Collections.Specialized.StringCollection; \
             @({}) | ForEach-Object {{ [void]$paths.Add($_) }}; \
             [System.Windows.Forms.Clipboard]::SetFileDropList($paths)",
            path_literals
        );
        let output = std::process::Command::new("powershell.exe")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-STA",
                "-Command",
                script.as_str(),
            ])
            .output()
            .map_err(|err| format!("failed to copy file to clipboard: {err}"))?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(if stderr.is_empty() {
                "failed to copy file to clipboard".to_string()
            } else {
                format!("failed to copy file to clipboard: {stderr}")
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = paths;
        Err("copy file to clipboard is only supported on Windows".to_string())
    }
}
