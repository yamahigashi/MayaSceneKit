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
        let paths = existing_absolute_paths(paths)?;
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

pub(in crate::gui) fn reveal_file_paths_in_system_file_manager(
    paths: &[PathBuf],
) -> Result<(), String> {
    if paths.is_empty() {
        return Err("no files to reveal".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        let paths = existing_absolute_paths(paths)?;
        let groups = paths_grouped_by_parent_dir(paths)?;
        for (folder, paths) in groups {
            reveal_file_group_in_explorer(&folder, &paths)?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = paths;
        Err("reveal file in Explorer is only supported on Windows".to_string())
    }
}

#[cfg(target_os = "windows")]
fn reveal_file_group_in_explorer(
    folder: &std::path::Path,
    paths: &[PathBuf],
) -> Result<(), String> {
    let folder_literal = powershell_string_literal(&folder.to_string_lossy());
    let path_literals = paths
        .iter()
        .map(|path| powershell_string_literal(&path.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        r#"
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class MayaSceneKitShellReveal {{
    [DllImport("ole32.dll")]
    public static extern int CoInitialize(IntPtr pvReserved);

    [DllImport("ole32.dll")]
    public static extern void CoUninitialize();

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr ILCreateFromPathW(string pszPath);

    [DllImport("shell32.dll")]
    public static extern int SHOpenFolderAndSelectItems(IntPtr pidlFolder, uint cidl, IntPtr[] apidl, uint dwFlags);

    [DllImport("shell32.dll")]
    public static extern void ILFree(IntPtr pidl);
}}
'@

$folder = {folder_literal}
$paths = @({path_literals})
$initialized = $false
$folderPidl = [IntPtr]::Zero
$itemPidls = @()
$hr = [MayaSceneKitShellReveal]::CoInitialize([IntPtr]::Zero)
if (($hr -ne 0) -and ($hr -ne 1)) {{
    throw ('CoInitialize returned 0x{{0:X8}}' -f ($hr -band 0xffffffff))
}}
$initialized = $true
try {{
    $folderPidl = [MayaSceneKitShellReveal]::ILCreateFromPathW($folder)
    if ($folderPidl -eq [IntPtr]::Zero) {{
        throw 'ILCreateFromPathW failed for folder'
    }}
    foreach ($path in $paths) {{
        $pidl = [MayaSceneKitShellReveal]::ILCreateFromPathW($path)
        if ($pidl -eq [IntPtr]::Zero) {{
            throw ('ILCreateFromPathW failed for ' + $path)
        }}
        $itemPidls += $pidl
    }}
    $hr = [MayaSceneKitShellReveal]::SHOpenFolderAndSelectItems($folderPidl, [uint32]$itemPidls.Count, [IntPtr[]]$itemPidls, 0)
    if ($hr -ne 0) {{
        throw ('SHOpenFolderAndSelectItems returned 0x{{0:X8}}' -f ($hr -band 0xffffffff))
    }}
}} finally {{
    foreach ($pidl in $itemPidls) {{
        if ($pidl -ne [IntPtr]::Zero) {{
            [MayaSceneKitShellReveal]::ILFree($pidl)
        }}
    }}
    if ($folderPidl -ne [IntPtr]::Zero) {{
        [MayaSceneKitShellReveal]::ILFree($folderPidl)
    }}
    if ($initialized) {{
        [MayaSceneKitShellReveal]::CoUninitialize()
    }}
}}
"#
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
        .map_err(|err| format!("failed to reveal file in Explorer: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if stderr.is_empty() {
            "failed to reveal file in Explorer".to_string()
        } else {
            format!("failed to reveal file in Explorer: {stderr}")
        })
    }
}

#[cfg(target_os = "windows")]
fn existing_absolute_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let paths = paths
        .iter()
        .filter(|path| path.exists())
        .map(|path| {
            path.canonicalize()
                .map(shell_compatible_path)
                .map_err(|err| format!("failed to resolve {}: {err}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if paths.is_empty() {
        Err("target files are not specified or not found".to_string())
    } else {
        Ok(paths)
    }
}

#[cfg(target_os = "windows")]
fn paths_grouped_by_parent_dir(
    paths: Vec<PathBuf>,
) -> Result<Vec<(PathBuf, Vec<PathBuf>)>, String> {
    let mut groups = Vec::<(PathBuf, Vec<PathBuf>)>::new();
    for path in paths {
        let parent = path
            .parent()
            .map(PathBuf::from)
            .ok_or_else(|| "failed to determine target folder".to_string())?;
        if !parent.is_dir() {
            return Err(format!("folder not found: {}", parent.display()));
        }
        match groups.iter_mut().find(|(folder, _)| folder == &parent) {
            Some((_, paths)) => paths.push(path),
            None => groups.push((parent, vec![path])),
        }
    }
    Ok(groups)
}

#[cfg(target_os = "windows")]
fn powershell_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(target_os = "windows")]
fn shell_compatible_path(path: PathBuf) -> PathBuf {
    use std::path::{Component, Prefix};

    let normalized = {
        let mut components = path.components();
        match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::VerbatimDisk(drive) => {
                    let mut normalized = PathBuf::from(format!("{}:", drive as char));
                    normalized.extend(components);
                    Some(normalized)
                }
                Prefix::VerbatimUNC(server, share) => {
                    let mut normalized = PathBuf::from(r"\\");
                    normalized.push(server);
                    normalized.push(share);
                    normalized.extend(components);
                    Some(normalized)
                }
                _ => None,
            },
            _ => None,
        }
    };
    normalized.unwrap_or(path)
}
