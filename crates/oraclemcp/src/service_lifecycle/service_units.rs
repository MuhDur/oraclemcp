use super::{
    SERVICE_LIMIT_NOFILE, SERVICE_MEMORY_MAX_SYSTEMD, SERVICE_OOM_SCORE_ADJUST, SERVICE_TASKS_MAX,
};

pub(super) fn systemd_unit(exe: &str, serve_args: &[String]) -> String {
    let exec = std::iter::once(systemd_quote(exe))
        .chain(serve_args.iter().map(|arg| systemd_quote(arg)))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "[Unit]\n\
         Description=oraclemcp always-on MCP service\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=notify\n\
         NotifyAccess=main\n\
         ExecStart={exec}\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         LimitNOFILE={SERVICE_LIMIT_NOFILE}\n\
         TasksMax={SERVICE_TASKS_MAX}\n\
         MemoryMax={SERVICE_MEMORY_MAX_SYSTEMD}\n\
         OOMScoreAdjust={SERVICE_OOM_SCORE_ADJUST}\n\
         Environment=ORACLEMCP_SERVICE=1\n\n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

pub(super) fn launchd_plist(label: &str, exe: &str, serve_args: &[String]) -> String {
    let args = std::iter::once(exe.to_owned())
        .chain(serve_args.iter().cloned())
        .map(|arg| format!("        <string>{}</string>", xml_escape(&arg)))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
             <key>Label</key>\n\
             <string>{}</string>\n\
             <key>ProgramArguments</key>\n\
             <array>\n{}\n\
             </array>\n\
             <key>RunAtLoad</key>\n\
             <true/>\n\
             <key>KeepAlive</key>\n\
             <true/>\n\
             <key>SoftResourceLimits</key>\n\
             <dict>\n\
                 <key>NumberOfFiles</key>\n\
                 <integer>{}</integer>\n\
                 <key>NumberOfProcesses</key>\n\
                 <integer>{}</integer>\n\
             </dict>\n\
         </dict>\n\
         </plist>\n",
        xml_escape(label),
        args,
        SERVICE_LIMIT_NOFILE,
        SERVICE_TASKS_MAX
    )
}

pub(super) fn windows_bin_path(exe: &str, serve_args: &[String]) -> String {
    std::iter::once(windows_quote(exe))
        .chain(serve_args.iter().map(|arg| windows_quote(arg)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn systemd_quote(input: &str) -> String {
    if input
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b':' | b'-'))
    {
        input.to_owned()
    } else {
        format!("\"{}\"", input.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn windows_quote(input: &str) -> String {
    format!("\"{}\"", input.replace('"', "\\\""))
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
