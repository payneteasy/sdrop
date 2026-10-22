use clap::{CommandFactory, Parser, Subcommand};
use sdrop::commands::{self, PutArgs};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

/// One-time secrets: encrypted locally, the server sees only ciphertext.
#[derive(Parser)]
#[command(name = "sdrop", version)]
struct Cli {
    /// Without a command on a terminal: the interactive mode (`sdrop tui`).
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Interactive mode: create, open and track secrets in the terminal.
    Tui,
    /// Encrypt a secret from FILE or stdin; recipient link to stdout, owner link to stderr.
    Put {
        /// Delete after this time if nobody opens it: 1h, 24h or 7d.
        #[arg(long, default_value = "24h")]
        ttl: String,
        /// Ask for a passphrase (second channel) on the terminal.
        #[arg(long)]
        passphrase: bool,
        /// Read the passphrase from the first line of a file.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
        /// Send a file as is (any bytes); repeat for several files (up to 20). The recipient gets the names.
        #[arg(long, value_name = "PATH")]
        file: Vec<PathBuf>,
        /// Text secret from a file or "-" for stdin. Without --file: stdin if omitted.
        input: Option<PathBuf>,
    },
    /// Open a recipient link ("-" reads it from stdin) and print the secret.
    Get {
        url: String,
        /// Read the passphrase from the first line of a file.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
        /// Write the secret to PATH ("-" for stdout); text with files: a new directory PATH. Without it: text to stdout, files to a new ./sdrop-<id>/ directory.
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Show the status of a secret by the owner link.
    Status { url: String },
    /// Revoke an unread secret by the owner link.
    Revoke { url: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Some(cmd) = &cli.cmd else {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            return finish(sdrop::tui::run());
        }
        let _ = Cli::command().print_help();
        return ExitCode::from(2);
    };
    let result = match cmd {
        Cmd::Tui => sdrop::tui::run(),
        Cmd::Put {
            ttl,
            passphrase,
            passphrase_file,
            file,
            input,
        } => commands::put(PutArgs {
            ttl,
            passphrase: *passphrase,
            passphrase_file: passphrase_file.as_deref(),
            input: input.as_deref(),
            files: file,
        })
        .and_then(|(recipient, owner, expires)| {
            // The sender link is a required result, not diagnostics: losing it is an error.
            let owner_ok = writeln!(
                std::io::stderr(),
                "Owner link (status, revoke): {owner}\nOpens once; deleted if unread on: {expires}"
            )
            .is_ok();
            commands::write_stdout(&format!("{recipient}\n"))?;
            if owner_ok {
                Ok(())
            } else {
                Err(sdrop::api::CliError::Msg(
                    "could not write the owner link to stderr; the secret was created".into(),
                ))
            }
        }),
        Cmd::Get {
            url,
            passphrase_file,
            output,
        } => commands::link_arg(url)
            .and_then(|u| commands::get(&u, passphrase_file.as_deref(), output.as_deref())),
        Cmd::Status { url } => commands::link_arg(url)
            .and_then(|u| commands::status(&u))
            .and_then(|s| commands::write_stdout(&s)),
        Cmd::Revoke { url } => commands::link_arg(url)
            .and_then(|u| commands::revoke(&u))
            .and_then(|s| commands::write_stdout(&s)),
    };
    finish(result)
}

fn finish(result: Result<(), sdrop::api::CliError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sdrop: {e}");
            ExitCode::FAILURE
        }
    }
}
