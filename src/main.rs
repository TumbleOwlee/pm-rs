use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::{path::Path, thread};
use users::get_current_username;

/// Macro to simplify .to_string()
macro_rules! str {
    ( $x:expr ) => {
        $x.to_string()
    };
}

/// Print colorized error message
pub fn error(msg: &str) {
    println!("[{}] {}: {}", "!".red(), "Error".red(), msg);
}

/// Print colorized info message
pub fn info(msg: &str) {
    println!("[{}] {}: {}", "i".blue(), "Info".blue(), msg);
}

/// Print colorized warning message
pub fn warn(msg: &str) {
    println!("[{}] {}: {}", "w".yellow(), "Warn".yellow(), msg);
}

/// Print colorized success message
pub fn success(msg: &str) {
    println!("[{}] {}: {}", "!".green(), "Success".green(), msg);
}

/// Parse a single key-value pair
/// ref. https://github.com/clap-rs/clap/blob/master/examples/typed-derive.rs
fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn StdError + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: StdError + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: StdError + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

/// Available subcommands
#[derive(Subcommand, Debug)]
enum SubCommand {
    /// Get the status of all processes.
    Status,
    /// Kill running processes.
    Kill { pids: Vec<u32> },
    /// Execute given command.
    Run {
        /// Working directory to use, defaults to current directory.
        #[arg(short, long)]
        working_directory: Option<String>,
        /// Environment variables
        #[arg(short, long, value_parser = parse_key_val::<String, String>)]
        environment: Vec<(String, String)>,
        /// Program to execute.
        program: String,
        /// Required parameters to run the program.
        args: Vec<String>,
    },
    /// Run the daemon service.
    Daemon,
}

/// Background process management utility.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    #[command(subcommand)]
    command: SubCommand,
}

/// Command information
#[derive(Deserialize, Serialize, Debug)]
struct Command {
    working_directory: String,
    program: String,
    args: Vec<String>,
    environment: Vec<(String, String)>,
}

/// Available request types
#[derive(Deserialize, Serialize, Debug)]
enum Request {
    Run(Command),
    Kill(Vec<u32>),
    Status,
}

/// Process information stored by daemon
#[derive(Debug)]
struct ProcessInfo {
    program: String,
    args: Vec<String>,
    handle: Child,
}

/// Process information for clients
#[derive(Serialize, Deserialize, Debug)]
struct Process {
    program: String,
    args: Vec<String>,
    pid: u32,
    active: bool,
}

/// Available response types
#[derive(Serialize, Deserialize, Debug)]
enum Response {
    Error(String),
    ProcessList(Vec<Process>),
    Success(Vec<u32>),
}

/// Daemon holding map of processes
struct Daemon {
    processes: HashMap<u32, ProcessInfo>,
}

impl Daemon {
    fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    /// Start a process with given command information
    fn start(&mut self, socket: &mut UnixStream, task: Command) -> Result<()> {
        info(&format!("Run task: {:?}", task));
        let mut command = ProcessCommand::new(task.program.clone());
        command.current_dir(task.working_directory);
        command.envs(task.environment);
        command.stdin(Stdio::piped());
        for arg in &task.args {
            command.arg(arg);
        }
        match command.spawn() {
            Ok(child) => {
                let pid = child.id();
                self.processes.insert(
                    pid,
                    ProcessInfo {
                        program: task.program,
                        args: task.args,
                        handle: child,
                    },
                );
                let resp = Response::Success(vec![pid]);
                let resp_json = serde_json::to_string(&resp)?;
                socket.write_all(resp_json.as_bytes())?;
            }
            Err(e) => {
                let resp = Response::Error(format!("Failed to spawn process: {:?}", e));
                let resp_json = serde_json::to_string(&resp)?;
                socket.write_all(resp_json.as_bytes())?;
            }
        }
        Ok(())
    }

    /// Stop processes with given PIDs
    fn stop(&mut self, socket: &mut UnixStream, pids: Vec<u32>) -> Result<()> {
        let errors: Vec<(u32, std::io::Error)> = pids
            .iter()
            .map(|pid| {
                if let Some(p) = self.processes.get_mut(pid) {
                    (*pid, p.handle.kill())
                } else {
                    (*pid, Ok(()))
                }
            })
            .filter_map(|(pid, r)| r.err().map(|e| (pid, e)))
            .collect();

        if errors.is_empty() {
            let resp = Response::Success(pids.clone());
            let resp_json = serde_json::to_string(&resp)?;
            socket.write_all(resp_json.as_bytes())?;
            info(&format!("Killed task: {:?}", pids));
        } else {
            let resp = Response::Error(str!(
                "Failed to kill processes. Check status for currently active processes."
            ));
            let resp_json = serde_json::to_string(&resp)?;
            socket.write_all(resp_json.as_bytes())?;
            error(&format!("Failed to stop tasks: {:?}", pids));
        }

        for pid in pids.iter() {
            if let Some(p) = self.processes.get_mut(pid) {
                match p.handle.kill() {
                    Ok(()) => {}
                    Err(e) => {
                        let resp = Response::Error(format!("Failed to kill process: {:?}", e));
                        let resp_json = serde_json::to_string(&resp)?;
                        socket.write_all(resp_json.as_bytes())?;
                        error(&format!("Failed to stop task: {:?}", pid));
                    }
                }
            }
        }
        Ok(())
    }

    /// Get current status of all managed processes
    fn status(&mut self, socket: &mut UnixStream) -> Result<()> {
        info("Show status of tasks.");
        let resp = Response::ProcessList(
            self.processes
                .iter_mut()
                .map(|(_, p)| Process {
                    program: p.program.clone(),
                    args: p.args.clone(),
                    pid: p.handle.id(),
                    active: p.handle.try_wait().is_ok_and(|v| v.is_none()),
                })
                .collect(),
        );
        let resp_json = serde_json::to_string(&resp)?;
        socket.write_all(resp_json.as_bytes())?;

        let mut pids: Vec<u32> = Vec::new();
        for (pid, p) in &mut self.processes {
            if p.handle.try_wait().is_ok_and(|v| !v.is_none()) {
                pids.push(*pid);
            }
        }

        for i in pids {
            self.processes.remove(&i);
        }

        Ok(())
    }

    /// Handle request from a client
    fn handle_request(&mut self, socket: &mut UnixStream) -> Result<()> {
        let mut buf = String::with_capacity(1024);
        socket.read_to_string(&mut buf)?;

        match serde_json::from_str(&buf)? {
            Request::Run(task) => self.start(socket, task),
            Request::Kill(pids) => self.stop(socket, pids),
            Request::Status => self.status(socket),
        }
    }

    /// Run daemon and handle requests until signal is received
    pub fn run(&mut self) -> Result<Option<String>> {
        let (sender, receiver) = crossbeam_channel::bounded(100);
        let mut signals = Signals::new(&[SIGINT])?;

        thread::spawn(move || {
            for sig in signals.forever() {
                warn(&format!("Received signal: {:?}", sig));
                if let Err(e) = sender.send(sig) {
                    error(&format!("Send signal failed: {:?}", e));
                    break;
                }
            }
        });

        let username = get_current_username().unwrap();
        let user = username.to_str().context("Failed to retrieve username.")?;

        if Path::new(&format!("/tmp/pm-{user}.sock", user = user)).exists() {
            return Err(anyhow!("Socket file already exists. If you're sure no daemon is active, delete the file /tmp/pm-{}.sock", user));
        }

        let sock = format!("/tmp/pm-{user}.sock", user = user);
        let bind_path = Path::new(&sock);
        let listener = UnixListener::bind(bind_path)?;
        listener.set_nonblocking(true)?;

        info("Waiting for new connection.");

        loop {
            match listener.accept() {
                Ok((mut socket, _addr)) => {
                    if let Err(e) = self.handle_request(&mut socket) {
                        warn(&format!("Handling request failed: {:?}", e));
                    }
                    info("Waiting for new connection.");
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    warn(&format!("Accepting incoming connection failed: {:?}", e));
                    info("Waiting for new connection.");
                }
            }

            if let Ok(sig) = receiver.try_recv() {
                println!("signal: {:?}", sig);
                if sig == SIGINT || sig == SIGTERM {
                    if bind_path.exists() {
                        std::fs::remove_file(bind_path)?;
                    }
                    return Ok(None);
                }
            }
        }
    }
}

/// Send the given command to the daemon and print response
fn execute(args: &CliArgs) -> Result<Option<String>> {
    let username = get_current_username().unwrap();
    let user = username.to_str().context("Failed to retrieve username.")?;

    let sock = format!("/tmp/pm-{user}.sock", user = user);
    let bind_path = Path::new(&sock);
    let mut stream = UnixStream::connect(bind_path)?;

    let req_json = match &args.command {
        SubCommand::Status => serde_json::to_string(&Request::Status)?,
        SubCommand::Run {
            working_directory,
            environment,
            program,
            args,
        } => {
            let dir = if let Some(ref d) = working_directory {
                d.clone()
            } else {
                str!(std::env::current_dir()?.display())
            };
            serde_json::to_string(&Request::Run(Command {
                working_directory: dir,
                program: str!(program),
                args: args.to_vec(),
                environment: environment.to_vec(),
            }))?
        }
        SubCommand::Kill { pids } => serde_json::to_string(&Request::Kill(pids.to_vec()))?,
        SubCommand::Daemon => {
            unreachable!("The daemon case should never be reached. Submit bug report.")
        }
    };
    stream.write_all(&req_json.as_bytes())?;
    stream.shutdown(Shutdown::Write)?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    match serde_json::from_str(&response)? {
        Response::Error(e) => Err(anyhow!(e)),
        Response::Success(pid) => Ok(Some(format!("Process handled with PID={:?}", pid))),
        Response::ProcessList(list) => {
            let mut length = 0;
            for p in &list {
                length = std::cmp::max((str!(p.program) + " " + &p.args.join(" ")).len(), length);
            }
            let pad = std::cmp::max(7, length) - 7;

            println!(
                "  {}{}{}",
                "┌───────────┬────────┬─────────".yellow(),
                "─".repeat(pad).yellow(),
                "┐".yellow()
            );
            println!(
                "  {}   {}   {}   {}   {} {} {}{}",
                "│".yellow(),
                "State".blue(),
                "│".yellow(),
                "ID".blue(),
                "│".yellow(),
                "Command".blue(),
                " ".repeat(pad),
                "│".yellow()
            );
            println!(
                "  {}{}{}",
                "├───────────┼────────┼─────────".yellow(),
                "─".repeat(pad).yellow(),
                "┤".yellow()
            );
            for p in list {
                let state = if p.active {
                    "   alive  ".green()
                } else {
                    " not alive".red()
                };
                let command = p.program + " " + &p.args.join(" ");
                let cmdlen = command.len();
                println!(
                    "  {}{} {} {:6} {} {} {}{}",
                    "│".yellow(),
                    state,
                    "│".yellow(),
                    p.pid,
                    "│".yellow(),
                    command + &" ".repeat(7 - std::cmp::min(length, 7)),
                    " ".repeat(length - cmdlen),
                    "│".yellow()
                );
            }
            println!(
                "  {}{}{}",
                "└───────────┴────────┴─────────".yellow(),
                "─".repeat(pad).yellow(),
                "┘".yellow()
            );
            Ok(None)
        }
    }
}

fn main() {
    let args = CliArgs::parse();

    // Run either in daemon (service) mode or execute command
    if let SubCommand::Daemon = args.command {
        let mut daemon = Daemon::new();
        match daemon.run() {
            Err(e) => error(&str!(e)),
            Ok(Some(msg)) => success(&msg),
            _ => {}
        }
    } else {
        match execute(&args) {
            Err(e) => error(&str!(e)),
            Ok(Some(msg)) => success(&msg),
            _ => {}
        }
    }
}
