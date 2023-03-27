use clap::{command, Arg, ArgAction, Command};
use color_eyre::eyre::{bail, Context, Result};
use log::LevelFilter;
use rustyline::error::ReadlineError;
use std::str::FromStr;
use yari_sys::{ContextBuilder, Module};

/// Spawn interactive shell
fn interactive(context: &mut yari_sys::Context) -> Result<()> {
    let mut rl = rustyline::DefaultEditor::new().context("cannot create an editor")?;

    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str())?;

                match context.eval(&line) {
                    Ok(res_obj) => {
                        println!("{:?}", res_obj);
                    }
                    Err(e) => {
                        println!("{:?}", e);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ignore and clear input
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                bail!("Error: {:?}", err);
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    // Setup logging
    env_logger::Builder::from_default_env()
        .filter_module("rustyline", LevelFilter::Warn)
        .init();

    color_eyre::install()?;

    // Declare command line arguments
    let matches = command!()
        .arg(
            Arg::new("MODULE_DATA")
                .short('x')
                .long("module-data")
                .value_name("MODULE=FILE")
                .action(ArgAction::Append)
                .help("pass FILE's content as extra data to MODULE"),
        )
        .arg(
            Arg::new("INPUT")
                .value_name("FILE")
                .help("FILE to scan")
                .required(false),
        )
        .arg(
            Arg::new("LICENSES")
                .long("licenses")
                .help("print license information")
                .required(false),
        )
        .arg(
            Arg::new("RULE_FILE")
                .value_name("RULE")
                .help("FILE containing rule with strings and variables")
                .required(false),
        )
        .subcommand(
            Command::new("dump")
                .about("Dump a module structure")
                .arg(Arg::new("MODULE").help("module name").required(true)),
        )
        .get_matches();

    if matches.contains_id("LICENSES") {
        println!("{}", yari_sys::LICENSES);
        return Ok(());
    }

    // Prepare the context
    let input_file = matches.get_one::<String>("INPUT");
    let rule_file = matches.get_one::<String>("RULE_FILE");
    let mut builder = ContextBuilder::default()
        .with_sample(input_file)
        .with_rule_file(rule_file);

    // Add the module data
    if let Some(modules_data) = matches.get_many::<String>("MODULE_DATA") {
        for module_data in modules_data {
            let (module, data) = ContextBuilder::parse_module_data_str(module_data).unwrap();
            builder = builder.with_module_data(module, &data);
        }
    }

    let mut context = builder.build().context("Failed to create YARI context")?;

    match matches.subcommand() {
        Some(("dump", sub_matches)) => {
            let module = Module::from_str(sub_matches.get_one::<String>("MODULE").unwrap())?;
            context.dump_module(module);
        }
        _ => {
            // Start interactive shell
            interactive(&mut context)?;
        }
    }

    Ok(())
}
