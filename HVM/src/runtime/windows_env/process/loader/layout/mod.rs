use crate::models::ModuleRecord;

use super::*;

mod schema;
mod strings;

pub(in crate::runtime::windows_env::process::loader) use strings::encode_loader_string;
