use ansi_term::Style;
use log::*;

use crate::fs::fields as f;
use crate::output::cell::TextCell;
use crate::output::table::UserFormat;

impl f::User {
    pub fn render<C: Colours>(self, colours: &C, _format: UserFormat) -> TextCell {
        let (display_name, style) = {
            let result = self.0.lookup_account_sid();
            if let Ok((user_name, domain_name)) = result {
                ([domain_name, user_name].join("/"), colours.someone_else())
            } else {
                error!("Error looking up windows user name: {:?}", result);
                ("ERROR".to_owned(), ansi_term::Colour::Red.bold())
            }
        };

        TextCell::paint(style, display_name)
    }

}

pub trait Colours {
    fn you(&self) -> Style;
    fn someone_else(&self) -> Style;
}
