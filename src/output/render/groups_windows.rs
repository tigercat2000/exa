use ansi_term::Style;
use log::*;

use crate::fs::fields as f;
use crate::output::cell::TextCell;
use crate::output::table::UserFormat;

impl f::Group {
    pub fn render<C: Colours>(self, colours: &C, _format: UserFormat) -> TextCell {
        // TODO: Respect UserFormat and Colours.yours()
        let (display_name, style) = {
            let result = self.0.lookup_account_sid(true);
            if let Ok((group_name, domain_name)) = result {
                ([domain_name, group_name].join("/"), colours.not_yours())
            } else {
                error!("Error looking up windows group name: {:?}", result);
                ("ERROR".to_owned(), ansi_term::Colour::Red.bold())
            }
        };

        TextCell::paint(style, display_name)
    }
}

pub trait Colours {
    fn yours(&self) -> Style;
    fn not_yours(&self) -> Style;
}