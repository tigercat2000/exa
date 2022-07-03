use ansi_term::Style;
use windows::Win32::Foundation::{GetLastError};
use windows::Win32::Security::{LookupAccountSidW, SidTypeUnknown};
use windows::core::{PCWSTR, PWSTR};
use std::io;
use log::*;

use crate::fs::fields as f;
use crate::output::cell::TextCell;
use crate::output::table::UserFormat;

impl f::User {
    pub fn render<C: Colours>(self, colours: &C, _format: UserFormat) -> TextCell {
        let (display_name, style) = {
            let result = self.lookup_account_sid();
            if let Ok((user_name, domain_name)) = result {
                ([domain_name, user_name].join("/"), colours.someone_else())
            } else {
                error!("Error looking up windows user name: {:?}", result);
                ("ERROR".to_owned(), ansi_term::Colour::Red.bold())
            }
        };

        TextCell::paint(style, display_name)
    }

    /// Look up the character count of the username and domain name
    /// so that we can construct buffers of adequate size.
    /// 
    /// Returns `(username_character_count, domain_name_character_count)`
    fn lookup_account_sid_buffer(&self) -> Result<(u32, u32), io::Error> {
        let mut name_character_count = 0;
        let mut domain_name_character_count = 0;
        let return_value = unsafe {
            LookupAccountSidW(
                PCWSTR(std::ptr::null()), // Local computer
                self.0.owner, // The SID we want to look up
                PWSTR(std::ptr::null_mut()), // No buffer constructed yet
                &mut name_character_count, // The number of characters we need to store in our username buffer
                PWSTR(std::ptr::null_mut()), // No buffer constructed yet
                &mut domain_name_character_count, // The number of characters we need to store in our domain buffer
                std::ptr::null_mut() // Unused
            )
        };

        if return_value == true {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "LookupAccountSidW suceeded with null buffers when it should have failed"));
        }

        if (name_character_count == 0) || (domain_name_character_count == 0) {
            return Err(io::Error::new(io::ErrorKind::NotFound, "SID was incorrect, causing domain/name count to return 0"));
        }

        Ok((name_character_count, domain_name_character_count))
    }

    /// Returns the (username, domain name) of the SID we give it.
    fn lookup_account_sid(&self) -> Result<(String, String), io::Error> {
        // Get the buffer sizes.
        let (mut name_character_count, mut domain_name_character_count) = self.lookup_account_sid_buffer()?;

        // Make the buffers.
        let mut name_buffer = Vec::with_capacity(name_character_count as usize);
        let mut domain_name_buffer = Vec::with_capacity(domain_name_character_count as usize);

        let mut e_use = SidTypeUnknown;
        let return_value = unsafe {
            LookupAccountSidW(
                PCWSTR(std::ptr::null()),
                self.0.owner,
                PWSTR(name_buffer.as_mut_ptr()),
                &mut name_character_count,
                PWSTR(domain_name_buffer.as_mut_ptr()),
                &mut domain_name_character_count,
                &mut e_use,
            )
        };

        if return_value != true {
            let error = unsafe { GetLastError() };
            // TODO: FormatMessage
            return Err(io::Error::new(io::ErrorKind::InvalidInput, error.0.to_string()));
        }

        // Set the buffer lengths to the bytes written by LookupAccountSidW
        unsafe {
            name_buffer.set_len(name_character_count as usize);
            domain_name_buffer.set_len(domain_name_character_count as usize);
        }

        Ok((
            String::from_utf16_lossy(&name_buffer),
            String::from_utf16_lossy(&domain_name_buffer),
        ))
    }
}

pub trait Colours {
    fn you(&self) -> Style;
    fn someone_else(&self) -> Style;
}
