//! Wrapper types for the values returned from `File`s.
//!
//! The methods of `File` that return information about the entry on the
//! filesystem -- size, modification date, block count, or Git status -- used
//! to just return these as formatted strings, but this became inflexible once
//! customisable output styles landed.
//!
//! Instead, they will return a wrapper type from this module, which tags the
//! type with what field it is while containing the actual raw value.
//!
//! The `output::details` module, among others, uses these types to render and
//! display the information as formatted strings.

// C-style `blkcnt_t` types don’t follow Rust’s rules!
#![allow(non_camel_case_types)]
#![allow(clippy::struct_excessive_bools)]

use self::windows::NamedSecurityInfo;


/// The type of a file’s block count.
pub type blkcnt_t = u64;

/// The type of a file’s group ID.
pub type gid_t = u32;

/// The type of a file’s inode.
pub type ino_t = u64;

/// The type of a file’s number of links.
pub type nlink_t = u64;

/// The type of a file’s timestamp (creation, modification, access, etc).
pub type time_t = i64;

#[cfg(unix)]
/// The type of a file’s user ID.
pub type uid_t = u32;

#[cfg(windows)]
mod windows {
    use std::convert::TryFrom;
    use std::{path::Path, os::windows::prelude::OsStrExt};
    use std::io;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::System::Memory::LocalFree;
    use windows::Win32::Foundation::{PSID, GetLastError};
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, LookupAccountSidW, SidTypeUnknown};
    use windows::Win32::Security::Authorization::{SE_OBJECT_TYPE, SE_FILE_OBJECT, GetNamedSecurityInfoW};

    pub struct NamedSecurityInfo {
        pub owner: PSID,
        pub group: PSID,
        pub security_descriptor: PSECURITY_DESCRIPTOR,
    }

    impl NamedSecurityInfo {
        /// Look up the character count of the username and domain name
        /// so that we can construct buffers of adequate size.
        /// 
        /// Returns `(username_character_count, domain_name_character_count)`
        pub fn lookup_account_sid_buffer(&self) -> Result<(u32, u32), io::Error> {
            let mut name_character_count = 0;
            let mut domain_name_character_count = 0;
            let return_value = unsafe {
                LookupAccountSidW(
                    PCWSTR(std::ptr::null()), // Local computer
                    self.owner, // The SID we want to look up
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
        pub fn lookup_account_sid(&self) -> Result<(String, String), io::Error> {
            // Get the buffer sizes.
            let (mut name_character_count, mut domain_name_character_count) = self.lookup_account_sid_buffer()?;

            // Make the buffers.
            let mut name_buffer = Vec::with_capacity(name_character_count as usize);
            let mut domain_name_buffer = Vec::with_capacity(domain_name_character_count as usize);

            let mut e_use = SidTypeUnknown;
            let return_value = unsafe {
                LookupAccountSidW(
                    PCWSTR(std::ptr::null()),
                    self.owner,
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
    
    impl TryFrom<&Path> for NamedSecurityInfo {
        type Error = std::io::Error;

        fn try_from(p: &Path) -> Result<Self, Self::Error> {
            let object_name: Vec<u16> = p.as_os_str().encode_wide().chain(Some(0)).collect();
            let p_object_name = PCWSTR(object_name.as_ptr());
            let object_type: SE_OBJECT_TYPE = SE_FILE_OBJECT;
            let security_info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
            let mut sid_owner = PSID(std::ptr::null_mut());
            let mut sid_group = PSID(std::ptr::null_mut());
            let mut security_descriptor = PSECURITY_DESCRIPTOR::default();

            unsafe {
                GetNamedSecurityInfoW(
                    p_object_name, 
                    object_type,
                    security_info,
                    &mut sid_owner,
                    &mut sid_group,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut security_descriptor);
            }
            

            if sid_owner.is_invalid() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "Owner SID not found"));
            }

            if sid_group.is_invalid() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "Group SID not found"));
            }

            if security_descriptor.is_invalid() {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Security Descriptor Inaccessible"));
            }

            Ok(
                NamedSecurityInfo {
                    owner: sid_owner,
                    group: sid_group,
                    security_descriptor,
                }
            )
        }
    }

    impl Drop for NamedSecurityInfo {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.security_descriptor.0 as isize);
            }
        }
    }

}

/// The file’s base type, which gets displayed in the very first column of the
/// details output.
///
/// This type is set entirely by the filesystem, rather than relying on a
/// file’s contents. So “link” is a type, but “image” is just a type of
/// regular file. (See the `filetype` module for those checks.)
///
/// Its ordering is used when sorting by type.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub enum Type {
    Directory,
    File,
    Link,
    Pipe,
    Socket,
    CharDevice,
    BlockDevice,
    Special,
}

impl Type {
    pub fn is_regular_file(self) -> bool {
        matches!(self, Self::File)
    }
}


/// The file’s Unix permission bitfield, with one entry per bit.
#[derive(Copy, Clone)]
pub struct Permissions {
    pub user_read:      bool,
    pub user_write:     bool,
    pub user_execute:   bool,

    pub group_read:     bool,
    pub group_write:    bool,
    pub group_execute:  bool,

    pub other_read:     bool,
    pub other_write:    bool,
    pub other_execute:  bool,

    pub sticky:         bool,
    pub setgid:         bool,
    pub setuid:         bool,
}

/// The file's FileAttributes field, available only on Windows.
#[derive(Copy, Clone)]
pub struct Attributes {
    pub archive:         bool,
    pub directory:       bool,
    pub readonly:        bool,
    pub hidden:          bool,
    pub system:          bool,
    pub reparse_point:   bool,
}

/// The three pieces of information that are displayed as a single column in
/// the details view. These values are fused together to make the output a
/// little more compressed.
#[derive(Copy, Clone)]
pub struct PermissionsPlus {
    pub file_type:   Type,
    #[cfg(unix)]
    pub permissions: Permissions,
    #[cfg(windows)]
    pub attributes:  Attributes,
    pub xattrs:      bool,
}


/// The permissions encoded as octal values
#[derive(Copy, Clone)]
pub struct OctalPermissions {
    pub permissions: Permissions,
}

/// A file’s number of hard links on the filesystem.
///
/// Under Unix, a file can exist on the filesystem only once but appear in
/// multiple directories. However, it’s rare (but occasionally useful!) for a
/// regular file to have a link count greater than 1, so we highlight the
/// block count specifically for this case.
#[derive(Copy, Clone)]
pub struct Links {

    /// The actual link count.
    pub count: nlink_t,

    /// Whether this file is a regular file with more than one hard link.
    pub multiple: bool,
}


/// A file’s inode. Every directory entry on a Unix filesystem has an inode,
/// including directories and links, so this is applicable to everything exa
/// can deal with.
#[derive(Copy, Clone)]
pub struct Inode(pub ino_t);


/// The number of blocks that a file takes up on the filesystem, if any.
#[derive(Copy, Clone)]
pub enum Blocks {

    /// This file has the given number of blocks.
    Some(blkcnt_t),

    /// This file isn’t of a type that can take up blocks.
    None,
}


#[cfg(unix)]
/// The ID of the user that owns a file. This will only ever be a number;
/// looking up the username is done in the `display` module.
#[derive(Copy, Clone)]
pub struct User(pub uid_t);

#[cfg(windows)]
pub struct User(pub NamedSecurityInfo);

/// The ID of the group that a file belongs to.
#[derive(Copy, Clone)]
pub struct Group(pub gid_t);


/// A file’s size, in bytes. This is usually formatted by the `number_prefix`
/// crate into something human-readable.
#[derive(Copy, Clone)]
pub enum Size {

    /// This file has a defined size.
    Some(u64),

    /// This file has no size, or has a size but we aren’t interested in it.
    ///
    /// Under Unix, directory entries that aren’t regular files will still
    /// have a file size. For example, a directory will just contain a list of
    /// its files as its “contents” and will be specially flagged as being a
    /// directory, rather than a file. However, seeing the “file size” of this
    /// data is rarely useful — I can’t think of a time when I’ve seen it and
    /// learnt something. So we discard it and just output “-” instead.
    ///
    /// See this answer for more: http://unix.stackexchange.com/a/68266
    None,

    /// This file is a block or character device, so instead of a size, print
    /// out the file’s major and minor device IDs.
    ///
    /// This is what ls does as well. Without it, the devices will just have
    /// file sizes of zero.
    DeviceIDs(DeviceIDs),
}

/// The major and minor device IDs that gets displayed for device files.
///
/// You can see what these device numbers mean:
/// - <http://www.lanana.org/docs/device-list/>
/// - <http://www.lanana.org/docs/device-list/devices-2.6+.txt>
#[derive(Copy, Clone)]
pub struct DeviceIDs {
    pub major: u8,
    pub minor: u8,
}


/// One of a file’s timestamps (created, accessed, or modified).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time {
    pub seconds: time_t,
    pub nanoseconds: time_t,
}


/// A file’s status in a Git repository. Whether a file is in a repository or
/// not is handled by the Git module, rather than having a “null” variant in
/// this enum.
#[derive(PartialEq, Copy, Clone)]
pub enum GitStatus {

    /// This file hasn’t changed since the last commit.
    NotModified,

    /// This file didn’t exist for the last commit, and is not specified in
    /// the ignored files list.
    New,

    /// A file that’s been modified since the last commit.
    Modified,

    /// A deleted file. This can’t ever be shown, but it’s here anyway!
    Deleted,

    /// A file that Git has tracked a rename for.
    Renamed,

    /// A file that’s had its type (such as the file permissions) changed.
    TypeChange,

    /// A file that’s ignored (that matches a line in .gitignore)
    Ignored,

    /// A file that’s updated but unmerged.
    Conflicted,
}


/// A file’s complete Git status. It’s possible to make changes to a file, add
/// it to the staging area, then make *more* changes, so we need to list each
/// file’s status for both of these.
#[derive(Copy, Clone)]
pub struct Git {
    pub staged:   GitStatus,
    pub unstaged: GitStatus,
}

impl Default for Git {

    /// Create a Git status for a file with nothing done to it.
    fn default() -> Self {
        Self {
            staged: GitStatus::NotModified,
            unstaged: GitStatus::NotModified,
        }
    }
}
