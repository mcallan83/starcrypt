# Archiving macOS volumes

On macOS, creation automatically checks the canonical source against the
mount point returned by `statfs`. A mounted DMG is handled like another mounted
volume; a directory named `/Volumes/something` is not sufficient to activate
filtering. Linux and other platforms do not apply this policy.

When the selected source is a volume root, Starcrypt excludes these exact
root-level entry names before opening or descending into them:

| Entries | Purpose |
| --- | --- |
| `.DocumentRevisions-V100` | macOS Versions database (older document versions) |
| `.Spotlight-V100` | Spotlight index |
| `.fseventsd` | Filesystem event journal |
| `.TemporaryItems` | Temporary volume storage |
| `.Trashes` | Deleted items in the volume's Trash |
| `.hotfiles.btree` | HFS+ hot-file bookkeeping |
| `.journal`, `.journal_info_block` | HFS+ journal bookkeeping |
| `.quota.user`, `.quota.group` | Volume quota accounting |
| `.HFS+ Private Directory Data\r` | HFS+ directory hard-link implementation storage; final character is a carriage return |

Each exclusion is printed to stderr. This applies to vault folders, ZIP, and 7z
creation. Identically named entries in subdirectories or an ordinary source
folder remain included. Other read errors still abort creation and remove
incomplete output. There is no catch-all permission-error suppression.

This is a file-content archive, not a disk image or a bootable system backup.
Trash and the Versions database can contain old/deleted user content; automatic
exclusion means those historical copies are not retained. Keep the original DMG
if you need the entire filesystem and its history.

## Other macOS compatibility considerations

- `.git`, `.DS_Store`, `.VolumeIcon.icns`, indexing preference files, `._*`,
  `.AppleDouble`, and `__MACOSX` remain included. Metadata sidecars can contain
  resource forks and should not be discarded just because they are hidden.
- Native extended attributes, resource forks, Finder tags, permissions, ACLs,
  and creation dates are not preserved by the current vault implementation.
  Existing sidecar files are preserved as bytes, without synthesizing sidecars
  from native metadata. Files that depend on native resource forks can therefore
  be incomplete after extraction.
- Symlinks are stored without following their targets. Sockets, FIFOs, device
  nodes, and non-UTF-8 names/targets are rejected with an error rather than lost.
  Hard-link identity and sparse allocation are not preserved.
- Application/document bundles are traversed as directories. This does not make
  a live database or package consistent while another process modifies it;
  close writers before archiving.
- Time Machine backup trees and `lost+found` are not automatically excluded:
  they may contain valuable user data. This policy does not promise support for
  cloning Time Machine's filesystem structures or a macOS system volume.

## Research behind the policy

Reviewed November 12, 2026. These sources inform a deliberately narrow volume-root
policy; Starcrypt does not copy any source's entire exclusion list.

- [Apple: statfs](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fstatfs.2.html)
  defines the mounted-on path used for root detection.
- [Apple: File System Event Security](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/FileSystemEventSecurity/FileSystemEventSecurity.html)
  describes `.fseventsd` protection and warns against accessing its data directly.
- [Bombich: Carbon Copy Cloner exclusions](https://support.bombich.com/hc/en-us/articles/20686463321751-Some-files-and-folders-are-automatically-excluded-from-a-backup-task)
  documents temporary storage, volume-specific databases, journals, quota data,
  and Trash exclusions, including why the Versions database is volume-specific.
- [Apple: HFS+ format definitions](https://github.com/apple-oss-distributions/hfs/blob/main/core/hfs_format.h)
  documents private hard-link storage.
- [Apple: File System Details](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
  describes packages, security, and filesystem differences.
