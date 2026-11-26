# Data Deposit Box for TerraMaster TOS 7

Continuous, encrypted cloud backup of the shared folders you choose on a
TerraMaster NAS, with restore back to the NAS from the Data Deposit Box web
portal.

- App id: `ddbbackup`
- Package: Deb, single package, x86_64
- Requires: TOS 7.0 or later, and a Data Deposit Box account
- Publisher: Data Deposit Box Inc., <https://datadepositbox.com/>
- Support: <https://datadepositbox.com/contact/>

The package is published as `ddbbackup_x86_64.deb` in this repository's
[Releases](../../releases). This repository holds the package's files
(configuration, language file, icon, service unit, lifecycle scripts); the
agent's binaries are proprietary and ship only in the release package.

## Setting it up

1. Install **Data Deposit Box** from the App Center.
2. In **Control Panel → Shared Folders**, give the `allusers` group access
   to each shared folder to back up: **Read** to back it up, **Read/Write**
   to also restore files into it.
3. Open the app from the App Center and sign in with your Data Deposit Box
   account. This registers the NAS as a device on that account.
4. Choose the folders to back up, and restore files, in the Data Deposit
   Box web portal.

## Permissions

| Permission | Why |
|---|---|
| Runs as the dedicated user `ddbbackup`, never as root | |
| Member of `allusers` | TOS has no per-app folder access: the agent reads (and, for restore, writes) the shared folders the administrator opens to `allusers`, and no others |
| Port 44883/tcp, listening | The sign-in page that **Open** shows (see Network) |
| Outbound HTTPS (443) | Backup and restore with Data Deposit Box servers |

## Network

- **Port 44883/tcp** serves only the sign-in page and its images. It shows
  no files, folders or settings of the NAS. Once the NAS is signed in, the
  page sends the browser on to the Data Deposit Box web portal, which has
  its own sign-in. The account password goes from the page to Data Deposit
  Box over HTTPS and is not stored on the NAS.
- **Outbound HTTPS** to Data Deposit Box servers only: `service.acpana.com`
  (backup service), `connect.datadepositbox.com` (account check at sign-in),
  `datadepositbox.com` (current sign-in page), and the storage servers the
  service assigns to the account.
- Files are encrypted on the NAS before upload.

## Files in the package

Under `/usr/local/ddbbackup/`, which TOS places on the volume chosen at
install. Read-only to the running app.

| Path | What |
|---|---|
| `config.ini` | App Center metadata |
| `ddbbackup.lang` | Name and description, 26 languages |
| `images/icons/ddbbackup.svg` | Icon |
| `init.d/ddbbackup.service` | systemd unit: runs as `ddbbackup`, `ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true` |
| `ddbbackup.env` | Where the agent keeps its files (below) |
| `bin/ddb_launcher`, `bin/ddb_backup`, `bin/ddb_wserv` | The agent: launcher, backup and restore, sign-in page |
| `config/` | Server and brand settings (`configuration.xml`), version, the shared folder list script, the sign-in page and its images |
| `THIRD-PARTY-NOTICES.txt` | Licences of the open-source code the agent uses |

## Runtime file manifest

Everything the app creates while it runs. The postinst script creates
`data/` and `logs/` (mode 750, owner `ddbbackup`); the agent creates
everything in them. Paths are relative to `/usr/local/ddbbackup/data/`
unless noted.

| Path | Purpose | Format | Created when | Growth bound / rotation | Lifecycle |
|---|---|---|---|---|---|
| `token.com` | The device's sign-in credential (mode 600) | Text, < 1 KB | At sign-in | Fixed size | Persistent; replaced at the next sign-in; deleted if the device is removed from the account |
| `machineid.com` | The device's id on the account | Text, < 100 bytes | At sign-in | Fixed size | Persistent; deleted with `token.com` |
| `host.cfg` | The server this device uses | Text, one line | At first start; rewritten if the service moves the device | < 256 bytes | Persistent |
| `profile11.xml` | Backup selection and schedule set in the web portal | XML | When the portal first reads or saves the settings | A few KB; grows with the number of folder selections and exclusions | Persistent |
| `DdbDb.db`, `DdbDb.db-wal`, `DdbDb.db-shm` | Index of the files selected for backup, to find new and changed files | SQLite | At start | Grows with the number of files selected for backup; rows for deleted or deselected files are removed. The `-wal` file normally stays around 4 MB | Persistent |
| `1_1_file.crc`, `1_1_file.db` | Changed blocks of a changed file up to 4 MB, while it uploads | Binary | During the upload of a changed file | About the size of that file (≤ 4 MB) | Temporary; deleted after each upload, and at the start of the next |
| `tmp_old.crc`, `tmp_new.crc`, `tmp_delta.dat` | Changed blocks of a changed file over 4 MB, while it uploads | Binary | During the upload of a changed file | Up to the size of that file; one set at a time (fixed names) | Temporary; deleted when the upload ends; an interrupted upload leaves them until the next large upload replaces them |
| `tmp/` | Directory for the temporary files below | Directory | At start | | Persistent (empty when idle) |
| `tmp/<fileid>.restore` | A file being restored, before it is checked and copied to its folder | File data | During a restore | The size of the files being restored | Temporary; deleted when the restore finishes, and at start |
| `tmp/addb.<id>_cleanup.*` | List of files the service holds for this device, to find files deleted from the NAS | Binary | When the service schedules a cleanup | Grows with the number of files backed up | Temporary; the download is deleted when the cleanup ends, the list at the next cleanup or at start |
| `tmp/addb.<id>.admin.temp` | Daily activity marker | Empty file | Every 24 hours | 0 bytes | Temporary; deleted at start |
| `tmp/linux_lastlog.zip`, `tmp/linux_all_log.zip`, `tmp/tmpshort.log` | Log bundles, only when Data Deposit Box support requests the logs | Zip, text | On a support request | Zips over 30 MB are not sent | Zips deleted after upload; `tmpshort.log` replaced each time |
| `/usr/local/ddbbackup/logs/backup_client_YYYY_MM_DD.log` | Backup, restore and sign-in log | Text | One file per day | A few lines per file backed up | Every 24 hours of running, files older than 20 days are deleted |
| `/usr/local/ddbbackup/logs/launcher_YYYY_MM_DD.log` | Launcher starts and stops | Text | One file per day | A few lines per start or stop | As above |
| `/usr/local/ddbbackup/logs/ps.txt` | List of running processes, for support | Text | On a support request | Replaced each time | As above |
| `/usr/local/ddbbackup/logs/crash_YYYYMMDD_HHMMSS.txt` | Crash report (mode 600) | Text | If the agent crashes | A few KB each | The newest 19 are kept |
| `/run/ddbbackup/ddb_backup.pid`, `ddb_wserv.pid` | Single-instance locks | Empty files | At start | 0 bytes | Removed by systemd when the service stops (`RuntimeDirectory`) |
| Service-private `/tmp`, `/var/tmp` | SQLite's temporary files for large queries | Binary | Rarely | Removed by SQLite at once | Wiped by systemd when the service stops (`PrivateTmp=true`) |
| Shared folders you restore into | Restored files, owned by `ddbbackup` | Your files | When you restore to the NAS from the web portal | The files you restore | Yours: never deleted by the app |

The app writes nothing to the shared system `/tmp`, `/etc` or anywhere else
outside the paths above.

## Upgrade and uninstall

- **Upgrade** (App Center): the app stops, the old version is removed
  keeping `data/` and `logs/`, and the new version starts. The NAS stays
  signed in as the same device.
- **Uninstall**, "Delete all config files" unticked: the app, its service
  and its files are removed; `data/` and `logs/` are kept, so a reinstall
  comes back signed in as the same device.
- **Uninstall**, ticked: `data/` and `logs/` are deleted too, and
  `ddbbackup` leaves `allusers`. A reinstall registers a new device.
- Neither touches your shared folders or the backups held by Data Deposit
  Box.

## Third-party software

See [`THIRD-PARTY-NOTICES.txt`](THIRD-PARTY-NOTICES.txt), also installed with
the app.
