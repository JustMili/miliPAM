# miliPAM

A custom Pluggable Authentication Module (PAM) for Linux written in C++. miliPAM uses **Argon2id** for secure password hashing and **libsodium** for cryptographic primitives. It uses a JSON database managed with file locking. Every hash has its own file for secure file reading and clean memory management.

Its main purpose is to allow you to make temporary credentials.


## Features

- **High Security Hashing:** Utilizes Argon2id algorithm for password store protection.
- **Privilege Separation:** Includes a root-privileged helper (`milipam_helper`) for secure database access.
- **Usage:** Allows you to make single-use or limited-use temporary credentials.
- **Safe I/O & Locking:** File locking (`flock`) prevents race conditions during database updates.
- **Clean Architecture:** Modular design separates module logic, CLI administration, and privilege helpers.

## Installation

### **Install compiled version**

Go to [https://github.com/JustMili/miliPAM/releases](https://github.com/JustMili/miliPAM/releases)
Download the latest stable release and follow the instructions found in the description


### **Compile**

**Clone this repository:**
```bash
git clone https://github.com/JustMili/miliPAM.git
```

**Build the project**
```bash
cd miliPAM
make
```
`make` automatically downloads and builds **nlohmann/json**, **Argon2** and **libsodium**
into `externals/` (internet connection required on first build).

You need to install these yourself:
- `g++`, `gcc`, `make`, `git`, `curl`
- `autoconf`, `automake`, `libtool` (needed to build libsodium)
- PAM development headers (`libpam0g-dev` on Debian/Ubuntu, `pam-devel` on Fedora/RHEL)
- glibc ≥ 2.34 (kernel ≥ 5.9)

**Install**
```bash
sudo ./install.sh
```

## Usage

The CLI utility milipam is used to manage stored authentication entries.

**Add entry**

```bash
sudo milipam -add <username> <max_uses> [-note <optional_note>]
```
You will be prompted in terminal to enter a password. The characters will not be shown.
Set max_uses to -1 for unlimited uses.

Example:
```bash
sudo milipam -add john 5 -note "Temporary access for tomorrow's event"
```

**List existing entries**

```bash
sudo milipam -list
```

**Delete an entry by ID**
```bash
sudo milipam -delete <entry_id>
```

**Show help**

```bash
sudo milipam -help
```
