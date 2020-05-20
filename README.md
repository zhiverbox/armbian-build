# zHIVErbox Armbian Customizations #

The zHIVErbox fork of the Armbian build tools tries to stick as close as possible 
to the upstream master branch and do customizations via our [armbian-userpatches 
repository](https://github.com/zhiverbox/armbian-userpatches). However, a few modifications can't be done via the userpatches:

1. btrfs subvolumes for /, /home, /var and /var/lib
zHIVErbox makes use of btrfs subvolumes, so we can easily move /var to the hard
disk of the Odroid HC1/HC2 and disable log2ram, which slightly increases the 
available (free) memory on the zHIVErbox.

2. kernel self-protection and security hardenings
zHIVErbox applies many kernel security settings described in: 
* https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings
* https://tails.boum.org/contribute/design/kernel_hardening/
This can't be done via the armbian-userpatches, so we have to do this here.

3. cache directory for userpatches
In addition to the `userpatches/overlay` directory, zHIVErbox set's up a
`userpatches/cache` directory, which is persisted across builds but doesn't contain
any essential sources. It can be used by apt to speed up subsequent builds, as 
packages which are installed through userpatches don't have to be downloaded with
every build when they have been downloaded with a previous build already.

4. use btrfs with `lzo` compression instead of `zlib`
Vanilla Armbian doesn't allow the configuration of which compression should be
used with btrfs. zHIVErbox adds this as a configuration option and uses `lzo` 
by default, which gives slight performance improvements. 

5. minor changes
4.1. avoid username leaks in `armbian-check-first-login.sh`
4.2. use netcat with Tor socks `proxy in armbian-config.sh`
4.3. use torsocks to pull zHIVErbox git updates in `compile.sh`

# Armbian #

Debian based Linux for ARM based single-board computers
  
[https://www.armbian.com](https://www.armbian.com "Armbian")


# How to build an image or a kernel?

Supported build environment is **Ubuntu Bionic 18.04 x64** ([minimal iso image](http://archive.ubuntu.com/ubuntu/dists/bionic/main/installer-amd64/current/images/netboot/mini.iso)).

- guest inside a [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or other virtualization software,
- guest managed by [Vagrant](https://docs.armbian.com/Developer-Guide_Using-Vagrant/). This uses Virtualbox (as above) but does so in an easily repeatable way,
- inside a [Docker](https://docs.armbian.com/Developer-Guide_Building-with-Docker/), [systemd-nspawn](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html) or other container environment [(example)](https://github.com/armbian/build/pull/255#issuecomment-205045273),
- running natively on a dedicated PC or a server (**not** recommended),
- **25GB disk space** or more and **2GB RAM** or more available for the VM, container or native OS,
- superuser rights (configured `sudo` or root access).

**Execution**

	apt -y install git
	git clone https://github.com/armbian/build
	cd build
	./compile.sh

Make sure that full path to the build script does not contain spaces.

You will be prompted with a selection menu for a build option, a board name, a kernel branch and an OS release. Please check the documentation for [advanced options](https://docs.armbian.com/Developer-Guide_Build-Options/) and [additional customization](https://docs.armbian.com/Developer-Guide_User-Configurations/).

Build process uses caching for the compilation and the debootstrap process, so consecutive runs with similar settings will be much faster.

# How to report issues?

Please read [this](https://github.com/igorpecovnik/lib/blob/master/.github/ISSUE_TEMPLATE.md) notice first before opening an issue.

# How to contribute?

- [Fork](https://help.github.com/articles/fork-a-repo/) the project
- Make one or more well commented and clean commits to the repository. 
- Perform a [pull request](https://help.github.com/articles/creating-a-pull-request/) in github's web interface.

If it is a new feature request, don't start the coding first. Remember to [open an issue](https://guides.github.com/features/issues/) to discuss the new feature.

If you are struggling, check [this detailed step by step guide on contributing](https://www.exchangecore.com/blog/contributing-concrete5-github/).

## Where to get more info?

- [Documentation](https://docs.armbian.com/Developer-Guide_Build-Preparation/ "Developer resources")
- [Prebuilt images](https://www.armbian.com/download/ "Download section")
- [Support forums](https://forum.armbian.com/ "Armbian support forum")
