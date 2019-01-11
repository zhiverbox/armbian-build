#!/bin/bash

# The zHIVErbox installation scripts may be used according to the 
# MIT License EXCEPT for the following conditions:
#   * Running ANY software that forks the 
#     Bitcoin consensus (https://bitcoin.org)
#   * If you want to run software like Bcash (Bitcoin Cash) and similar
#     consensus forks, feel free to write your own installation scripts 
#     from scratch, but you are not granted permission to use, copy, 
#     modify or benefit-from the work of the zHIVErbox authors and 
#     contributors.
# We know this sounds arbitrarly and allows for heated discussions, 
# but these are simply our terms. We provide our work for free, so 
# either accept it or try to create your own stuff.

########################
# script configuration #
########################
SRC="$(dirname "$(realpath "${BASH_SOURCE}")")"
PROJNAME="zHIVErbox"
VERSION=0.2.0

# name and location of log file
INST_LOG=$SRC/install-$PROJNAME.log

# default LUKS password of the source images (zHIVErbox-x.x.x.img.src)
SOURCE_LUKS_PASSW="abcd"

# user input prefix
UINPRFX="         >" # 9 spaces
# sed intendation
SED_INTEND="         " # 9 spaces

# bash colors
BOLD='\e[1m'
RED='\e[0;31m'
GREEN='\e[0;32m'
MAGENTA='\e[0;35m'
ORANGE='\e[0;33m'
NC='\x1B[0m'

# check for whitespace in $SRC and exit for safety reasons
grep -q "[[:space:]]" <<<"${SRC}" && { echo "\"${SRC}\" contains whitespace. Not supported. Aborting." >&2 ; exit 1 ; }

cd $SRC

#--------------------------------------------------------------------------------------------------------------------------------
# Script functions
#--------------------------------------------------------------------------------------------------------------------------------

check_host_os()
{
	SUPPORTED_HOST_OS="xenial bionic"
	# Ubuntu Xenial and Bionic are the only fully supported host OS releases
	local codename=$(lsb_release -sc)
	display_alert "Detected installer host OS release" "${codename:-(unknown)}" ""
	
	if [[ -z $codename || $SUPPORTED_HOST_OS != *"$codename"* ]]; then
		display_alert "It seems you are running on an unsupported host system" "${codename:-(unknown)}" "err"
		echo -e \
"${BOLD}$PROJNAME installer${NC} has only been tested on 
  * Ubuntu Xenial (16.04 LTS)
  * Ubuntu Bionic (18.04 LTS)
  
Please use Virtualbox and setup a supported OS to run this installer.
${RED}Press CTRL+C to abort or continue without support.${NC}
" | sed "s/^/${SED_INTEND}/"
		press_any_key
		echo -e \
"> If you still want to continue on this unsupported system, please 
select a profile:"

		select HOSTOS in $SUPPORTED_HOST_OS;
		do
			echo "" && display_alert "Continuing with profile:" "$HOSTOS" "wrn"
			display_alert "You will likely encounter errors!" "" "wrn"
			break
		done
	else
		HOSTOS=$codename
	fi
}

# host os specific differences this script needs to handle
host_os_configuration()
{
	case $HOSTOS in
		xenial)
			ESSENTIAL_PACKAGES="cryptsetup btrfs-tools gpgv2 secure-delete git nmap net-tools"
			CMD_GET_LOCAL_IP4_ADDR="ip route get 1 | awk '{print \$NF;exit}'";
			CMD_GPG="gpg2";
			SYSTEMCTL_NOTFOUND="not-found";
			;;
		bionic)
			ESSENTIAL_PACKAGES="cryptsetup btrfs-tools gpg secure-delete git nmap net-tools";
			CMD_GET_LOCAL_IP4_ADDR="ip route get 1 | awk '{print \$(NF-2);exit}'";
			CMD_GPG="gpg";
			SYSTEMCTL_NOTFOUND="could not be found";
			;;
	esac
}

display_alert()
#--------------------------------------------------------------------------------------------------------------------------------
# Let's have unique way of displaying alerts
#--------------------------------------------------------------------------------------------------------------------------------
{
	# log function parameters to install.log
	echo "Displaying message: $@" >> $INST_LOG

	local tmp=""
	[[ -n $2 ]] && tmp="[${ORANGE} $2 ${NC}]"

	case $3 in
		err)
		echo -e "[${RED} error ${NC}] $1 $tmp"
		;;

		wrn)
		echo -e "[${MAGENTA} warn ${NC}] $1 $tmp"
		;;

		ext)
		echo -e "[${GREEN} o.k. ${NC}] ${GREEN}$1${NC} $tmp"
		;;

		info)
		echo -e "[${GREEN} o.k. ${NC}] $1 $tmp"
		;;
		
		todo)
		echo -e "[\e[0;45m TODO \x1B[0m] $1 $tmp"
		;;

		*)
		echo -e "[${GREEN} .... ${NC}] $1 $tmp"
		;;
	esac
}

press_any_key()
{
    read -n 1 -s -r -p "$UINPRFX Press any key to continue."
    printf '\r'
}

new_screen()
{
    echo "" && clear
}

press_any_key_for_new_screen()
{
    echo ""
    press_any_key
    new_screen
}

introduction()
{
    new_screen
    display_alert "#######################################################################" "" ""
    display_alert "Image customization for $PROJNAME                " "Version: $VERSION" ""
    display_alert "#######################################################################" "" ""
	echo -e \
"
${BOLD}$PROJNAME${NC} - pronounced like '${MAGENTA}cypher box${NC}' (sī′fər bŏks) - is an 
${BOLD}unfairly secure and unfairly cheap${NC} base system for the era of
distributed networks (meshnets).  Minds joining those networks
form a ${BOLD}HIVE (swarm) of self-sovereign individuals${NC} who
${RED}DON'T TRUST, BUT VERIFY.${NC}  
"  | sed "s/^/${SED_INTEND}/"

    press_any_key
	echo -e \
"Unfortunatly, security cannot be provided as a simple 'download'.  
A secure system requires ${BOLD}individual encryption${NC} and a ${BOLD}secure source 
of randomness${NC} (entropy). Therefore a secure system can 
only be created by a self-sovereign individual themself - and 
only for themself.  However, not everybody in a HIVE (society) can 
aquire the highly specialized knowledge and skills to create their 
own secure system from scratch?!  
"  | sed "s/^/${SED_INTEND}/"

    press_any_key
	echo -e \
"Therefore Cypherpunks write software and provide technology that can 
be used by other individuals to achieve the same level of security, 
privacy and self sovereignty.  Those tools should be as user friendly 
as possible without compromising on security.  Ideally, those tools 
still provide a certain level of education, to retain their users from 
developing a 'blindly trusting attitude'.  ${BOLD}DON'T TRUST, VERIFY!${NC}
" | sed "s/^/${SED_INTEND}/"

    press_any_key
	echo -e \
"$PROJNAME is build entirely on FLOSS (Free/Libre Open Source Software).  
This allows other Cypherpunks to review, verify and improve $PROJNAME 
without permission." | sed "s/^/${SED_INTEND}/"

}

bncf_agreement()
{
    press_any_key_for_new_screen
    display_alert "----------------------------------------------------------------------" "" ""
    display_alert "Bitcoin Non-Consensus fork agreement                                  " "" ""
    display_alert "----------------------------------------------------------------------" "" ""
	echo -e \
"${BOLD}TL;DR:${NC} You can do with a $PROJNAME whatever you want, except for 
running Bcash (Bitcoin Cash) & Co. on it.
In other words: Your are ${RED}not allowed${NC} to run software that 
${RED}forks the consensus rules${NC} of the ${ORANGE}Bitcoin blockchain${NC}.
" | sed "s/^/${SED_INTEND}/"

    press_any_key
	echo -e \
"${BOLD}Long Version:${NC}                                                  
The $PROJNAME installation scripts may be used according to the 
${MAGENTA}MIT License${NC} ${RED}EXCEPT${NC} for the following conditions:
  * Running ANY ${RED}software that forks the 
    ${ORANGE}Bitcoin consensus${NC} (https://bitcoin.org)
  * If you want to run software like Bcash (Bitcoin Cash) and similar
    consensus forks, feel free to write your own installation scripts 
    from scratch, but you are ${BOLD}not granted permission${NC} to use, copy, 
    modify or benefit-from the work of the $PROJNAME authors and 
    contributors.
We know this sounds arbitrarly and allows for heated discussions, 
but these are simply our terms. We provide our work for free, so 
either accept it or try to create your own stuff.
" | sed "s/^/${SED_INTEND}/"
    echo ""
    read -p "$UINPRFX I agree to NOT run Bitcoin-Consensus-Fork software (y/n)? " choice
    case "$choice" in 
        y|Y|yes|YES ) echo ""; display_alert "Great! Welcome to the $PROJNAME community!" "Agreement accepted." "ext";;
        * ) echo ""; display_alert "Sorry. Bye!" "Agreement declined." "err"; echo "" && press_any_key; exit 1;;
    esac
    echo ""
}

check_req_apt_packages()
{
    press_any_key_for_new_screen
    display_alert "Checking software prerequesites of your system ($HOSTOS)" "$ESSENTIAL_PACKAGES" ""
echo -e | sed "s/^/${SED_INTEND}/" << EOF
We might need to install some additional software on your computer.

Wait! Why? What software?

EOF
    press_any_key
echo -e | sed "s/^/${SED_INTEND}/" << EOF
Don't panic! The software comes from your system's 
software management: APT alias Advanced Package Tool
[ see: https://en.wikipedia.org/wiki/APT_(Debian) ]

The needed software is probably already installed on your computer. 
We just want to make sure it really is there before we continue.

EOF
    press_any_key
    
    for package in $ESSENTIAL_PACKAGES; 
    do
    	check_package $package
    done
    
}

# base58 encoding from https://github.com/grondilu/bitcoin-bash-tools/blob/master/bitcoin.sh
declare -a base58=(
      1 2 3 4 5 6 7 8 9
    A B C D E F G H   J K L M N   P Q R S T U V W X Y Z
    a b c d e f g h i j k   m n o p q r s t u v w x y z
)
unset dcr; for i in {0..57}; do dcr+="${i}s${base58[i]}"; done

encodeBase58() 
{
	#[[ -z $base58 ]] declare_base58
	echo -n "$1" | sed -e's/^\(\(00\)*\).*/\1/' -e's/00/1/g' | tr -d '\n'
	dc -e "16i ${1^^} [3A ~r d0<x]dsxx +f" |
	while read -r n; do echo -n "${base58[n]}"; done
}

check_disk_space()
{
    # we need at least ~2GB of temp space
    local free_tmp=$(df /tmp/ | tail -1 | awk '{ print $4 }')
    if (( $free_tmp < 2*1000*1000 )); then
        display_alert "Not enough free disk space in temporary file system (/tmp)" "df -h /tmp" "err"
        df -h /tmp | sed "s/^/${SED_INTEND}/"
        display_alert "$PROJNAME installation requires at least 2GB of temporary disk space." "" "err"
        exit 1
    fi
}

make_root()
{
    if [[ $EUID != 0 ]]; then
	    display_alert "This script requires root privileges, trying to use sudo" "" "wrn"
	    sudo rm $INST_LOG 2> /dev/null
            touch $INST_LOG
	    sudo "$SRC/install-$PROJNAME.sh" "$@"
	    exit $?
    fi
    
    # create temp directory for whole build
    TMP_BUILD_DIR=$(mktemp -d)
    # put default password into a file
	echo -n $SOURCE_LUKS_PASSW > $TMP_BUILD_DIR/sourcepass
    
    ## traps for abort/cleanup
    trap cleanup EXIT
}

cleanup()
{
    # automatically cleanup loop devices
    umount_images
    # automatically delete temp build dir
    delete_tmpbuilddir
    # automatically clean all secrets on exit
    secure_remove_secrets
    # show donation address
	show_donation_address
}

# securely remove secrets from tmpfs automatically on EXIT
secure_remove_secrets()
{
    new_screen
    # contains GPG secret
    srm -r $TMP_GNUPGHOME > /dev/null 2>&1
    
    # contains cjdns secret
    srm -r $TMP_CJDCONF > /dev/null 2>&1
    
    # drop PageCache, dentries and inodes
    sync; echo 3 > /proc/sys/vm/drop_caches
    
    # tell the user what happend
    display_alert "$PROJNAME installation was finished or aborted!" "CLEANING UP TRACES" "info"
    echo ""
    display_alert "Securely erased all generated $PROJNAME secrets in" "/dev/shm" "ext"
    echo ""
    display_alert "Dropped kernel PageCache, dentries and inodes" "sync; echo 3 > /proc/sys/vm/drop_caches" "ext"
    
    # Clean RAM
    echo ""
    display_alert "Deleting memory (RAM) data in a secure manner now" "sdmem -ll -v" ""
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
    
sdmem  is  designed  to delete data which may lie still in your memory
(RAM) in a secure manner which can not be  recovered  by  thieves,  law
enforcement or other threats.  Note that with the new SDRAMs, data will
not wither away but will be kept static - it is  easy  to  extract  the
necessary  information!   The  wipe  algorithm  is  based  on the paper
"Secure Deletion of Data from Magnetic  and  Solid-State  Memory"  pre‐
sented  at  the  6th Usenix Security Symposium by Peter Gutmann, one of
the leading civilian cryptographers.

EOF
    display_alert "We're using a faster but less secure variant now:" "sdmem -ll -v" "wrn"
    display_alert "If you require ULTRA security, manually run:" "sdmem -v" "wrn"
    echo ""
    press_any_key
    #sdmem -ll -v
    display_alert "Memory cleanup finished!" "sdmem" "ext"
}

umount_images()
{
    umount $MOUNT_DEST_ROOT > /dev/null 2>&1
    cryptsetup luksClose $DEST_ROOT_MAPPER > /dev/null 2>&1
    umount $MOUNT_SRC_ROOT > /dev/null 2>&1
    cryptsetup luksClose SRC_ROOT_MAPPER > /dev/null 2>&1
    losetup --detach-all > /dev/null 2>&1
}

delete_tmpbuilddir()
{
    rm -rf $TMP_BUILD_DIR > /dev/null 2>&1
}

check_package()
{
    echo -n "Checking for $1: " | sed "s/^/${SED_INTEND}/"
	PKG_OK=$(dpkg-query -W --showformat='${Status} (${Version})\n' $1 2>/dev/null)
	#echo "Checking for $1: $PKG_OK" | sed "s/^/${SED_INTEND}/"
	if [[ ! $PKG_OK =~ ^'install ok installed' ]]; then
	  echo -n "Not installed. Installing... " 
	  apt-get --yes install $1 >> $INST_LOG
	  echo "Done."
	  echo -n "  Status of  $1: " | sed "s/^/${SED_INTEND}/"
	  echo $(dpkg-query -W --showformat='${Status} (${Version})\n' $1 2>/dev/null)
	else
	  echo $PKG_OK | sed 's/install ok//'
	fi
}

optional_enable_trezor_integration()
{
    press_any_key_for_new_screen
    display_alert "Optional: Enable Trezor hardware integration" "https://trezor.io" ""
    echo ""
echo -e | sed "s/^/${SED_INTEND}/" << EOF
$PROJNAME security can be hardened significantly and more 
conveniently with a Trezor hardware device.

EOF
    press_any_key
echo -e | sed "s/^/${SED_INTEND}/" << EOF
RECOMMENDED: If you own a Trezor device, it will be used for
  * $PROJNAME SSH login: Public-key authentication
  * $PROJNAME disc encryption: Secure entropy source 
    (randomness) for a new LUKS volume key
  * $PROJNAME boot system signature verification: 
    Manually verify that initramfs hasn't been compromized
    
EOF

    read -p "$UINPRFX Enable $PROJNAME Trezor integration (y/n)? [default: no] " choice
    case "$choice" in 
      y|Y|yes|YES ) USE_TREZOR="yes"; display_alert "Trezor integration:" "ENABLED" "info";;
      * ) USE_TREZOR="no"; display_alert "Trezor integration:" "DISABLED" "wrn";;
    esac
    echo ""
    if [[ $USE_TREZOR == "yes" ]]; then
        check_trezor_apt_packages
        check_trezor_github_projects
    fi
}

check_trezor_apt_packages()
{
    press_any_key_for_new_screen
    display_alert "Trezor integration requirements" "python3-dev, cython3, libusb-dev, libudev-dev, git" ""
    echo ""
echo -e | sed "s/^/${SED_INTEND}/" << EOF
Trezor integration requires additional software on your
computer. But don't worry, all of that is Open Source 
software as well.

Let's first install available software via your system's
software management (APT) again.

EOF
    press_any_key
    check_package python3-pip
    check_package python3-dev
    check_package python3-tk
    check_package cython3
    check_package libusb-1.0-0-dev
    check_package libudev-dev
    check_package git
    
    echo ""
    press_any_key
}

check_trezor_github_projects()
{
    press_any_key_for_new_screen
    display_alert "Additional Trezor software required from:" "https://github.com" ""
    echo ""
echo -e | sed "s/^/${SED_INTEND}/" << EOF
The following software is not available via your system's
software management (APT). We need to download the source
code from GitHub.
  * https://github.com/trezor/python-trezor
  * https://github.com/romanz/trezor-agent

EOF
    press_any_key
    
    ask_use_tor
    
    install_trezorctl
    install_trezor_agent
}

ask_use_tor()
{
    echo ""
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
GitHub is a centralized 'clearnet' repository. There's no
distributed alternative available (yet). To preserve your
privacy it's recommended to download GitHub projects 
over the TOR network [ https://www.torproject.org ].

EOF
    read -p "$UINPRFX Use TOR to download from github.com (y/n)? [default: yes] " choice
    case "$choice" in 
      n|N|no|NO ) USE_TOR="no";;
      * ) USE_TOR="yes";;
    esac
    echo ""
    
    if [[ $USE_TOR ]]; then
        check_package tor
        check_package torsocks
        display_alert "TOR privacy:" "ENABLED" "info"
        TORIFY_CMD="torsocks"
        GIT_CMD="torsocks git"
        PIP_CMD="torsocks pip3"
    else        
        display_alert "TOR privacy:" "DISABLED" "wrn"
        TORIFY_CMD=""
        GIT_CMD="git"
        PIP_CMD="pip3"
    fi
    
    echo ""
    press_any_key
}

clone_or_update_from_github()
{
    local name=$1
    local target_path="$SRC_HOME/$name"
    local origin=$2
    display_alert "Download $name from GitHub" "$origin" ""
    echo ""
    
    check_package git
    
    # ask for TOR in case we haven't done before
    [[ ! -v USE_TOR ]] && ask_use_tor
    
    # make sure target path exists
    sudo -H -u $SUDO_USER mkdir -p $target_path
    
    # if source directory doesn't exist yet we have to clone from github first
    if [[ ! -d "$target_path/.git/" ]]; then
        display_alert "Download $name from GitHub" "$GIT_CMD clone ${origin}.git $target_path" ""
        display_alert "Be patient. This will take some time..." "" ""
        display_alert "(see details: $INST_LOG)" "" ""
        echo ""
        sudo -H -u $SUDO_USER $GIT_CMD clone ${origin}.git $target_path >> $INST_LOG 2>&1
    fi
    
    cd $target_path
    display_alert "Target directory:" "$target_path" ""
    
    # fetch origin for updates
    display_alert "Fetch $name repository updates" "$GIT_CMD fetch" ""
    sudo -H -u $SUDO_USER $GIT_CMD fetch >> $INST_LOG 2>&1
    
    # local checkout to latest stable version
    latesttag=$(git describe --abbrev=0 --tags)
    display_alert "Switch $name to latest release" "git checkout ${latesttag}" ""
    sudo -H -u $SUDO_USER git checkout ${latesttag} && export ${name^^}_CHECKOUT_COMPLETE=true >> $INST_LOG 2>&1
    display_alert "$(tail -n1 $INST_LOG)" "" "info" | sed 's/Displaying message: //'
    display_alert "(see details: $INST_LOG)" "" ""

    # TODO: verify sources have not been compromized (man-in-the-middle attack)
    #git verify-tag --raw $(git describe)
    
    # back to working directory
    cd $SRC
    
    echo ""
    press_any_key
}

check_trezorctl()
{
	[[ -n $(which trezorctl) ]] || echo "trezorctl is missing" && return 1
	return 1
}

install_trezorctl()
{
    press_any_key_for_new_screen
    clone_or_update_from_github "python-trezor" "https://github.com/trezor/python-trezor"
    
    # install trezorctl using pip
    display_alert "Install trezor:" "sudo -H -u $SUDO_USER $PIP_CMD install --user -e ." ""
    sudo -H -u $SUDO_USER $PIP_CMD install --user -e $SRC_HOME/python-trezor >> $INST_LOG 2>&1
    display_alert "$(tail -n1 $INST_LOG)" "" "info"
    echo "(see details: $INST_LOG)" | sed "s/^/${SED_INTEND}/"
    display_alert "$(sudo -H -u $SUDO_USER which trezorctl)" "which trezorctl" "ext"
   
    echo ""
    press_any_key
}

check_trezor_agent()
{
    [[ -n $(which trezor-agent) ]] || echo "trezor-agent is missing" && return 1
}

install_trezor_agent()
{
    press_any_key_for_new_screen
    clone_or_update_from_github "trezor-agent" "https://github.com/romanz/trezor-agent"
    
    # install libagent using pip
    display_alert "Installing libagent" "sudo -H -u $SUDO_USER $PIP_CMD install --user -e $SRC_HOME/trezor-agent" ""
    sudo -H -u $SUDO_USER $PIP_CMD install --user -e $SRC_HOME/trezor-agent >> $INST_LOG 2>&1
    display_alert "$(tail -n1 $INST_LOG) (see details: $INST_LOG)" "" "info"

    # install trezor-agent using pip
    display_alert "Installing trezor-agent" "sudo -H -u $SUDO_USER $PIP_CMD install --user -e $SRC_HOME/trezor-agent/agents/trezor" ""
    sudo -H -u $SUDO_USER $PIP_CMD install --user -e $SRC_HOME/trezor-agent/agents/trezor >> $INST_LOG 2>&1
    display_alert "$(tail -n1 $INST_LOG) (see details: $INST_LOG)" "" "info" 
    display_alert "$(sudo -H -u $SUDO_USER which trezor-agent)" "which trezor-agent" "ext"
    
    echo ""
    press_any_key
}

cjdns_networking_preface()
{
    press_any_key_for_new_screen
    display_alert "Networking essentials:" "https://en.wikipedia.org/wiki/Ethernet" ""
    echo ""
echo -e | sed "s/^/${SED_INTEND}/" << EOF
Do you wonder how you will connect to your $PROJNAME later?

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
Well, via Ethernet! Often called LAN (Local Area Network).
But usually this is a bit of a hassle. Typically you have a 'router' 
somewhere in your network, which assigns temporary IP addresses to 
other devices in your network.

Just like the current Ethernet IP address of this computer:

EOF
    press_any_key
    display_alert "$(eval $CMD_GET_LOCAL_IP4_ADDR)" "$CMD_GET_LOCAL_IP4_ADDR" "ext"
    echo ""
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
But the $PROJNAME has no display and keyboard. How will you
find out the IP address of your $PROJNAME?

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
And even if you do find out? The IP addresses your router assigns 
are temporary. They can change over time.

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
And what about security? How can you be sure the IP address you think 
your $PROJNAME has is really your $PROJNAME and not from an attacker? 

There's a name for these kind of attacks:

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
Man-in-the-middle attack:                
[ https://en.wikipedia.org/wiki/Man-in-the-middle_attack ]

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
In short: Traditional networking is a hassle! And insecure!

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
LET'S FIX THAT NOW!                      

EOF
}

cjdns_solution()
{
    press_any_key_for_new_screen
    display_alert "Cjdns: Networking Reinvented" "https://github.com/cjdelisle/cjdns" ""
    echo ""
echo -e | sed "s/^/${SED_INTEND}/" << EOF
$PROJNAME uses 'Cjdns' as a solution to the previous problems.

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
Cjdns provides near-zero-configuration networking, and prevents 
many of the security and scalability issues that plague existing 
networks (including the traditional Internet).

[ https://en.wikipedia.org/wiki/Cjdns ]

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
How? And if it was that easy why isn't everyone using it?

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
Cjdns is a bit like Bitcoin. Everyone can generate their own 
network address using Public-key cryptography. And everyone can 
generate as many addresses as they like, just like everyone can 
generate as many Bitcoin addresses as they like. 
There's no central authority that assigns Cjdns network addresses.

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
And just like Bitcoin transactions, every Cjdns data packet must be 
cryptographically signed by it's owner (sender). And anyone who 
receives such a packet verifies it. This makes 'Man-in-the-middle' 
attacks very hard, if not practically impossible. It would require 
breaking Public-key cryptography.

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
In addition every Cjdns data packet is encrypted and can 
only be decrypted by the final receipient.

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
Nice! But where is the catch?

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
Actually there's none. Cjdns is compatible with the IPv6 protocol, 
so it can be used with regular Ethernet hardware and software. 
Like Bitcoin, all you need is an additional piece of FLOSS 
(Free/Libre Open Source Software). And Cjdns is FLOSS!

EOF
}

zhiverbox_cjdns_approach()
{
    press_any_key_for_new_screen
    display_alert "Install Cjdns" "https://github.com/cjdelisle/cjdns" ""
    echo ""
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
Cjdns ships pre-installed on every $PROJNAME already, 
so all we need to do now is:

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
  1. Install Cjdns on this computer here as well. This will 
     automatically generate a unique Cjdns address for your computer.
EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
  2. Generate a unique Cjdns address for your $PROJNAME - similar to 
     the GPG identity we created before.
EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
     (Yes, it would be nice if we could use the GPG private key for 
     Cjdns as well. But GPG uses RSA cryptography and Cjdns uses 
     ECC (Elliptic Curve Cryptography). Precisely Cjdns uses the 
     Edwards Curve Ed25519, which isn't officially supported by GPG 
     yet. Therefore we need two different private keys - 
     one for GPG and one for Cjdns.)
EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
  3. Put the Cjdns address of your $PROJNAME into the hosts file  
     (/etc/hosts) of this computer here. So you can easily connect to 
     your $PROJNAME through it's name, instead of typing-in the 
     long Cjdns address.
     
EOF
    press_any_key
}

get_local_ip4_addr()
{
    echo $($CMD_GET_LOCAL_IP4_ADDR)
}

get_local_cjd_addr()
{
    echo $(ip add | grep "inet6 fc" | awk '{ print $2 }' | sed 's/\/8//')
}

get_cjd_addr_from_config()
{
    echo $(cat $1 | grep "\"ipv6\":" | awk '{ print $2 }' | sed 's/"//g;s/,//g')
}

check_and_install_cjdns()
{
    display_alert "Checking for existing Cjdns" "systemctl status cjdns" ""
    local cjdns_status=$(systemctl status cjdns 2>&1 | head -2 | tail -1)
    echo $cjdns_status | sed "s/^/${SED_INTEND}/"
    if [[ -n $(echo $cjdns_status | grep "$SYSTEMCTL_NOTFOUND") ]]; then
        CJDNS_INSTALLED="no"
        display_alert "Cjdns is not installed yet" "" "wrn"
    else
        CJDNS_INSTALLED="yes"
        display_alert "Cjdns is already installed" "$(which cjdroute)" "info"
    fi
    
    echo ""
    
    [[ $CJDNS_INSTALLED == "no" ]] && install_cjdns
    
    display_alert "Your IPv4  address is:" "$(eval $CMD_GET_LOCAL_IP4_ADDR)" "info"
    display_alert "Your Cjdns address is:" "$(get_local_cjd_addr)" "info"
echo -e | sed "s/^/${SED_INTEND}/" << EOF
    
Notice - while your IPv4 address may change over time and traffic is not
encrypted - your Cjdns address is unique in our solar system and really 
is truely yours! No one else owns this address! And it's free of charge! 
A present from mathematics. :)

Now let's generate one for your $PROJNAME as well!
     
EOF
    press_any_key
    
    TMP_CJDCONF="$(mktemp -p /dev/shm/)"
    cjdroute --genconf >> $TMP_CJDCONF
    ZHIVERBOX_CJDADDR=$(get_cjd_addr_from_config $TMP_CJDCONF)
    display_alert "$PROJNAME Cjdns address:" "$ZHIVERBOX_CJDADDR" "info"
    echo ""
    press_any_key
    
	echo -e \
"Cjdns is near-zero-configuration: There is no pairing needed in your 
local network. Your computer and $PROJNAME will find each other 
automatically when they are in the same network. 
${RED}Exception:${NC} This doesn't apply to a 'guest OS' running inside 
Virtualbox, which will be in a different network than your $PROJNAME.
Hence, automatic Cjdns peering doesn't work in this case and additional
configuration is required.
" | sed "s/^/${SED_INTEND}/"
     
    press_any_key
echo -e | sed "s/^/${SED_INTEND}/" << EOF
Notice how all Cjdns addresses begin with 'fc'? This means they will
never be routed in the 'legacy' public Internet.

[ see: https://en.wikipedia.org/wiki/Unique_local_address ]
     
EOF
    press_any_key
    new_screen
    display_alert "Hyperboria - the global meshnet" "https://github.com/hyperboria" ""
echo -e | sed "s/^/${SED_INTEND}/" << EOF

However, Cjdns can be configured to connect to other local meshnets 
over the traditional Internet. Together they form a 'new' global
meshnet called 'Hyperboria'. Think of it as a new, secure Internet.

[ see: https://hyperboria.net/ and https://github.com/hyperboria ]
     
EOF
    press_any_key
echo -e | sed "s/^/${SED_INTEND}/" << EOF
Connecting your computer or your $PROJNAME to Hyperboria is beyond 
the scope of this installation process. You can do this later if 
you're interested. Have a look at the following document:

[ https://github.com/hyperboria/peers ]
     
EOF
}

install_cjdns()
{
    press_any_key_for_new_screen
    while [ ! $CJDNS_CHECKOUT_COMPLETE  ]
    do
        clone_or_update_from_github "cjdns" "https://github.com/cjdelisle/cjdns"
    done
    
    display_alert "Checking for additonal system packages to compile Cjdns source code" "build-essential, python2.7" ""
    check_package build-essential
    check_package python2.7
    
    # install cjdns according to https://github.com/cjdelisle/cjdns
    cd $SRC_HOME/cjdns
    display_alert "Build Cjdns:" "sudo -H -u $SUDO_USER NO_TEST=1 $TORIFY_CMD ./do" ""
    display_alert "Be patient. This will take some time..." "" ""
    sudo -H -u $SUDO_USER NO_TEST=1 $TORIFY_CMD ./do >> $INST_LOG 2>&1
    display_alert "$(tail -n1 $INST_LOG)" "" "info"
    echo "(see details: $INST_LOG)" | sed "s/^/${SED_INTEND}/"
    install -o root -g root -m 0755 ./cjdroute /usr/bin/cjdroute
    display_alert "$(sudo -H -u $SUDO_USER which cjdroute)" "which cjdroute" "ext"
    echo ""
    
    # copy service files
    display_alert "Install Cjdns as system service" "" ""
    install -o root -g root -m 0644 ./contrib/systemd/cjdns.service /etc/systemd/system/
    display_alert "Installed:" "/etc/systemd/system/cjdns.service" "info"
    install -o root -g root -m 0644 ./contrib/systemd/cjdns-resume.service /etc/systemd/system/
    display_alert "Installed:" "/etc/systemd/system/cjdns-resume.service" "info"
    echo ""
    
    # back to working directory
    cd $SRC
    
    # enable system service
    systemctl enable cjdns
    
    # start cjdns
    display_alert "Starting Cjdns system service" "systemctl start cjdns" ""
    systemctl start cjdns
    systemctl status cjdns | head -3
    echo ""
    
    display_alert "Cjdns installation complete" "" "info"
    press_any_key    
}

copy_cjdconf_to_target_image()
{
    cp $TMP_CJDCONF $MOUNT_DEST_ROOT/etc/cjdroute.conf
}

bitmessage_messaging_preface()
{
    press_any_key_for_new_screen
    display_alert "Distributed notifications:" "https://en.wikipedia.org/wiki/Bitmessage" ""
    echo ""
echo -e | sed "s/^/${SED_INTEND}/" << EOF
Do you wonder how your $PROJNAME will send you notifications?

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
Well, $PROJNAME could use 'e-mail', 'Telegram bots' 
(https://core.telegram.org/bots) or any other services
to conveniently notify you on your smartphone.

But all of these services rely on some centralized 'legacy Internet' 
services. $PROJNAME wouldn't deserve the words HIVE or mesh
networking if we wouldn't use a distributed and decentralized 
alternative for messages!?

Yes, we have one!

EOF
    press_any_key
        echo -e | sed "s/^/${SED_INTEND}/" << EOF
Bitmessage                                   

Bitmessage is a decentralized, encrypted, peer-to-peer, trustless 
communications protocol that can be used by one person to send 
encrypted messages to another person, or to multiple subscribers.

[ see: https://en.wikipedia.org/wiki/Bitmessage ]
[ see: https://bitmessage.org/wiki/Main_Page ]
[ see: https://github.com/Bitmessage/PyBitmessage ]

Let's install Bitmessage on your computer now!

EOF
    press_any_key
    check_and_install_bitmessage
    press_any_key_for_new_screen
    display_alert "Bitmessage installation complete." "$(which pybitmessage)" "ext"
    echo ""
    press_any_key
    
    ask_user_launch_bitmessage
    
    check_bitmessage_tor
    
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
Hint: You can also install Bitmessage on MacOS and Windows:
[ https://github.com/Bitmessage/PyBitmessage/releases ]

Or even on Android:
[ https://github.com/Dissem/Abit ]

EOF
    press_any_key
    echo -e "\e[0;31mPlease create a 'new identity' in the Bitmessage application now!\x1B[0m" | sed "s/^/${SED_INTEND}/"
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
$PROJNAME will send it's notifications to this address.
Use 'zhiverbox-messages' as the label for that account (identity)!

EOF
    press_any_key
    enter_confirm_bitmessageid
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
    
Note: It is discouraged to use that identity (address) for any
other uses (non $PROJNAME related). Please create additional 
identities (addresses) for each use case to protect your privacy!
You can create as many identities as you like - for free!

EOF
}

ask_user_launch_bitmessage()
{
    echo -e "\e[0;31mPlease start Bitmessage from your program launcher now!\x1B[0m\n" | sed "s/^/${SED_INTEND}/" 

    i=0
    while [[ ! $(pgrep pybitmessage) ]]; do
     
        [[ $i = 25 ]] && i=0 && printf '\r'
        [[ $i = 0 ]] && printf '         Waiting for pybitmessage running ...'
        printf '.';
        ((i++))
        sleep 3 
    done
    printf '\r'
    echo "pybitmessage seems to be running..." | sed "s/^/${SED_INTEND}/"
    echo ""
}

check_and_install_bitmessage()
{
    display_alert "Checking for existing pybitmessage" "which pybitmessage" ""
    local bitmessage_status=$(which pybitmessage)
    if [[ -z $bitmessage_status ]]; then
        BITMESSAGE_INSTALLED="no"
        display_alert "pybitmessage is not installed yet" "" "wrn"
    else
        BITMESSAGE_INSTALLED="yes"
        display_alert "pybitmessage is already installed" "$(which pybitmessage)" "info"
    fi
    
    [[ $BITMESSAGE_INSTALLED == "no" ]] && install_bitmessage
}

install_bitmessage()
{
    press_any_key_for_new_screen
    clone_or_update_from_github "PyBitmessage" "https://github.com/Bitmessage/PyBitmessage"
    
    display_alert "Checking for additonal system packages to compile bitmessage source code" "python python-msgpack python-qt4 python-pyopencl python-setuptools build-essential openssl libssl-dev git" ""
    # https://bitmessage.org/wiki/Compiling_instructions#Resolve_dependencies
    check_package python    
    check_package python-msgpack 
    check_package python-qt4
    check_package python-pyopencl 
    check_package python-setuptools
    check_package build-essential
    check_package openssl
    check_package libssl-dev
    check_package git
    
    # install PyBitmessage according to https://bitmessage.org/wiki/Compiling_instructions
    cd $SRC_HOME/PyBitmessage
    echo ""
    display_alert "Check dependencies:" "sudo -H -u $SUDO_USER $TORIFY_CMD python checkdeps.py" ""
    python checkdeps.py
    press_any_key
    display_alert "Install PyBitmessage:" "sudo -H -u $SUDO_USER $TORIFY_CMD python setup.py install" ""
    display_alert "Be patient. This will take some time..." "" ""
    python setup.py install >> $INST_LOG 2>&1
    display_alert "$(tail -n1 $INST_LOG)" "" "info"
    echo "(see details: $INST_LOG)" | sed "s/^/${SED_INTEND}/"
    echo ""
    display_alert "$(sudo -H -u $SUDO_USER which pybitmessage)" "which pybitmessage" "ext"
    
    # restart unity so bitmessage is shown in launcher
    #desktop-file-install --dir=~/.local/share/applications ./desktop/pyBitmessage.desktop
    desktop-file-install nofile.desktop &>/dev/null
    
    # back to working directory
    cd $SRC
}

check_bitmessage_tor()
{
    local bitmessage_keys_file=/home/$SUDO_USER/.config/PyBitmessage/keys.dat
    if [[ -f $bitmessage_keys_file ]]; then
        local bitmessage_has_tor=$(grep "socksport\s\+=\s\+9050" $bitmessage_keys_file)
        if [[ -z $bitmessage_has_tor ]]; then
            display_alert "Hint:  Enable Tor proxy in Bitmessage network settings to protect your privacy!" "type: SOCKS5 | hostname: localhost | port: 9050" "wrn"
            echo ""
            display_alert "This installer can configure Tor for your Bitmessage automatically!" "" ""
	        read -p "$UINPRFX Do you want to enable Tor? (y/n) [default: yes]" choice 
	        case "$choice" in 
	          n|N|no|NO ) echo "OK, not using Tor! But you can enable Tor manually any time" | sed "s/^/${SED_INTEND}/";
	                      echo "in the Bitmessage network settings." | sed "s/^/${SED_INTEND}/";;
	          * ) setup_bitmessage_tor;;
	        esac
	        echo ""
            press_any_key
        else
            display_alert "Your Bitmessage is already configured with Tor. Good!" "" "info"
            echo ""
        fi
    else
        display_alert "Bitmessage keys file doesn't exist!" "$bitmessage_keys_file" "err"
        display_alert "Please install Bitmessage first and launch it at least once!" "$bitmessage_keys_file" "err"
        echo ""
    fi
    
}

setup_bitmessage_tor()
{
    display_alert "We have to shutdown Bitmessage to enable Tor!" "pkill -1 pybitmessage" ""
    pkill -1 pybitmessage
    while [[ $(pgrep pybitmessage) ]]; do echo "Waiting for Bitmessage to stop ..."; sleep 3; done
    
    # make sure tor is installed
    display_alert "Make sure Tor software is installed ..." "" ""
    check_package tor
    display_alert "Make sure Tor service starts automatically ..." "systemctl enable tor" ""
    systemctl enable tor
    display_alert "Start Tor system service now ..." "systemctl start tor" ""
    systemctl start tor
    
    local bitmessage_keys_file=/home/$SUDO_USER/.config/PyBitmessage/keys.dat
    if [[ -f $bitmessage_keys_file ]]; then
        echo ""
        display_alert "Configure Tor for PyBitmessage in:" "$bitmessage_keys_file" ""
        sudo -u $SUDO_USER sed -i 's/^socksproxytype\s\+=.*/socksproxytype = SOCKS5/w /dev/stdout' $bitmessage_keys_file
        sudo -u $SUDO_USER sed -i 's/^sockshostname\s\+=.*/sockshostname = localhost/w /dev/stdout' $bitmessage_keys_file
        sudo -u $SUDO_USER sed -i 's/^socksport\s\+=.*/socksport = 9050/w /dev/stdout' $bitmessage_keys_file
        sudo -u $SUDO_USER sed -i 's/^socksauthentication\s\+=.*/socksauthentication = False/w /dev/stdout' $bitmessage_keys_file
        sudo -u $SUDO_USER sed -i 's/^sockslisten\s\+=.*/sockslisten = False/w /dev/stdout' $bitmessage_keys_file
        display_alert "PyBitmessage Tor setup complete." "" "info"
        echo ""
        press_any_key
    else
        echo ""
        display_alert "Bitmessage configuration file not found at default location:" "$bitmessage_keys_file" "err"
        display_alert "You have to configure Tor manually in Bitmessage network settings:" "type: SOCKS5 | hostname: localhost | port: 9050" "wrn"
        echo ""
        press_any_key
    fi
    ask_user_launch_bitmessage
    press_any_key
}

enter_confirm_bitmessageid()
{
	confirm_bitmessageid()
	{
	    display_alert "Your Bitmessage ID is:   " "$1" ""
		read -p "$UINPRFX Is this really correct? (y/n) " choice 
		case "$choice" in 
		  y|Y|yes|YES ) BITMSGID=$1; echo "Great! Your $PROJNAME will send all notifications to this address!" | sed "s/^/${SED_INTEND}/";;
		  * ) enter_bitmessageid;;
		esac
	}
	enter_bitmessageid()
	{
	    echo -e "\e[0;31m$UINPRFX Paste your Bitmessage ID (address) here!\x1B[0m" 
		read -p "$UINPRFX My Bitmessage Address:    " bitmsgid;
		case "$bitmsgid" in 
		  BM-* ) confirm_bitmessageid $bitmsgid;;
		  * ) echo "No valid bitmessage ID. Must start with 'BM-'" | sed "s/^/${SED_INTEND}/"; 
		      enter_bitmessageid;;
		esac
	}
	
	enter_bitmessageid
}

configuration_summary()
{
    press_any_key_for_new_screen
    display_alert "---------------------------------------------------------" "" ""
    display_alert "Configuration complete." "All requirements satisfied." "info"
    display_alert "---------------------------------------------------------" "" ""
    display_alert "$PROJNAME name:" "$ZHIVERBOX_NAME" "info"
    display_alert "$PROJNAME GPG fingerprint:" "$(parse_gpg_fingerprint $PROJNAME)" "info"
    display_alert "$PROJNAME GPG KEY ID:" "$GPG_KEY_ID" "info"
    display_alert "$PROJNAME Cjdns address:" "$ZHIVERBOX_CJDADDR" "info"
    display_alert "$PROJNAME notifications receipient:" "$BITMSGID" "info"
    display_alert "$PROJNAME Trezor integration:" "$([[ $USE_TREZOR == "yes" ]] && echo ENABLED || echo DISABLED)" "$([[ $USE_TREZOR == "yes" ]] && echo info || echo wrn)"
    display_alert "Build system summary:" "" ""
    display_alert "* $(uname -o 2> /dev/null)" "$(cat /etc/*-release | grep DISTRIB_DESCRIPTION | sed 's/^DISTRIB_DESCRIPTION=//')" "info"
    display_alert "* sha256sum" "$(sha256sum --version 2> /dev/null | head -n1)" "info"
    display_alert "* losetup" "$(losetup --version 2> /dev/null | head -n1)" "info"
    display_alert "* crpytsetup" "$(cryptsetup --version 2> /dev/null | head -n1)" "info"
    display_alert "* btrfs" "$(btrfs --version 2> /dev/null | head -n1)" "info"
    display_alert "* partprobe" "$(partprobe --version 2> /dev/null | head -n1)" "info"
    display_alert "* $CMD_GPG" "$($CMD_GPG --version 2> /dev/null | grep GnuPG)" "info"
    display_alert "* libgcrypt (GnuPG)" "$($CMD_GPG --version 2> /dev/null | grep libgcrypt)" "info"
    display_alert "* nmap" "$(nmap --version 2> /dev/null | grep version)" "info"

    if [[ $USE_TOR == "yes" ]]; then
        display_alert "* tor" "$(tor --version 2> /dev/null | grep version)" "info"
    fi

    if [[ $USE_TREZOR == "yes" ]]; then
        display_alert "* libagent (Trezor)" "$(pip3 show libagent 2> /dev/null | grep Version)" "info"
        display_alert "* trezorctl (Trezor)" "$(pip3 show trezor 2> /dev/null | grep Version)" "info"
        display_alert "* trezor-agent (Trezor)" "$(pip3 show trezor-agent 2> /dev/null | grep Version)" "info"
    fi
    display_alert "---------------------------------------------------------" "" ""
    echo ""
}

check_trezor_gpg_init() {
	# check if trezor-gpg is initialized
	TMP_GNUPGHOME=$SUDO_HOME/.gnupg/trezor
        GPGENV=$SUDO_HOME/.gnupg/trezor/env
        if [ ! -d "$SUDO_HOME/.gnupg/trezor" ]; then 
            echo "trezor-agent is installed, but no GPG identity initialized"
	else
	    display_alert "Trezor GPG agent seems to be installed and initialized" "$TMP_GNUPGHOME" "info"
            display_alert "Listing available public keys" "$CMD_GPG --list-keys" ""
            sudo -u $SUDO_USER $GPGENV $CMD_GPG --list-keys | sed "s/^/${SED_INTEND}/"
            display_alert "Showing configured default key" "$TMP_GNUPGHOME/gpg.conf" ""
            sudo -u $SUDO_USER grep "default" $TMP_GNUPGHOME/gpg.conf | sed "s/^/${SED_INTEND}/"
	fi
}

select_verify_source_image()
{
    # select the source image to customize
    cd $SRC
    echo "" && press_any_key_for_new_screen
    display_alert "---------------------------------------------------------" "" ""
    display_alert "Begin $PROJNAME image customization" "" "info"
    display_alert "---------------------------------------------------------" "" ""
    echo ""
    select_source_image
    echo ""
    display_alert "Calculating the SHA256 hash of the $PROJNAME image file." "sha256sum" ""
    SOURCE_IMAGE_HASH=$(sha256sum $IMAGE_FILE)
    echo ""
    echo -e -n "\e[7m" | sed "s/^/${SED_INTEND}/"
    echo $SOURCE_IMAGE_HASH | awk '{ print $1 }' 
    echo -e -n "\e[27m"
    echo $SOURCE_IMAGE_HASH | awk '{ print $2 }' | sed "s/^/${SED_INTEND}/"
    echo ""
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
Did you build this source image yourself?
Or did you just download it via the traditional Internet? 

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
If you downloaded a copy, you MUST take the extra effort to verify this
image hash! Else you might be victim of a Man-in-the-middle attack: 

[ https://en.wikipedia.org/wiki/Man-in-the-middle_attack ]

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
Your whole $PROJNAME security absolutely depends on the correctness of 
this source image hash!!!

EOF
    press_any_key
    confirm_image_hash
}

select_source_image()
{
    echo -e "\e[0;31mSelect the $PROJNAME source image file you want to install\x1B[0m"
    
    if [[ -d ./output/images ]]; then
    	local imagedir=./output/images
    else
    	local imagedir=$(pwd)
    fi
    
    local imgcount=$(find $imagedir -maxdepth 1 -type f -name "*.img.src" 2>/dev/null | wc -l)
    if [[ $imgcount > 0 ]]; then
    	echo "$imagedir"
        PS3="> Select number: " 
        select IMAGE_FILE in $imagedir/*.img.src;
        do
	        echo "" && display_alert "Using $PROJNAME source image file" "$IMAGE_FILE" "ext"
	        break
        done
    else
    	display_alert "No source image found in:" "$imagedir" "err"
    	echo -e \
"Please copy the source image file (*.img.src) into the same directory as this installer script:
$imagedir
"
		press_any_key
		select_source_image
    fi
    
    find_partitions
}

find_partitions()
{
    local partitions=$(partprobe -s $IMAGE_FILE | sed 's/.*partitions //')
    if [[ $partitions == "1 2" ]]; then
        BOOTPART=1
        ROOTPART=2
    else
        echo ""
        display_alert "The selected image doesn't seem to be a $PROJNAME image" "" "err"
        select_source_image
    fi
}

confirm_image_hash()
{
	read -p "$UINPRFX Type 'yes' when you have verified the SHA256 hash! " choice
	case "$choice" in 
	  yes|YES ) echo "";;
	  * ) confirm_image_hash;;
	esac
}

copy_unlock_images()
{	
	# make a copy of the source image
	SRC_IMAGE_FILE=$1
	DEST_IMAGE_NAME=$ZHIVERBOX_NAME.img
	display_alert "Creating a copy of the source image" "dd if=$1 of=$TMP_BUILD_DIR/$DEST_IMAGE_NAME" ""
	dd if=$SRC_IMAGE_FILE of=$TMP_BUILD_DIR/$DEST_IMAGE_NAME status=progress
	DEST_IMAGE=$TMP_BUILD_DIR/$DEST_IMAGE_NAME
	echo ""
	press_any_key
	
	# mount the source rootfs image	read-only
	LOOP_SRC=$(losetup -f)
	losetup -r $LOOP_SRC $SRC_IMAGE_FILE
	#display_alert "$(losetup -a $LOOP_SRC)" "" ""
	display_alert "Scan source image for partitions" "partprobe -s $LOOP_SRC" ""
	display_alert "$(partprobe -s $LOOP_SRC)" "" "info"
	display_alert "Check source partition #$ROOTPART for LUKS" "cryptsetup isLuks ${LOOP_SRC}p${ROOTPART}" ""
	cryptsetup isLuks ${LOOP_SRC}p${ROOTPART} && IS_LUKS=true && display_alert "LUKS container found on source partition $ROOTPART" "" "info"
	SRC_LUKS_UUID=$(cryptsetup luksUUID "${LOOP_SRC}p${ROOTPART}")
	#MOUNT_SRC_ROOT="$TMP_BUILD_DIR/mnt/src-${PROJNAME}/_root"
	#mkdir -p $MOUNT_SRC_ROOT
	#SRC_ROOT_MAPPER="src_${PROJNAME}_root"
	#cryptsetup luksOpen --key-file $TMP_BUILD_DIR/sourcepass "${LOOP_SRC}p${ROOTPART}" SRC_ROOT_MAPPER #&& mount -o ro /dev/mapper/SRC_ROOT_MAPPER $MOUNT_SRC_ROOT
    
    echo ""
    
	# create mountpoint for destination rootfs image
	LOOP_DEST=$(losetup -f)
	losetup $LOOP_DEST $DEST_IMAGE
	#display_alert "$(losetup -a $LOOP_DEST)" "" ""
	display_alert "Scan destination image for partitions" "partprobe -s $LOOP_DEST" ""
	display_alert "$(partprobe -s $LOOP_DEST)" "" "info"
	display_alert "Check target partition #$ROOTPART for LUKS" "cryptsetup isLuks ${LOOP_DEST}p${ROOTPART}" ""
	cryptsetup isLuks ${LOOP_DEST}p${ROOTPART} && IS_LUKS=true && display_alert "LUKS container found on destination partition $ROOTPART" "" "info"
	MOUNT_DEST_ROOT="$TMP_BUILD_DIR/mnt/dest-${ZHIVERBOX_NAME}/_root"
	mkdir -p $MOUNT_DEST_ROOT
	
	echo ""
}

check_connect_trezor()
{
	local RETRY_MESSAGE="Connect the Trezor to this computer here! Not to the $PROJNAME!"
	read -p "Is your Trezor connected? Ready to continue (y/n)? " choice
	case "$choice" in 
	  y|Y ) [[ -n "$(trezorctl list)" ]] && (echo "Detected the following Trezor devices:" && trezorctl list && echo "") || (echo -e "\e[0;31mNo Trezor device detected! $RETRY_MESSAGE\x1B[0m" && check_connect_trezor);;
	  * ) echo -e "\e[0;31mWell, then please connect your Trezor now! $RETRY_MESSAGE\x1B[0m" && check_connect_trezor;;
	esac
}

show_confirm_passphrase()
{
	confirm_disclaimer_noted()
	{
		read -p "Type 'yes' when you are ready to continue! " choice
		case "$choice" in 
		  yes|YES ) echo "" && echo -e "\e[5mYour $PROJNAME root filesystem passphrase is:\e[25m" && echo -e "\e[104m$1\e[49m" && echo "";;
		  * ) confirm_disclaimer_noted "$1";;
		esac
	}
	confirm_passphrase_noted()
	{
		read -p "Type 'yes' in UPPERCASE when you have written down your passphrase! " choice
		case "$choice" in 
		  YES ) echo "";;
		  * ) confirm_passphrase_noted;;
		esac
	}
	
	# display disclaimer text
	display_alert "\e[0;31mATTENTION: You will be shown your '$PROJNAME root filesystem passphrase' now.\x1B[0m" "Please read carefully below!" ""
	echo -e -n "\e[101m"
	echo -e "This passphrase is called the 'cryptroot passphrase' and will only be shown once now and never again!!!" | sed "s/^/${SED_INTEND}/"
	echo -e "You will have to enter this passphrase every time you (re)boot your $PROJNAME!" | sed "s/^/${SED_INTEND}/"
	echo -e "Make sure to \e[1mwrite it down\e[21m on paper or save it in a \e[1msecure and encrypted place\e[21m like the 'Trezor Password Manager'!!!" | sed "s/^/${SED_INTEND}/"
	echo -e "* More information: https://doc.satoshilabs.com/trezor-user/passwordmanager.html" | sed 's/^/             /'
	echo -e "\x1B[0m"
	confirm_disclaimer_noted "$1"
	confirm_passphrase_noted
}

reencrypt_using_trezor_entropy()
{
	# unfortunately cryptsetup-reencrypt doesn't support the --master-key-file option, 
	# so we have to create a new LUKS container using Trezor provided entropy and 
	# copy the data from the old container to the new container
	
	# ask user to connect his Trezor now
	echo ""
	echo -e "\e[0;31mPlease connect your Trezor device to this computer now!\x1B[0m"
	check_connect_trezor

	# create a new LUKS container with Trezor support for entropy
	
	# first generate a secure passphrase using Trezor	
	display_alert "Creating a new secure LUKS passphrase using entropy from the Trezor." "trezorctl get_entropy 32" ""
	echo -e "\e[0;31mPlease check the display of your Trezor and press 'Confirm'!\x1B[0m"
	mkfifo $TMP_BUILD_DIR/trezor-entropy
	trezorctl get_entropy 32 > $TMP_BUILD_DIR/trezor-entropy &
	NEW_PASSPHRASE=$(encodeBase58 $(cat $TMP_BUILD_DIR/trezor-entropy))
	display_alert "Success! Generated new secure passphrase using Trezor." "" "ext"
	show_confirm_passphrase "$NEW_PASSPHRASE"
	
	# create a named pipe for the passphrase
	mkfifo $TMP_BUILD_DIR/passphrase
	echo -n "$NEW_PASSPHRASE" > $TMP_BUILD_DIR/passphrase &
	
	# pipe entropy from Trezor into named pipe
	display_alert "Creating a new secure LUKS volume master key using entropy from the Trezor." "trezorctl get_entropy 4096" ""
	trezorctl get_entropy 4096 > $TMP_BUILD_DIR/trezor-entropy &

	# encrypt partition via named pipes for passphrase and master key
	display_alert "\e[0;31mEncrypting $PROJNAME root partition with a new volume key now...\x1B[0m" "" ""
	
	echo "cryptsetup luksFormat -h sha512 -s 512 --uuid=$SRC_LUKS_UUID --master-key-file=$TMP_BUILD_DIR/trezor-entropy --key-file=$TMP_BUILD_DIR/passphrase ${LOOP_DEST}p${ROOTPART}"
	echo -e "\e[0;31mPlease check the display of your Trezor and press 'Confirm'!\x1B[0m"
	# we need to use the same uuid, else initramfs won't find the configured (in boot.ini) root device anymore
	cryptsetup luksFormat -v -q -h sha512 -s 512 --uuid=$SRC_LUKS_UUID --master-key-file=$TMP_BUILD_DIR/trezor-entropy --key-file=$TMP_BUILD_DIR/passphrase ${LOOP_DEST}p${ROOTPART}
	echo ""
	cryptsetup luksDump ${LOOP_DEST}p${ROOTPART}

	# copy data from the source container to the destination container
	display_alert "Copy data to the destination $PROJNAME root partition." "dd if=/dev/mapper/SRC_ROOT_MAPPER of=/dev/mapper/dest_zhiverbox-${GPG_KEY_ID}_root" ""
	echo -n "$NEW_PASSPHRASE" | cryptsetup luksOpen ${LOOP_DEST}p${ROOTPART} dest_zhiverbox-${GPG_KEY_ID}_root -
	dd if=/dev/mapper/SRC_ROOT_MAPPER of=/dev/mapper/dest_zhiverbox-${GPG_KEY_ID}_root status=progress	
}

reencrypt_preface()
{
    press_any_key_for_new_screen
    display_alert "Reencrypt $PROJNAME root partition" "" ""
        echo -e | sed "s/^/${SED_INTEND}/" << EOF
        
What is happening now? Why are we re-encrypting?

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
The $PROJNAME source image already contains 2 partitions:
 
  1. The 1st partition (boot) has a small boot system
  2. The 2nd partition (root) has the actual operating system

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
There is a reason for this split: We want the operating system (root)
to be fully encrypted. So when somebody removes the SD card from the 
$PROJNAME and puts it into another computer, they can't manipulate the 
operating system, because they don't know the decryption key.

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
However, the $PROJNAME hardware can't boot from an encrypted partition 
directly. You somehow have to enter the decryption key first.
Therefore, the boot partition contains an unencrypted mini-Linux
- called initramfs - whose only purpose is to allow the input of the 
decryption key for the actual operating system.

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
The used disk encryption mechanism is called LUKS:
[ see: https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup ]

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
The $PROJNAME source image has LUKS encryption already pre-setup. But 
since a source image might be downloaded by many people, everybody 
would share the same encryption key. Flashing this source image as-is 
on the SD card would be totally pointless from a security perspective!

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
So to guarantee your $PROJNAME having a unique encryption key - also 
called 'LUKS volume key' - we have to generate one now and re-encrypt 
the whole root partition using that new key.

EOF
    press_any_key
    echo -e | sed "s/^/${SED_INTEND}/" << EOF
That's what happens next. You will create a personalized copy of the 
$PROJNAME source image which only you will be able to decrypt!

EOF
    press_any_key
}

reencrypt_using_kernel_entropy()
{
    press_any_key_for_new_screen
	display_alert "Re-encrypting root partition" "cryptsetup-reencrypt" ""
	echo ""
	press_any_key
	echo -e | sed "s/^/${SED_INTEND}/" << EOF
We will now re-encrypt the whole root partition of the target image 
with a new key. This key is generated using entropy (randomness) 
from your computer.

EOF
    press_any_key
    display_alert "We will use aes-xts-plain64 because the zHIVErbox CPU (Exynos 5422) has hardware support for it since kernel 4.14.18-106" "" ""
    display_alert "See:" "https://magazine.odroid.com/article/secure-storage-creating-encrypted-file-system-linux/" ""
    display_alert "See:" "https://wiki.odroid.com/odroid-xu4/software/disk_encryption" ""
    display_alert "XTS has some potential weakness, but we're using btrfs so should be fine." "" ""
    display_alert "See:" "https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS_weaknesses" ""
    press_any_key
    local cryptopts="--cipher aes-xts-plain64 -s 512 -h sha512"
    display_alert "Start:" "cryptsetup-reencrypt $cryptopts ${LOOP_DEST}p${ROOTPART}" ""
    echo -n "............................................." | sed "s/^/${SED_INTEND}/"
    printf '\r'
	cryptsetup-reencrypt $cryptopts ${LOOP_DEST}p${ROOTPART} --key-file $TMP_BUILD_DIR/sourcepass >> $INST_LOG
	cryptsetup luksDump ${LOOP_DEST}p${ROOTPART} >> $INST_LOG 2>&1
	echo ""
	display_alert "The $ZHIVERBOX_NAME root partition is now ecrypted with a new unique volume key!" "" "ext"
	echo ""
	press_any_key
	echo -e | sed "s/^/${SED_INTEND}/" << EOF
This 'volume key' is quite long. We don't even show it to you for 
security reasons! Instead, the key is protected with a passphrase. 
However, the passphrase is usually the weakest point. You can have 
the the best encryption algorithm in the world and dismantle it by
using a weak passphrase.

Ideally, the passphrase should be completely random and have the 
same entropy as the LUKS volume key. The human brain is really bad 
at choosing / inventing passphrases, therefore we'll generate a 
random one using kernel entropy.

EOF
    press_any_key
    display_alert "Generate passphrase" "encodeBase58 \$(dd if=/dev/urandom count=1 2>/dev/null | sha256sum -b | awk '{print \$1}')" ""
    local luks_pass=$(encodeBase58 $(dd if=/dev/urandom count=1 2>/dev/null | sha256sum -b | awk '{print $1}'))
    echo -e -n "\e[7m" | sed "s/^/${SED_INTEND}/"
    echo $luks_pass  
    echo -e -n "\e[27m"
    echo ""
    display_alert "You don't have to use this passphrase, it's just a suggestion. But we STRONGLY ENCOURAGE you to use a similar strong one (256 bit)." "" "wrn"
    echo ""
	press_any_key
	display_alert "\e[0;31mPlease enter a strong passphrase to encrypt your LUKS volume key!\x1B[0m" "cryptsetup luksChangeKey ${LOOP_DEST}p${ROOTPART}" ""
	# luksChangeKey doesn't automatically repeat (--tries) if the passphrase doesn't match
	# so we have to take care of that
	local success=false
	local errorfile=$TMP_BUILD_DIR/luksChangeKey.error
	while [[ $success = false ]]; do
	    cryptsetup luksChangeKey ${LOOP_DEST}p${ROOTPART} --key-file $TMP_BUILD_DIR/sourcepass 2>$errorfile
	    if [[ -s $errorfile ]]; then
	        cat $errorfile
	        echo ""
	    else
	        success=true
	    fi
	done
	display_alert "The passphrase for unlocking the $ZHIVERBOX_NAME root file system was changed!" "" "ext"
	echo ""
	press_any_key
	display_alert "Make sure to \e[0;31mremember your passphrase\x1B[0m or use a secure Password Manager! You need it \e[0;31mevery time you (re-)boot\x1B[0m the $PROJNAME!" "" "wrn"
	echo ""
	press_any_key
	display_alert "If you ever forget this passphrase, your $PROJNAME cannot be booted anymore!" "" "wrn"
	echo ""
	press_any_key
	display_alert "Let's test your passphrase before we continue!" "" ""
	after_reencrypt_mount_dest_root
}

after_reencrypt_mount_dest_root()
{
    DEST_ROOT_MAPPER="dest_${ZHIVERBOX_NAME}_root"
	display_alert "Unlocking root partition" "cryptsetup luksOpen ${LOOP_DEST}p${ROOTPART} $DEST_ROOT_MAPPER" ""
	cryptsetup luksOpen ${LOOP_DEST}p${ROOTPART} $DEST_ROOT_MAPPER
    mount /dev/mapper/$DEST_ROOT_MAPPER $MOUNT_DEST_ROOT
    echo ""
    echo "$ ls _root"
    ls $MOUNT_DEST_ROOT
    echo ""
    press_any_key
}

after_reencrypt_move_keys()
{
    press_any_key_for_new_screen
    display_alert "Copy secret keys to $ZHIVERBOX_NAME root partition" "GPG Cjdns" ""
        echo -e | sed "s/^/${SED_INTEND}/" << EOF
        
Now that we have a secure root partition, we can move all the
secret keys we previously generated for the $PROJNAME onto it.

EOF
    press_any_key
    after_reencrypt_move_gpg_key
    echo ""
    after_reencrypt_move_cjdns_key
    echo ""
}

after_reencrypt_move_gpg_key()
{
    display_alert "Move GPG key to $ZHIVERBOX_NAME root" "" ""
    cp -r $TMP_GNUPGHOME $MOUNT_DEST_ROOT/root/.gnupg
    display_alert "Moved GPG key to $ZHIVERBOX_NAME root" "/root/.gnupg/" "ext"
    ls -la $MOUNT_DEST_ROOT/root/.gnupg/
}

after_reencrypt_move_cjdns_key()
{
    display_alert "Move Cjdns key to $ZHIVERBOX_NAME root" "" ""
    cp $TMP_CJDCONF $MOUNT_DEST_ROOT/etc/cjdroute.conf
    display_alert "Moved Cjdns key to $ZHIVERBOX_NAME root" "/etc/cjdroute.conf" "ext"
    ls -la $MOUNT_DEST_ROOT/etc/cjdroute.conf
}

setup_ssh_key_preface()
{
	press_any_key_for_new_screen
	display_alert "Move SSH public key to $ZHIVERBOX_NAME root" "/etc/zhiverbox/id_ssh_user.pub" ""
	echo -e | sed "s/^/${SED_INTEND}/" << EOF
$PROJNAME relies on public key authentication for SSH. Regular password
logins into your $PROJNAME are disabled. You can either use an existing
SSH key or we'll generate a new one now.

EOF
	
	read -p "$UINPRFX Do you have an existing SSH key? (y/n) [default: no] " choice 
    case "$choice" in 
      y|Y|yes|YES ) ask_copy_ssh_keypair;;
      * ) create_new_ssh_keypair;;
    esac
    echo ""
    select_copy_ssh_public_key
}

create_new_ssh_keypair()
{
	sshkeygencmd="sudo -u $SUDO_USER ssh-keygen -t ecdsa -b 384"
	display_alert "Generating new SSH key pair using kernel entropy..." "$sshkeygencmd" ""
	echo -e | sed "s/^/${SED_INTEND}/" << EOF
We'll use ECDSA, because ED25519 is not supported by dropbear/initramfs
(yet).
EOF
	
	# ssh-keygen asks for the filename, but if the user doesn't enter an absolute
	# path the key is created in the current working directory.
	# let's catch this case and change into ~/.ssh before the command	
	cd $SUDO_HOME/.ssh
	$sshkeygencmd
	cd $SRC
	
	echo ""
	press_any_key
}

ask_copy_ssh_keypair()
{
	display_alert "Copy ssh keys to ~/.ssh/" "" ""
	echo -e | sed "s/^/${SED_INTEND}/" << EOF
Please copy your existing SSH key to your ~/.ssh/ folder of this 
computer. If you are not planning to login from this computer, you only 
need to copy the public key (.pub extension) now. But if you want to 
connect to your $PROJNAME using this computer here, you need to copy 
both - the private key (usually starting with 'id_' and no file 
extension) and the corresponding public key (usually the same file name 
as the private key plus the '.pub' extension).

EOF
	press_any_key
	
}

select_copy_ssh_public_key()
{
	echo -e "\e[0;31mSelect the SSH public key you want to copy to your $PROJNAME\x1B[0m"
	select SSHPUBKEY in /home/$SUDO_USER/.ssh/*.pub;
    do
	    echo "" && display_alert "SSH authentication on $PROJNAME root system will done against:" "$SSHPUBKEY" "ext"
	    mkdir $MOUNT_DEST_ROOT/etc/zhiverbox 2>/dev/null
	    cp $SSHPUBKEY $MOUNT_DEST_ROOT/etc/zhiverbox/
	    
	    # enable public key for root account
	    mkdir $MOUNT_DEST_ROOT/root/.ssh 2>/dev/null
	    cat $SSHPUBKEY > $MOUNT_DEST_ROOT/root/.ssh/authorized_keys
	    
	    # disable password of root account
	    #sed -i 's/^root:/root:::0:99999:7:::/' $MOUNT_DEST_ROOT/etc/shadow
	    
	    # disable password authentication
	    display_alert "Disabling SSH password authentication for all accounts..." "$MOUNT_DEST_ROOT/etc/ssh/sshd_config" ""
	    sed -i 's/^.*PasswordAuthentication\s.*$/PasswordAuthentication no/' $MOUNT_DEST_ROOT/etc/ssh/sshd_config
	    break
    done
    display_alert "Later you will be able to login to the $PROJNAME root system via" "ssh root@<$PROJNAME IP ADDRESS>" "ext"
    echo ""
    press_any_key
}

extract_default_dropbear_ssh_key()
{
	# extract the SSH key needed to login to the boot system (initial ram disk with dropbear)
	display_alert "Extracting the SSH key for the $PROJNAME boot system (initramfs)" "" ""
	
	mkdir ~/.ssh 2> /dev/null && chown $SUDO_USER:users ~/.ssh
	cp $MOUNT_DEST_ROOT/etc/dropbear-initramfs/id_ecdsa ~/.ssh/id_zhiverbox_boot_default && chown $SUDO_USER:users ~/.ssh/id_zhiverbox_boot_default
	
	# add key to ssh config so ssh client will try to use is it autmatically
	# TODO
	
	display_alert "Copied SSH key to local system." "cp $MOUNT_DEST_ROOT/etc/dropbear-initramfs/id_ecdsa ~/.ssh/id_zhiverbox_boot_default" "info"
	display_alert "Later you will be able to login to the $PROJNAME boot system via" "ssh -p 2222 root@<$PROJNAME IP ADDRESS>" "ext"
	press_any_key
	display_alert "You should learn/write down this command!"
	echo ""
	press_any_key
}

after_reencrypt_set_hostname()
{
    # set hostname lower case
    echo -n ${ZHIVERBOX_NAME,,} > $MOUNT_DEST_ROOT/etc/hostname
}

dropbear_preface()
{
    press_any_key_for_new_screen
}

parse_gpg_fingerprint() 
{
    local fingerprint=$($CMD_GPG --fingerprint $1 | sed '2q;d' | sed 's/.*=//')
    echo $fingerprint
}

parse_gpg_fingerprint_no_spaces() 
{
    echo $(parse_gpg_fingerprint $1 | sed 's/ //g')
}

create_gpg_identity()
{
    # Create a new unique GPG identity for this customized $PROJNAME image.
    #
    # Since the $PROJNAME is running autonomously we sometimes need to notify the owner of the $PROJNAME about
    # events / state changes (e.g. updates) via insecure / untrusted communication channels (e.g. email). 
    # Therefore, all messages originating from the $PROJNAME must be cyptographically signed so the user can
    # verify the authenticity of those messages. We'll use GPG (GnuPG) to sign those messages.
    # 
    # However, a password for the GPG private key doesn't make sense as the $PROJNAME is no human. 
    # Why? For an autonomous instance like the $PROJNAME, the private key itself is already "the password".
    # If the GPG private key would have an additional password, this password would have to be stored 
    # on the $PROJNAME as well - side by side with the private key. Ergo we can skip it and rely on the fact 
    # that the $PROJNAME root file system - where the private key resides - is encrypted and can only be 
    # read/accessed by the $PROJNAME root user. A password wouldn't add any more security in this case.
    #
    # To create the GPG identity, we'll use a temp directory in the memory (/dev/shm) of the host system.
    # This prevents that the private key (which doesn't have a password) is written to any persistent memory
    # on the host used to create the $PROJNAME image. The private key will be copied into the customized
    # image at the end of the creationg process and deleted from the memory of the host again. As a result,
    # the private key should only exist within the encrypted $PROJNAME image after this customization process
    # and not on the host anymore nor anywhere else.
    #
    # Why isn't the GPG identity just created during the first boot of the $PROJNAME? 
    # For convenience!
    # 1. We can easily export a copy of the public key on the host system already right now and don't
    #    have to wait until the first boot - after which it is more complicated to retrieve the public key
    #    via SSH (SCP) or USB and copy it back to the workstation of the user. It would be possible but a 
    #    lot more complicated.
    #    Whereas by creating the GPG key now on the host system, the user setting up the $PROJNAME already 
    #    has a copy of the public key on his workstation. We just have to take extra care, that the
    #    passwordless private key is not leaked and persisted after the end of this installation script!
    #    Therefore we use a temporary TMP_GNUPGHOME directory in the shared memory (/dev/shm) of the host.
    # 2. We can use the GPG key fingerprint (key ID) as a verifyable identifier for:
    #    * The filename of the resulting customized image file
    #    * The hostname of the $PROJNAME instance the user sees when he is logged-in via SSH
    
    press_any_key_for_new_screen
    display_alert "We will now generate a secret GPG key for your $PROJNAME." "" ""
echo -e | sed "s/^/${SED_INTEND}/" << EOF

Why? What is that needed for?   

EOF
    press_any_key
echo -e | sed "s/^/${SED_INTEND}/" << EOF
GPG alias GnuPG alias 'GNU Privacy Guard' is a 
free software suite for cryptography.
[ see: https://en.wikipedia.org/wiki/GNU_Privacy_Guard ]

EOF
    press_any_key
echo -e | sed "s/^/${SED_INTEND}/" << EOF
Your $PROJNAME will use GPG to digitally sign all messages / 
notifications it sents to you. So you can be sure (verify) 
a message was really sent from your $PROJNAME and not by 
someone else to trick you.

EOF
    press_any_key
echo -e | sed "s/^/${SED_INTEND}/" << EOF
GPG requires a secret key which is only stored on your $PROJNAME.
This secret key is also called 'private key'.
We will generate this secret key now using entropy (randomness) 
from your computer.

EOF
    press_any_key
    
    # https://www.gnupg.org/documentation/manuals/gnupg-devel/Unattended-GPG-key-generation.html#Unattended-GPG-key-generation
    TMP_GNUPGHOME="$(mktemp -d -p /dev/shm/)"
    export GNUPGHOME=$TMP_GNUPGHOME
    
# Curve25519 (ed25519) doesn't seem to be supported in batch mode (unattended key generation) yet
cat >$TMP_BUILD_DIR/gpgkeyconf << EOF
     %echo Generating a default key without passphrase for $PROJNAME root user
#    Key-Type: EDDSA
     Key-Type: default
#    Key-Usage: sign
#    Subkey-Type: ed25519
     Name-Real: $PROJNAME
#    Name-Comment: 
#    Name-Email: none
     Expire-Date: 0
#    Passphrase: none
     %no-protection # don't use a passphrase
     # Do a commit here, so that we can later print "done" :-)
     %commit
     %echo done
EOF
    display_alert "Generating GPG identity for your $PROJNAME" "$CMD_GPG --batch --full-gen-key $TMP_BUILD_DIR/gpgkeyconf" ""
echo -e | sed "s/^/${SED_INTEND}/" << EOF

Attention: 
If you run this script too often in a row, GPG key generation might 
suck your system out of precious entropy! If this happens, this step 
will hang until your system has collected enough entropy again!

EOF
    display_alert "Entropy before: $(cat /proc/sys/kernel/random/entropy_avail) byte" "cat /proc/sys/kernel/random/entropy_avail" "ext"
    display_alert "GPG key generation" "STARTED" ""

    $CMD_GPG --batch --gen-key $TMP_BUILD_DIR/gpgkeyconf >> $INST_LOG 2>&1
    $CMD_GPG --list-secret-keys >> $INST_LOG 2>&1

    display_alert "GPG key generation" "FINISHED" "info"
    display_alert "Entropy after: $(cat /proc/sys/kernel/random/entropy_avail) byte" "cat /proc/sys/kernel/random/entropy_avail" "ext"
    echo ""
     
    local fingerprint=$(parse_gpg_fingerprint $PROJNAME)
    local fingerprint_ns=$(parse_gpg_fingerprint_no_spaces $PROJNAME)
    #echo "$fingerprint -> $(encodeBase58 $fingerprint | cut -c1-6)"
    # get the key id (last 8 chars of the fingerprint)
    GPG_KEY_ID=$(echo $fingerprint_ns | cut -c33-40)
    
    press_any_key_for_new_screen
    display_alert "The GPG fingerprint of your $PROJNAME is:" "$fingerprint" "info"
    echo ""
    press_any_key
echo -e | sed "s/^/${SED_INTEND}/" << EOF
This is not the secret key! Just the fingerprint of the corresponding 
'public key'. The public key is quite long. Too long for humans to 
handle. That's why the fingerprint is usually shown instead. 
The public key (and it's fingerprint) does not need any special 
protection. That's why it's called 'public'. Like your name.

If you want to learn more about Public-key cryptography, have a look at 
Wikipedia: [ https://en.wikipedia.org/wiki/Public-key_cryptography ]

EOF
    press_any_key
echo -e | sed "s/^/${SED_INTEND}/" << EOF
The GPG KEY ID are the last 8 numerics of the fingerprint.
Yes, those letters are also numerics! Hexadecimal numerics!

[ see: https://en.wikipedia.org/wiki/Hexadecimal ]

EOF
    display_alert "The GPG KEY ID of your $PROJNAME is:" "$GPG_KEY_ID" "info"
    make_default_device_name
    echo ""
    press_any_key
echo -e | sed "s/^/${SED_INTEND}/" << EOF
This is still not the secret key! And we will never display the 
secret key. Ever! Never ever! 
The secret key is securely stored on your $PROJNAME.  

EOF
    press_any_key
echo -e | sed "s/^/${SED_INTEND}/" << EOF
But this short GPG KEY ID - you can write down! It helps you to 
identify your $PROJNAME later. You'll see it quite often. 
We use it a lot. So write it down!

EOF
}

make_default_device_name()
{
    ZHIVERBOX_NAME="${PROJNAME,,}-${GPG_KEY_ID,,}"
}

change_device_name()
{
    press_any_key_for_new_screen
    display_alert "The name of your $PROJNAME will be:" "$ZHIVERBOX_NAME" "info"
    echo ""
    display_alert "If you want to change that name (not recommended) you can do so now." "" "wrn"
echo -e | sed "s/^/${SED_INTEND}/" << EOF
The name is used for easy identification in case you have 
multiple ${PROJNAME}es:
  * filename of your personalized, re-encrypted $PROJNAME image file
  * hostname (shown in login shell)
  * matches the GPG KEY ID used to sign messages sent to you

EOF
    read -p "$UINPRFX Do you want to change the name (y/n)? [default: no] " choice
    case "$choice" in 
      y|Y|yes|YES ) read -p "$UINPRFX $PROJNAME name: " name;;
      * ) ;;
    esac
    echo ""
    [[ ! -z $name ]] && ZHIVERBOX_NAME=$name
    display_alert "Your $PROJNAME will have the following name:" "$ZHIVERBOX_NAME" "info"
    echo ""
    press_any_key
}

after_reencrypt_change_fs_labels()
{
    # ext4 label can be 16 chars at most
    e2label ${LOOP_DEST}p${BOOTPART} boot-${GPG_KEY_ID,,}
    display_alert "Changed the ext4 label of boot partition." "e2label ${LOOP_DEST}p${BOOTPART} boot-${GPG_KEY_ID,,}" "info"
    btrfs filesystem label $MOUNT_DEST_ROOT cryptroot-${ZHIVERBOX_NAME,,}
    display_alert "Changed the btrfs label of cryptroot partition." "btrfs filesystem label $MOUNT_DEST_ROOT cryptroot-${ZHIVERBOX_NAME,,}" "info"
}

gpg_export_public_key()
{
    # export public key to build directory
    $CMD_GPG --armor --export $PROJNAME > $TMP_BUILD_DIR/$ZHIVERBOX_NAME.asc
    cp $TMP_BUILD_DIR/$ZHIVERBOX_NAME.asc $TMP_GNUPGHOME
    display_alert "Export GPG public key" "$CMD_GPG --armor --export $PROJNAME > $ZHIVERBOX_NAME.asc" "ext"
}

sign_initramfs()
{
    echo ""
    display_alert "Creating digital signature of the $ZHIVERBOX_NAME boot partition (initramfs)." "$CMD_GPG --detach-sig ${LOOP_DEST}p1 --output $DEST_IMAGE.boot.sig" ""
	$CMD_GPG --output $DEST_IMAGE.boot.sig --detach-sig ${LOOP_DEST}p1
}

sign_final_image()
{
    echo ""
    display_alert "Creating digital signature of the $ZHIVERBOX_NAME image." "$CMD_GPG --output $DEST_IMAGE.sig --detach-sig $DEST_IMAGE" ""
	$CMD_GPG --output $DEST_IMAGE.sig --detach-sig $DEST_IMAGE
}

add_cjdaddr_to_hosts()
{
    echo ""
    display_alert "Adding Cjdns address of $ZHIVERBOX_NAME to:" "/etc/hosts" ""
    # make lower case ${a,,}
    echo "$ZHIVERBOX_CJDADDR    ${ZHIVERBOX_NAME,,}" >> /etc/hosts
    echo "$ZHIVERBOX_CJDADDR    ${ZHIVERBOX_NAME,,}" >> $TMP_BUILD_DIR/$ZHIVERBOX_NAME.cjdhost
}

sign_initramfs_using_trezor()
{
	confirm_disclaimer_noted()
	{
		read -p "$UINPRFX Type 'yes' when you are aware of Evil-Maid-Attacks and ready to continue! " choice
		case "$choice" in 
		  yes|YES ) display_alert "Evil-Maid-Attack awareness:" "CONFIRMED" "info";;
		  * ) confirm_disclaimer_noted "$1";;
		esac
	}
	display_alert "Calculating the SHA256 hash of the $PROJNAME boot system (initramfs)." "sha256sum ${LOOP_DEST}p1" ""
        echo -e "\e[7m"
        sha256sum ${LOOP_DEST}p1
        echo -e "\e[27m"
	display_alert "You certainly want to write down (print) this hash value on paper and put it somewhere safe!" "" "wrn"
	display_alert "Why? The $PROJNAME (Odroid HC-1 / HC-2) doesn't have a 'Secure Boot' feature." "" "wrn"
        display_alert "This is unfortunate and allows for potential Evil-Maid-Attacks:" "https://en.wikipedia.org/wiki/Evil_Maid_attack" "wrn"
        display_alert "Summary: Depending on your environment - it might be possible for someone" "" "wrn"
        display_alert "to compromize the $PROJNAME boot system while you are away." "" "wrn"
        display_alert "The attacker needs to shutdown the $PROJNAME so you are forced" "" "wrn"
        display_alert "to enter the disk password again. This will look like a normal power outage to you." "" "wrn"
        display_alert "Eventually, a sophisticated Evil-Maid-Attack is even prepared without a shutdown of the $PROJNAME" "" "wrn"
        display_alert "and the attacker just waits until you restart the $PROJNAME yourself." "" "wrn"
        display_alert "To counter this attack, you should always verify the hash of the boot partition first, " "" "wrn"
        display_alert "when your $PROJNAME was restarted or shutdown and turned-on again." "" "wrn"
        display_alert "Only enter your disc encryption password after you verified" "" "wrn"
	display_alert "that the hash of the boot partition didn't change!!!" "" "wrn"
	display_alert "-----------------------" "" ""
	display_alert "Verification procedure:" "" ""
	display_alert "   1. When you notice your $PROJNAME is turned off or was restarted: Turn it off!" "Turn $PROJNAME off!" "wrn"
	display_alert "   2. When you restarted the $PROJNAME yourself: Turn it off!" "Turn $PROJNAME off!" "wrn"
	display_alert "   3. Eject the SD-Card and put it into this computer again." "Remove SD-Card from $PROJNAME!" ""
	display_alert "   4. Run the $PROJNAME verification script:" "zHIVErbox-verify-boot-system.sh" ""
	display_alert "   5. Compare the hash value from step 4 with the hash value you wrote down on paper." "Verify with your eyes!" ""
	display_alert "  6a. If the hash value is different now, you should consider the boot system compromized and DON'T BOOT!" "DON'T BOOT $PROJNAME!" "err"
	display_alert "   6b. If the hash value didn't change, you can put the SD-Card into the $PROJNAME again and boot normally." "Boot $PROJNAME!" "info"
	display_alert "Unfortunately, there's a catch! The hash value of the boot system can change INTENTIONALLY through certain system updates!" "DRAWBACK" "wrn"
	display_alert "So how do you tell the difference between an Evil-Maid-Attack and a system update you didn't notice?" "DRAWBACK" "wrn"
	display_alert "Solution: $PROJNAME will send you secure (digitally signed) emails containing the new hash value" "Signed E-Mail" "info"
	display_alert "when the boot system was intentionally updated. But you have to verify the authenticity of the email." "Signed E-Mail" "info"
	display_alert "-----------------------" "" ""
	display_alert "In the future, there will hopefully be cheap 'Secure Boot' hardware for $PROJNAME." "" ""
	echo ""
        confirm_disclaimer_noted
	echo ""

        display_alert "Creating digital signature of the $PROJNAME boot system (initramfs)." "$CMD_GPG --detach-sig ${LOOP_DEST}p1 --output $DEST_IMAGE.boot.sig" ""
	$CMD_GPG --output $DEST_IMAGE.boot.sig --detach-sig ${LOOP_DEST}p1
	display_alert "" "" ""
	
	
        #gpg agent for trezor doesn't exist yet
	#sudo -u $SUDO_USER trezor-gpg init
	
}

show_donation_address()
{
	echo ""
    display_alert "Your donation to $PROJNAME" "via bitcoin (BTC)" "todo"

	echo -e \
"                                                                             
\e[30;107m           bitcoin: 36eNEA54cf7RSDKKp8RvGc1r4D8Ze2hMdJ           \e[0m
\e[30;107m                                                                 \e[0m
\e[30;107m   ██████████████   █████   █               █   ██████████████   \e[0m
\e[30;107m   ██          ██  ███████          █   ████    ██          ██   \e[0m
\e[30;107m   ██  ██████  ██  ███ ████   █   ██████████    ██  ██████  ██   \e[0m
\e[30;107m   ██  ██████  ██  ████  ██     ██████ ███      ██  ██████  ██   \e[0m
\e[30;107m   ██  ██████  ██             ████ ██           ██  ██████  ██   \e[0m
\e[30;107m   ██          ██   █     █████████   █████     ██          ██   \e[0m
\e[30;107m   ██████████████  ██   ██ ███ ███  █  ███  █   ██████████████   \e[0m
\e[30;107m                     ██     █   ██    ██  ████                   \e[0m
\e[30;107m   ███      █████         █   █████   ████████    █   ████████   \e[0m
\e[30;107m   ██        ███    ██████  █            ███  █   ████           \e[0m
\e[30;107m   ████████    ██  ███    ████████████████    ████████  ██   █   \e[0m
\e[30;107m      ████ ██      ██   ████ ███   █████  ████   ███  ██    ██   \e[0m
\e[30;107m   █   ██  ██   █  ██  ███ █████  █       ██  █   ██████████     \e[0m
\e[30;107m     ██    ██      ██        █████  █   ██        ████ ████ ██   \e[0m
\e[30;107m   ██████       █████████         ████████      ██ █████    ██   \e[0m
\e[30;107m   ██████     █    ███      █   ████ ███  █   ████   ███   █     \e[0m
\e[30;107m    █████████  ██    ██   █   ████    ██████  ██  █   ██████     \e[0m
\e[30;107m   █████████ ██     █  ██   █     ██████ ███        ██████████   \e[0m
\e[30;107m         ████  ██  ████  ███████████ ███      █   ██████  ████   \e[0m
\e[30;107m         ████        ██   ██ ███ ██   ██                         \e[0m
\e[30;107m   ██████████   ███  ██    █████  █         █████████            \e[0m
\e[30;107m                   ██████    █████  ███     ██     ███  ██████   \e[0m
\e[30;107m   ██████████████      ██         ████    ████  █   ████  ████   \e[0m
\e[30;107m   ██          ██   █  ███  █   ███████    ███      ██    ███    \e[0m
\e[30;107m   ██  ██████  ██  ██     █   ██████ ███  ████████████           \e[0m
\e[30;107m   ██  ██████  ██       █   █    ████   ████████        ██   █   \e[0m
\e[30;107m   ██  ██████  ██     █  █████████████████   ████         ████   \e[0m
\e[30;107m   ██          ██   █     ██ ███   █████████████    ███   ████   \e[0m
\e[30;107m   ██████████████  ██      █████   ███████ ██████   ████  ███    \e[0m
\e[30;107m                                                                 \e[0m
\e[30;107m           bitcoin: 36eNEA54cf7RSDKKp8RvGc1r4D8Ze2hMdJ           \e[0m
" | sed "s/^/${SED_INTEND}/"
	echo -e \
"If you like the $PROJNAME tools, please send a small donation to 
our ${ORANGE}bitcoin address${NC} shown above. We'd like to continue building 
user friendly, open source Cypherpunk tools for everybody. 
${BOLD}Thank you for your support!${NC}
" | sed "s/^/${SED_INTEND}/"
}

scan_local_network()
{
	display_alert "Scan your local network for the IP address of your $PROJNAME" "" "todo"
	echo -e \
"The $PROJNAME installer assumes there is a DHCP server present in your 
local network, which automatically assigns an IP address to your 
$ZHIVERBOX_NAME's boot system.

As mentioned earlier, we can't use Cjdns to connect to the boot system 
unfortunately. Cjdns is only available once the root system is running.
We'll have to scan your local network to find the IP address of your 
$PROJNAME. 
" | sed "s/^/${SED_INTEND}/"
	display_alert "Listing local networks" "ip route list" ""
	echo ""
	ip route list | sed "s/^/${SED_INTEND}/"
	echo ""
	local guess_network=$(ip route list proto kernel | head -n1 | awk '{print $1}')
	read -p "$UINPRFX Please enter your local network address range: " -e -i $guess_network networkrange
	echo ""
	local nmapcmd="nmap -sn $networkrange"
	display_alert "Scanning network..." "nmap -sn $networkrange" ""
	$nmapcmd | sed "s/^/${SED_INTEND}/"
	echo ""
	local arpcmd="arp -a | grep 00:1e:06"
	display_alert "Detecting Odroid devices..." "$arpcmd" ""
	arp -a | grep 00:1e:06 | sed "s/^/${SED_INTEND}/"
	if [[ -z $? ]]; then
		display_alert "No Odroids detected in your local network." "" "err"
		display_alert "Please make sure your computer is in the same network as your $PROJNAME." "" "todo"
		echo -e \
"Manually re-run the following commands to scan for Odroids:
1. ${ORANGE}nmap -sn $networkrange${NC}
2. ${ORANGE}$arpcmd${NC}

Alternatively find out the IP address of you $PROJNAME via your 
DHCP server (router). They usually have a web interface.
" | sed "s/^/${SED_INTEND}/"
	fi
	echo ""
	press_any_key
	
	echo -e \
"Once you know the IP address of your $PROJNAME you can connect via:

1. ${ORANGE}ssh root@<IP_ADDRESS> -p 2222${NC} (boot system)
2. ${ORANGE}ssh root@<IP_ADDRESS>        ${NC} (root system)
" | sed "s/^/${SED_INTEND}/"
	
	press_any_key
}

#--------------------------------------------------------------------------------------------------------------------------------
# Script execution
#--------------------------------------------------------------------------------------------------------------------------------

# clean the log file
echo "" >> $INST_LOG

# check disk space
check_disk_space

# make sure we are root
make_root

# we're root now but sometimes need the user who started this
SUDO_HOME=$(eval echo ~$SUDO_USER)

# source directory for 3rd party sources (github.com)
SRC_HOME="$SUDO_HOME/.local/src"

# show the introduction screens
introduction

# show and request the Bitcoin-Non-Consensus-Fork agreement
bncf_agreement

# check host os
check_host_os && host_os_configuration

# check required packages
check_req_apt_packages

# create GPG keypair
create_gpg_identity

# allow to change device name
change_device_name
gpg_export_public_key

# configure notifications receipient
bitmessage_messaging_preface

# cjdns installation
cjdns_networking_preface
cjdns_solution
zhiverbox_cjdns_approach
check_and_install_cjdns

# optional enable Trezor hardware wallet integration
optional_enable_trezor_integration

# show configuration summary
configuration_summary

# begin image customization
select_verify_source_image

# reencryption explanation
reencrypt_preface

# prepare the target image
copy_unlock_images $IMAGE_FILE

if [[ $IS_LUKS ]]; then
	if [[ $USE_TREZOR == "yes" ]]; then
		reencrypt_using_trezor_entropy
	else 
		reencrypt_using_kernel_entropy
	fi
else
	display_alert "No LUKS container found on partition $ROOTPART. Are you sure you selected a $PROJNAME image?" "" "err"
	exit $?
fi

# change the label of the cryptroot
after_reencrypt_change_fs_labels

# move keys to target partition
after_reencrypt_move_keys
setup_ssh_key_preface

# extract SSH key for initramfs
extract_default_dropbear_ssh_key

# set hostname
after_reencrypt_set_hostname

# show and sign the initramfs hash
#sign_initramfs_using_trezor

# sign initramfs before unmounting
sign_initramfs

# unmount images
umount_images

# copy final image
cp $DEST_IMAGE .
chown $SUDO_USER:users ./$DEST_IMAGE_NAME

# sign final image and boot partition
sign_final_image

# copy signatures
cp $TMP_BUILD_DIR/*.sig .
chown $SUDO_USER:users ./*.sig

# copy gpg public key file
cp $TMP_BUILD_DIR/*.asc .
chown $SUDO_USER:users *.asc

# add cjdns address to /etc/hosts
add_cjdaddr_to_hosts
cp $TMP_BUILD_DIR/*.cjdhost .
chown $SUDO_USER:users *.cjdhost

echo ""
press_any_key

# customization complete
echo ""
clear
display_alert "$PROJNAME image customization complete!" "$SRC/$DEST_IMAGE_NAME" "ext"
echo ""
display_alert "Flash this image to a SD card with Etcher now!" "https://etcher.io/" "todo"
echo ""
press_any_key
display_alert "When finished flashing, put the SD card into the Odroid and power it." "" "todo"
echo -e \
"Once the boot system is ready, the blue LED will keep double blinking.
" | sed "s/^/${SED_INTEND}/"
press_any_key

# help the user finding his zHIVErbox
scan_local_network

# copy log file
cp $INST_LOG ./$DEST_IMAGE_NAME.log
chown $SUDO_USER:users ./$DEST_IMAGE_NAME.log
