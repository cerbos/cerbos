#!/bin/sh
# Modified from https://nfpm.goreleaser.com/tips/#prepost-installremoveupgrade-scripts

SERVICE_PATH=/etc/systemd/system
SERVICE_NAME=cerbos

systemd_version=0
if command -V systemctl >/dev/null 2>&1; then
    systemd_version=$(systemctl --version | head -1 | sed 's/systemd //g')
else
    printf "\033[32m Systemd not found. Currently only systemd is supported.\033[0m\n"
    exit 1
fi


cleanInstall() {
    # rhel/centos7 cannot use ExecStartPre=+ to specify the pre start should be run as root
    # even if you want your service to run as non root.
    if [ "${systemd_version}" -lt "231" ]; then
        printf "\033[31m systemd version %s is less then 231, fixing the service file \033[0m\n" "${systemd_version}"
        sed -i "s/=+/=/g" ${SERVICE_PATH}/${SERVICE_NAME}.service
    fi
    printf "\033[32m Reload the service unit from disk\033[0m\n"
    systemctl daemon-reload ||:
    printf "\033[32m Unmask the service\033[0m\n"
    systemctl unmask $SERVICE_NAME ||:
    printf "\033[32m Set the preset flag for the service unit\033[0m\n"
    systemctl preset $SERVICE_NAME ||:
    printf "\033[32m Set the enabled flag for the service unit\033[0m\n"
    systemctl enable $SERVICE_NAME ||:
    systemctl restart $SERVICE_NAME ||:
}

upgrade() { 
    systemctl daemon-reload ||:
    systemctl restart $SERVICE_NAME
}


# Step 2, check if this is a clean install or an upgrade
action="$1"
if  [ "$1" = "configure" ] && [ -z "$2" ]; then
  # Alpine linux does not pass args, and deb passes $1=configure
  action="install"
elif [ "$1" = "configure" ] && [ -n "$2" ]; then
    # deb passes $1=configure $2=<current version>
    action="upgrade"
fi

case "$action" in
  "1" | "install")
    cleanInstall
    ;;
  "2" | "upgrade")
    upgrade
    ;;
  *)
    # $1 == version being installed  
    printf "\033[32m Alpine\033[0m"
    cleanInstall
    ;;
esac

