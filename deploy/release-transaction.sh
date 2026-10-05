#!/usr/bin/env bash
# restore host integration after a failed release activation

# keep maintenance host files in the same activation transaction as the application
MAINTENANCE_ARTIFACTS=(
    '/etc/systemd/system/adsb-maintenance.service|adsb-maintenance.service'
    '/etc/systemd/system/adsb-maintenance.timer|adsb-maintenance.timer'
    '/etc/systemd/system/apt-daily.timer.d/adsb-weekly.conf|apt-daily-weekly.conf'
    '/etc/systemd/system/apt-daily-upgrade.timer.d/adsb-weekly.conf|apt-upgrade-weekly.conf'
    '/etc/apt/apt.conf.d/52unattended-upgrades-adsb|52unattended-upgrades-adsb'
)

# preserve one host file or record its prior absence
backup_activation_file() {
    local rollback_dir=$1
    local source=$2
    local label=$3
    # copy existing state without following a managed link
    if [[ -e "$source" || -L "$source" ]]; then
        cp -a -- "$source" "$rollback_dir/$label"
    else
        touch "$rollback_dir/$label.absent"
    fi
}

# restore one host file to its exact pre-activation state
restore_activation_file() {
    local rollback_dir=$1
    local destination=$2
    local label=$3
    rm -f -- "$destination"
    # replace the prior file when one existed
    if [[ -e "$rollback_dir/$label" || -L "$rollback_dir/$label" ]]; then
        cp -a -- "$rollback_dir/$label" "$destination"
    fi
}

# snapshot every live integration file before pointer selection
backup_activation_files() {
    local root=$1
    local rollback_dir=$2
    backup_activation_file "$rollback_dir" "$root/etc/adsb/admin.env" admin.env
    backup_activation_file "$rollback_dir" "$root/etc/adsb/runtime.json" runtime.json
    backup_activation_file "$rollback_dir" "$root/usr/local/sbin/adsb-stack" adsb-stack
    backup_activation_file "$rollback_dir" "$root/etc/sudoers.d/adsb-stack" sudoers
    backup_activation_file "$rollback_dir" "$root/etc/systemd/system/adsb-admin.service" adsb-admin.service
    backup_activation_file "$rollback_dir" "$root/etc/systemd/system/adsb-controller.service" adsb-controller.service
    backup_activation_file "$rollback_dir" "$root/etc/systemd/system/adsb-alerts.service" adsb-alerts.service
    # retain every weekly scheduling and update-policy file
    for artifact in "${MAINTENANCE_ARTIFACTS[@]}"; do
        backup_activation_file "$rollback_dir" "$root${artifact%%|*}" "${artifact##*|}"
    done
}

# restore pointers and host files after post-staging failure
rollback_activation() {
    local root=$1
    local rollback_dir=$2
    local current_code=$3
    local previous_map=$4
    local legacy_layout=$5
    local app_release=$6
    local map_release=$7
    local current_link="$root/opt/adsb/current"
    local map_link="$root/opt/adsb/map-ui"
    # restore or remove the application pointer
    if [[ -n "$current_code" && "$legacy_layout" != true ]]; then
        rm -f -- "$current_link.rollback"
        ln -s "$current_code" "$current_link.rollback"
        mv -Tf "$current_link.rollback" "$current_link"
    else
        rm -f -- "$current_link"
    fi
    # restore or remove the compatibility map pointer
    if [[ -n "$previous_map" ]]; then
        rm -f -- "$map_link.rollback"
        ln -s "$previous_map" "$map_link.rollback"
        mv -Tf "$map_link.rollback" "$map_link"
    else
        rm -f -- "$map_link"
    fi
    restore_activation_file "$rollback_dir" "$root/etc/adsb/admin.env" admin.env
    restore_activation_file "$rollback_dir" "$root/etc/adsb/runtime.json" runtime.json
    restore_activation_file "$rollback_dir" "$root/usr/local/sbin/adsb-stack" adsb-stack
    restore_activation_file "$rollback_dir" "$root/etc/sudoers.d/adsb-stack" sudoers
    restore_activation_file "$rollback_dir" "$root/etc/systemd/system/adsb-admin.service" adsb-admin.service
    restore_activation_file "$rollback_dir" "$root/etc/systemd/system/adsb-controller.service" adsb-controller.service
    restore_activation_file "$rollback_dir" "$root/etc/systemd/system/adsb-alerts.service" adsb-alerts.service
    # restore prior timer schedules and security policy before reloading units
    for artifact in "${MAINTENANCE_ARTIFACTS[@]}"; do
        restore_activation_file "$rollback_dir" "$root${artifact%%|*}" "${artifact##*|}"
    done
    rm -rf -- "$app_release" "$map_release"
}
