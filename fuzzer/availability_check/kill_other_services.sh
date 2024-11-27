#!/bin/bash

# During fuzzing, sometimes other services randomly start and cause high CPU usage polluting our logs

sudo systemctl stop unattended-upgrades; sudo systemctl disable unattended-upgrades
sudo sed -i 's/"1"/"0"/g' /etc/apt/apt.conf.d/20auto-upgrades

sudo apt purge -y command-not-found

sudo systemctl stop packagekit; sudo systemctl disable packagekit

sudo systemctl stop fwupd; sudo systemctl disable fwupd

sudo systemctl stop man-db.service; sudo systemctl disable man-db.service

apt-get remove -y ubuntu-release-upgrader-core

sudo systemctl stop snapd.service; sudo systemctl disable snapd.service
sudo systemctl stop snapd.socket; sudo systemctl disable snapd.socket

sudo apt remove -y landscape-common

sudo systemctl stop cron.service; sudo systemctl disable cron.service

sudo systemctl stop apt-daily-upgrade.service; sudo systemctl disable apt-daily-upgrade.service

sudo systemctl stop ufw.service; sudo systemctl disable ufw.service

# for cloud-id processes
sudo systemctl stop cloud-init; sudo systemctl disable cloud-init
sudo systemctl stop cloud-init-local; sudo systemctl disable cloud-init-local

sudo systemctl stop apt-*; sudo systemctl disable apt-*
sudo systemctl stop motd-news.*; sudo systemctl disable motd-news.*
