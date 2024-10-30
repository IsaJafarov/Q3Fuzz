#!/bin/bash

# During fuzzing, sometimes other services randomly start and cause high CPU usage polluting our logs

sudo systemctl stop unattended-upgrades
sudo systemctl disable unattended-upgrades
sudo sed -i 's/"1"/"0"/g' /etc/apt/apt.conf.d/20auto-upgrades

sudo apt purge -y command-not-found

sudo systemctl stop packagekit
sudo systemctl disable packagekit

sudo systemctl stop fwupd
sudo systemctl disable fwupd