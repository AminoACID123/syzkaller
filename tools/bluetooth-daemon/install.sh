#!/bin/sh

cd btd; make; cd ..

if [ ! -d /bin/btd/ ]; then
    mkdir /bin/btd
fi

cp btd/btd /bin/btd/


cp btd-systemd/btd-env /bin/btd
cp btd-systemd/btd.service /etc/systemd/system/

chmod 644 /etc/systemd/system/btd.service

systemctl enable btd
