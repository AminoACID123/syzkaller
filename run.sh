qemu-system-x86_64 \
-m 2048 \
-smp 2 \
-serial stdio \
-serial unix:/tmp/bt-server-bredr \
-no-reboot \
-name VM-0 \
-device virtio-rng-pci \
-enable-kvm \
-cpu host,migratable=off \
-device e1000,netdev=net0 \
-netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:6857-:22 \
-hda /home/xaz/Documents/syzkaller/tools/stretch.img \
-snapshot \
-kernel /home/xaz/Documents/linux-5.4/arch/x86_64/boot/bzImage \
-append "root=/dev/sda console=ttyS0" \
