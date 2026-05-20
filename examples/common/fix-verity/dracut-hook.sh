# dracut hook for fixing fs-verity on composefs sysroot
mount -o remount,rw /sysroot
(
  cd /sysroot/composefs
  echo >&2 'Enabling fsverity on composefs objects'
  for i in objects/*/*; do
      fsverity enable "$i"
  done
  echo >&2 'Enabling fsverity on meta.json'
  fsverity enable meta.json
  echo >&2 'done!'
)
umount /sysroot
sync
poweroff -ff
