/* Mount a composefs image with lcfs_mount_image(), the way C consumers
 * such as ostree-prepare-root do. Used by the privileged integration
 * tests to exercise the Rust libcomposefs.
 *
 * Usage: lcfs-mount-test [-d DIGEST] [-u UPPERDIR -w WORKDIR [-r]] IMAGE MOUNTPOINT OBJDIR
 *
 * The mount is read-only unless there's an upper directory; -r makes it
 * read-only then too.
 *
 * On failure, prints the error and exits with errno as the status, so
 * callers can check which error the library reported.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libcomposefs/lcfs-mount.h>

int main(int argc, char **argv)
{
	struct lcfs_mount_options_s options = { 0 };
	const char *objdirs[1];
	bool readonly = false;
	int opt;

	options.idmap_fd = -1;
	options.flags = LCFS_MOUNT_FLAGS_READONLY;
	while ((opt = getopt(argc, argv, "d:u:w:r")) != -1) {
		switch (opt) {
		case 'd':
			options.expected_fsverity_digest = optarg;
			break;
		case 'u':
			options.upperdir = optarg;
			options.flags &= ~LCFS_MOUNT_FLAGS_READONLY;
			break;
		case 'w':
			options.workdir = optarg;
			break;
		case 'r':
			readonly = true;
			break;
		default:
			fprintf(stderr, "usage: %s [-d DIGEST] [-u UPPERDIR -w WORKDIR [-r]] IMAGE MOUNTPOINT OBJDIR\n",
				argv[0]);
			return 2;
		}
	}
	if (readonly)
		options.flags |= LCFS_MOUNT_FLAGS_READONLY;
	if (argc - optind != 3) {
		fprintf(stderr, "expected IMAGE MOUNTPOINT OBJDIR\n");
		return 2;
	}

	objdirs[0] = argv[optind + 2];
	options.objdirs = objdirs;
	options.n_objdirs = 1;
	if (lcfs_mount_image(argv[optind], argv[optind + 1], &options) < 0) {
		int errsv = errno;
		fprintf(stderr, "lcfs_mount_image: %s\n", strerror(errsv));
		return errsv;
	}
	return 0;
}
