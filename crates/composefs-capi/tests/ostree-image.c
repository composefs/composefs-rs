/* SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0 */
/*
 * Build an EROFS image the way ostree does (see ostree_repo_checkout_composefs()
 * in ostree's src/libostree/ostree-repo-composefs.c): regular files have a
 * payload of "xx/<checksum>.file" pointing into the bare repo, with an fsverity
 * digest only when verity is enabled, and empty files have no payload.
 *
 * This is linked into the composefs-capi tests, which pin the image's digest,
 * and built standalone (with -DOSTREE_IMAGE_MAIN, writing the image to stdout)
 * against both the C libcomposefs and ours to compare the output.
 */
#define _GNU_SOURCE

#include "lcfs-writer.h"
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OSTREE_OBJ_A "8a/5d74a2f8e3c1a0b9d7e6f5c4b3a2918070605040302010f0e0d0c0b0a09087.file"
#define OSTREE_OBJ_B "e3/b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.file"
/* The composefs object path of the digest below */
#define DIGEST_OBJ "03/0a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc"

static ssize_t write_fd_cb(void *file, void *buf, size_t count)
{
	return write(*(int *)file, buf, count);
}

static struct lcfs_node_s *add_node(struct lcfs_node_s *parent,
				    const char *name, uint32_t mode, uint64_t size)
{
	struct lcfs_node_s *node = lcfs_node_new();
	if (node == NULL)
		return NULL;
	if (lcfs_node_add_child(parent, node, name) != 0) {
		lcfs_node_unref(node);
		return NULL;
	}
	lcfs_node_set_mode(node, mode);
	lcfs_node_set_uid(node, 0);
	lcfs_node_set_gid(node, 0);
	lcfs_node_set_size(node, size);
	return node;
}

/* Returns 0 on success, or -1 with errno set. */
int write_ostree_image(int fd)
{
	static const char selinux_bin[] = "system_u:object_r:bin_t:s0";
	static const char selinux_lib[] = "system_u:object_r:lib_t:s0";
	uint8_t digest[LCFS_DIGEST_SIZE];
	struct lcfs_node_s *root, *usr, *bin, *lib, *node;
	int r = -1;

	for (size_t i = 0; i < sizeof(digest); i++)
		digest[i] = (uint8_t)(i * 7 + 3);

	root = lcfs_node_new();
	if (root == NULL)
		return -1;
	lcfs_node_set_mode(root, S_IFDIR | 0755);

	if ((usr = add_node(root, "usr", S_IFDIR | 0755, 0)) == NULL)
		goto out;
	if ((bin = add_node(usr, "bin", S_IFDIR | 0755, 0)) == NULL)
		goto out;
	if ((lib = add_node(usr, "lib", S_IFDIR | 0755, 0)) == NULL)
		goto out;

	/* A file with verity enabled: payload and digest are independent */
	if ((node = add_node(bin, "bash", S_IFREG | 0755, 1432144)) == NULL)
		goto out;
	if (lcfs_node_set_payload(node, OSTREE_OBJ_A) != 0)
		goto out;
	lcfs_node_set_fsverity_digest(node, digest);
	if (lcfs_node_set_xattr(node, "security.selinux", selinux_bin,
				sizeof(selinux_bin)) != 0)
		goto out;

	/* A file without verity: only the payload */
	if ((node = add_node(lib, "libfoo.so.1", S_IFREG | 0644, 8193)) == NULL)
		goto out;
	if (lcfs_node_set_payload(node, OSTREE_OBJ_B) != 0)
		goto out;
	if (lcfs_node_set_xattr(node, "security.selinux", selinux_lib,
				sizeof(selinux_lib)) != 0)
		goto out;

	/* Not from ostree: a digest without a payload, which gets no redirect */
	if ((node = add_node(lib, "verity-only", S_IFREG | 0644, 4097)) == NULL)
		goto out;
	lcfs_node_set_fsverity_digest(node, digest);

	/* Not from ostree: the usual composefs layout, payload = digest's path */
	if ((node = add_node(lib, "object", S_IFREG | 0644, 5000)) == NULL)
		goto out;
	if (lcfs_node_set_payload(node, DIGEST_OBJ) != 0)
		goto out;
	lcfs_node_set_fsverity_digest(node, digest);

	/* An empty file has no payload */
	if (add_node(lib, "empty", S_IFREG | 0644, 0) == NULL)
		goto out;

	if ((node = add_node(bin, "sh", S_IFLNK | 0777, strlen("bash"))) == NULL)
		goto out;
	if (lcfs_node_set_payload(node, "bash") != 0)
		goto out;

	struct lcfs_write_options_s options = { 0 };
	options.format = LCFS_FORMAT_EROFS;
	options.version = 0;
	options.max_version = 1;
	options.file = &fd;
	options.file_write_cb = write_fd_cb;
	r = lcfs_write_to(root, &options);

out:
	lcfs_node_unref(root);
	return r;
}

#ifdef OSTREE_IMAGE_MAIN
int main(void)
{
	return write_ostree_image(STDOUT_FILENO) == 0 ? 0 : 1;
}
#endif
