#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *const destination = "/Library/PrivilegedHelperTools/dev.prismroute.installer";
static int trusted_directory(const char *path) {
    struct stat s;
    return lstat(path, &s) == 0 && S_ISDIR(s.st_mode) && s.st_uid == 0 && !(s.st_mode & 0022);
}

/* The system tool copies data only; never execute a user-owned file as root. */
static int run_system_tool(AuthorizationRef auth, const char *tool, char *const args[]) {
    FILE *pipe = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    OSStatus status = AuthorizationExecuteWithPrivileges(auth, tool, kAuthorizationFlagDefaults, args, &pipe);
#pragma clang diagnostic pop
    if (status != errAuthorizationSuccess || !pipe) return -1;
    char buf[512];
    for (;;) {
        ssize_t n = read(fileno(pipe), buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { fclose(pipe); return -1; }
        if (n == 0) break;
    }
    fclose(pipe);
    return 0; /* Verify the result; this API does not return child exit status. */
}

static int remove_temporary_installer(AuthorizationRef auth) {
    if (!trusted_directory("/Library/PrivilegedHelperTools")) return -1;
    char *args[] = {"-f", (char *)destination, NULL};
    if (run_system_tool(auth, "/bin/rm", args) != 0) return -1;
    struct stat meta;
    return lstat(destination, &meta) < 0 && errno == ENOENT ? 0 : -1;
}

static int verified_protected_installer(const char *expected) {
    struct stat before, after, named;
    int fd = open(destination, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_uid != 0 || before.st_nlink != 1 ||
        (before.st_mode & 0022) || !(before.st_mode & 0111) || before.st_size < 1024 || before.st_size > 268435456) { close(fd); return 0; }
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    char buffer[16384];
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { close(fd); return 0; }
        if (!n) break;
        CC_SHA256_Update(&context, buffer, (CC_LONG)n);
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &context);
    int valid = fstat(fd, &after) == 0 && lstat(destination, &named) == 0 &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_size == after.st_size &&
        after.st_dev == named.st_dev && after.st_ino == named.st_ino;
    close(fd);
    if (!valid || strlen(expected) != 64) return 0;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); i++) {
        if (expected[i * 2] != hex[digest[i] >> 4] || expected[i * 2 + 1] != hex[digest[i] & 15]) return 0;
    }
    return 1;
}

int prism_macos_install_helper(const char *source, const char *expected, char *output, int capacity) {
    if (!source || !expected || !output || capacity < 2) return -1;
    output[0] = 0;
    if (!trusted_directory("/") || !trusted_directory("/Library")) return -1;
    AuthorizationRef auth = NULL;
    if (AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &auth) != errAuthorizationSuccess) return -1;
    AuthorizationItem item = {kAuthorizationRightExecute, 0, NULL, 0};
    AuthorizationRights rights = {1, &item};
    OSStatus status = AuthorizationCopyRights(auth, &rights, kAuthorizationEmptyEnvironment,
        kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights, NULL);
    if (status != errAuthorizationSuccess) { AuthorizationFree(auth, kAuthorizationFlagDefaults); return -2; }
    struct stat meta;
    int created = 0;
    if (lstat("/Library/PrivilegedHelperTools", &meta) != 0) {
        if (errno != ENOENT) { AuthorizationFree(auth, 0); return -3; }
        char *args[] = {"-d", "-m", "755", "/Library/PrivilegedHelperTools", NULL};
        if (run_system_tool(auth, "/usr/bin/install", args) != 0) { AuthorizationFree(auth, 0); return -3; }
    }
    if (!trusted_directory("/Library/PrivilegedHelperTools")) { AuthorizationFree(auth, 0); return -3; }
    if (lstat(destination, &meta) != 0) {
        if (errno != ENOENT) { AuthorizationFree(auth, 0); return -3; }
        char *args[] = {"-m", "755", (char *)source, (char *)destination, NULL};
        created = 1;
        if (run_system_tool(auth, "/usr/bin/install", args) != 0) {
            (void)remove_temporary_installer(auth); AuthorizationFree(auth, 0); return -3;
        }
    }
    if (!verified_protected_installer(expected)) {
        if (created) (void)remove_temporary_installer(auth);
        AuthorizationFree(auth, 0); return -3;
    }
    char pid[32];
    if (snprintf(pid, sizeof(pid), "%ld", (long)getpid()) <= 0) { AuthorizationFree(auth, 0); return -1; }
    char *args[] = {"--client-pid", pid, NULL};
    FILE *pipe = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    status = AuthorizationExecuteWithPrivileges(auth, destination, kAuthorizationFlagDefaults, args, &pipe);
#pragma clang diagnostic pop
    if (status != errAuthorizationSuccess || !pipe) {
        if (created) (void)remove_temporary_installer(auth);
        AuthorizationFree(auth, 0); return -3;
    }
    size_t used = 0, limit = (size_t)capacity - 1;
    int failed = 0;
    while (used < limit) {
        ssize_t n = read(fileno(pipe), output + used, limit - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { failed = 1; break; }
        if (n == 0) break;
        used += (size_t)n;
    }
    output[used] = 0;
    if (used == limit) failed = 1;
    fclose(pipe);
    if (failed) { AuthorizationFree(auth, kAuthorizationFlagDefaults); return -5; }
    /* Do not remove an unknown replacement, even with administrator rights. */
    int cleanup = verified_protected_installer(expected) ? remove_temporary_installer(auth) : -1;
    AuthorizationFree(auth, kAuthorizationFlagDefaults);
    if (cleanup != 0) return -5;
    return !failed && strcmp(output, "PRISM_INSTALL_OK\n") == 0 ? 0 : -4;
}
