#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

// The caller has already authenticated the XPC peer. Transfer one socket to
// the guard; an acknowledgement confirms the guard accepted it. No JSON or
// sensitive data is sent until this succeeds.
int prism_bridge_send_fd(int channel, int descriptor) {
    char byte = 'F';
    struct iovec io = { .iov_base = &byte, .iov_len = 1 };
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
    struct msghdr msg = {0};
    msg.msg_iov = &io; msg.msg_iovlen = 1;
    msg.msg_control = control.bytes; msg.msg_controllen = sizeof(control.bytes);
    struct cmsghdr *header = CMSG_FIRSTHDR(&msg);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
    if (sendmsg(channel, &msg, 0) != 1) return -1;
    char reply = 0;
    if (read(channel, &reply, 1) != 1 || reply != 'A') return -1;
    return 0;
}
