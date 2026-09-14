/* The guest terminal structure uses the Linux ABI. */
_Static_assert(sizeof(struct termios) == sizeof(struct bridge_termios), "termios layout");
pid_t getpgid(pid_t pid) {
    return bridge(BR_GETPGID, pid, 0, 0);
}
pid_t getpgrp(void) {
    return getpgid(0);
}
int setpgid(pid_t pid, pid_t group) {
    return bridge(BR_SETPGID, pid, group, 0);
}
int setpgrp(void) {
    return setpgid(0, 0);
}
pid_t setsid(void) {
    return bridge(BR_SETSID, 0, 0, 0);
}
pid_t tcgetpgrp(int fd) {
    return bridge(BR_TCGETPGRP, fd, 0, 0);
}
int tcsetpgrp(int fd, pid_t group) {
    return bridge(BR_TCSETPGRP, fd, group, 0);
}
int tcgetattr(int fd, struct termios *t) {
    return bridge(BR_TCGETATTR, fd, (uintptr_t)t, 0);
}
int tcsetattr(int fd, int action, const struct termios *t) {
    return bridge(BR_TCSETATTR, fd, (uintptr_t)t, action);
}
char *ttyname(int fd) {
    static char name[4096];
    return bridge(BR_TTYNAME, fd, (uintptr_t)name, sizeof(name)) < 0 ? NULL : name;
}
speed_t cfgetospeed(const struct termios *t) {
    return t->c_cflag & CBAUD;
}
speed_t cfgetispeed(const struct termios *t) {
    return t->c_ispeed;
}
int cfsetospeed(struct termios *t, speed_t speed) {
    if (speed & ~CBAUD) {
        errno = EINVAL;
        return -1;
    }
    t->c_cflag = (t->c_cflag & ~CBAUD) | speed;
    t->c_ospeed = speed;
    return 0;
}
int cfsetispeed(struct termios *t, speed_t speed) {
    if (speed & ~CBAUD) {
        errno = EINVAL;
        return -1;
    }
    t->c_ispeed = speed;
    return 0;
}
int cfsetspeed(struct termios *t, speed_t speed) {
    return cfsetospeed(t, speed) || cfsetispeed(t, speed) ? -1 : 0;
}
void cfmakeraw(struct termios *t) {
    t->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    t->c_oflag &= ~OPOST;
    t->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    t->c_cflag = (t->c_cflag & ~(CSIZE | PARENB)) | CS8;
    t->c_cc[VMIN] = 1;
    t->c_cc[VTIME] = 0;
}
