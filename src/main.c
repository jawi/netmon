/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <poll.h>
#include <pthread.h>

#include "config.h"
#include "logging.h"
#include "mqtt.h"
#include "netlink.h"
#include "netmon.h"
#include "util.h"

#define ERR_UNKNOWN 1
#define ERR_PIPE 10
#define ERR_FORK 11
#define ERR_PIPE_READ 12
#define ERR_SETSID 20
#define ERR_DAEMONIZE 21
#define ERR_DEV_NULL 22
#define ERR_PID_FILE 23
#define ERR_CONFIG 24
#define ERR_CHDIR 25
#define ERR_DROP_PRIVS 26

typedef struct event_queue_item {
    struct event_queue_item *next;
    event_t *event;
} event_queue_item_t;

enum events {
    EVENT_TERM = 1,
    EVENT_DUMP = 2,
    EVENT_RELOAD = 3,
};

enum fds {
    FD_EVENTS = 0,
    FD_NETLINK = 1,
    FD_MQTT = 2,
    _FD_MAX,
};

typedef struct state {
    bool loop;
    config_t *config;

    int event_write_fd;

    event_queue_item_t *event_queue;

    struct pollfd fds[_FD_MAX];
} run_state_t;

static run_state_t run_state = { 0 };

/**
 * Netlink callback called for every Netlink event.
 */
static void netlink_event_callback(event_t *event) {
    event_queue_item_t *item = malloc(sizeof(event_queue_item_t));
    item->next = run_state.event_queue;
    item->event = event;
    run_state.event_queue = item;
}

static event_t *pop_event_queue(void) {
    event_queue_item_t *ptr = run_state.event_queue;
    event_t *event = NULL;

    if (ptr) {
        event_queue_item_t *prev = NULL;
        while (ptr->next) {
            prev = ptr;
            ptr = ptr->next;
        }

        if (ptr) {
            event = ptr->event;
            // consume event_queue_item item...
            if (prev) {
                prev->next = NULL;
            } else {
                run_state.event_queue = NULL;
            }
            free(ptr);
        }
    }

    return event;
}

static void flush_event_queue(void) {
    event_queue_item_t *ptr = run_state.event_queue;

    while (ptr) {
        event_queue_item_t *item = ptr;
        ptr = ptr->next;

        free_event(item->event);
        free(item);
    }
}

#define SAFE_SIGNAL(rc) \
    int _rc = rc; \
    if (write(err_pipe[1], &_rc, 1) != 1) { \
        log_warning("failed to write single byte to pipe!"); \
    } \
    close(err_pipe[1]);

#define SIGNAL_SUCCESS() \
	do { \
        SAFE_SIGNAL(0) \
	} while (0)

#define SIGNAL_FAILURE(rc) \
	do { \
        SAFE_SIGNAL(rc) \
		exit(rc); \
	} while (0)

static int daemonize(const char *pid_file, uid_t uid, gid_t gid) {
    // create a anonymous pipe to communicate between daemon and our parent...
    int err_pipe[2] = { 0 };
    if (pipe(err_pipe) < 0) {
        perror("pipe");
        return ERR_PIPE;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return ERR_FORK;
    } else if (pid > 0) {
        // parent, wait until daemon is finished initializing...
        close(err_pipe[1]);

        int rc = 0;
        if (read(err_pipe[0], &rc, 1) < 0) {
            rc = ERR_PIPE_READ;
        }
        exit(rc);
    } else { /* pid == 0 */
        // first child continues here...
        // NOTE: we can/should communicate our state to our parent in order for it to terminate!

        // we only write to this pipe...
        close(err_pipe[0]);

        // create a new session...
        pid = setsid();
        if (pid < 0) {
            SIGNAL_FAILURE(ERR_SETSID);
        }

        // fork again to ensure the daemon cannot take back the controlling tty...
        pid = fork();
        if (pid < 0) {
            SIGNAL_FAILURE(ERR_DAEMONIZE);
        } else if (pid > 0) {
            // terminate first child...
            exit(0);
        } else { /* pid == 0 */
            // actual daemon starts here...
            int fd;

            if ((fd = open("/dev/null", O_RDWR)) < 0) {
                log_error("unable to open /dev/null: %s", strerror(errno));
                SIGNAL_FAILURE(ERR_DEV_NULL);
            } else {
                dup2(fd, STDIN_FILENO);
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                close(fd);
            }

            umask(0);

            if (chdir("/") != 0) {
                log_error("unable to change directory: %m");
                SIGNAL_FAILURE(ERR_CHDIR);
            }

            if (write_pidfile(pid_file, uid, gid)) {
                SIGNAL_FAILURE(ERR_PID_FILE);
            }

            if (drop_privileges(uid, gid)) {
                SIGNAL_FAILURE(ERR_DROP_PRIVS);
            }

            // Finish startup...
            if (err_pipe[1] != -1) {
                SIGNAL_SUCCESS();
            }
        } /* daemon pid == 0 */
    } /* first child pid == 0 */

    return 0;
}

static void write_event(int fd, uint8_t event_type) {
    uint8_t buf[1] = { event_type };
    if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
        log_warning("Did not write all event data?!");
    }
}

static void signal_handler(int signo) {
    if (signo == SIGTERM || signo == SIGINT) {
        write_event(run_state.event_write_fd, EVENT_TERM);
    } else if (signo == SIGHUP) {
        write_event(run_state.event_write_fd, EVENT_RELOAD);
    } else if (signo == SIGUSR1) {
        write_event(run_state.event_write_fd, EVENT_DUMP);
    } else {
        log_debug("Unknown/unhandled signal: %d", signo);
    }
}

static void install_signal_handlers(void) {
    struct sigaction sigact;

    sigact.sa_handler = signal_handler;
    sigact.sa_flags = 0;

    sigemptyset(&sigact.sa_mask);

    sigaction(SIGUSR1, &sigact, NULL);
    sigaction(SIGUSR2, &sigact, NULL);
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGALRM, &sigact, NULL);
    sigaction(SIGCHLD, &sigact, NULL);
    sigaction(SIGINT, &sigact, NULL);

    // Ignore SIGPIPE
    sigact.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sigact, NULL);
}

static void dump_config(config_t *config) {
    log_debug("Using configuration:");
    log_debug("- daemon user/group: %d/%d", config->priv_user, config->priv_group);
    log_debug("- MQTT server: %s:%d", config->host, config->port);
    log_debug("  - client ID: %s", config->client_id);
    log_debug("  - MQTT QoS: %d", config->qos);
    log_debug("  - retain messages: %s", config->retain ? "yes" : "no");
    if (config->use_auth) {
        log_debug("  - using client credentials");
    }
    if (config->use_tls) {
        log_debug("- using TLS options:");
        log_debug("  - use TLS version: %s", config->tls_version);
        if (config->cacertpath) {
            log_debug("  - CA cert path: %s", config->cacertpath);
        }
        if (config->cacertfile) {
            log_debug("  - CA cert file: %s", config->cacertfile);
        }
        if (config->certfile) {
            log_debug("  - using client certificate: %s", config->certfile);
        }
        log_debug("  - verify peer: %s", config->verify_peer ? "yes" : "no");
        if (config->ciphers) {
            log_debug("  - cipher suite: %s", config->ciphers);
        }
    }
}

int main(int argc, char *argv[]) {
    const nfds_t nfds = _FD_MAX;

    int event_pipe[2] = { 0, 0 };
    netlink_handle_t *nl_handle = { 0 };
    mqtt_handle_t *mqtt_handle = { 0 };

    // parse arguments...
    char *conf_file = NULL;
    char *pid_file = NULL;

    bool foreground = false;
    bool debug = false;
    int opt;

    while ((opt = getopt(argc, argv, "c:dfhp:v")) != -1) {
        switch (opt) {
        case 'c':
            conf_file = strdup(optarg);
            break;
        case 'd':
            debug = true;
            break;
        case 'f':
            foreground = true;
            break;
        case 'p':
            pid_file = strdup(optarg);
            break;
        case 'v':
        case 'h':
        default:
            fprintf(stderr, PNAME " v" VERSION "\n");
            if (opt == 'v') {
                exit(0);
            }
            fprintf(stderr, "Usage: %s [-d] [-f] [-c config file] [-p pid file] [-v]\n", PNAME);
            exit(1);
        }
    }

    if (!conf_file) {
        conf_file = strdup(CONF_FILE);
    }
    if (!pid_file) {
        pid_file = strdup(PID_FILE);
    }

    // close any file descriptors we inherited...
    const long max_fd = sysconf(_SC_OPEN_MAX);
    for (int fd = 3; fd < max_fd; fd++) {
        close(fd);
    }
    // do this *after* we've closed the file descriptors!
    init_logging(debug, foreground);

    // install the signal handling routine
    install_signal_handlers();

    run_state.config = read_config(conf_file);

    // Sanity check; make sure we've got a valid configuration at hand...
    if (run_state.config == NULL) {
        goto cleanup;
    }

    dump_config(run_state.config);

    if (!foreground) {
        int retval = daemonize(pid_file, run_state.config->priv_user, run_state.config->priv_group);
        if (retval) {
            exit(retval);
        }
    }

    // Netlink initialization...
    nl_handle = init_netlink(netlink_event_callback);
    if (!nl_handle) {
        log_warning("Netlink initialization failed!");
        return -1;
    }

    // MQTT initialization...
    mqtt_handle = init_mqtt();
    if (!mqtt_handle) {
        log_warning("MQTT initialization failed!");
        return -1;
    }

    // allow events to be sent through a pipe...
    if (pipe(event_pipe) < 0) {
        perror("pipe");
        return ERR_PIPE;
    }

    // Keep track of the writing side...
    run_state.event_write_fd = event_pipe[1];

    // Prepare the netlink connection...
    if (connect_netlink(nl_handle)) {
        log_warning("netlink connection failed!");
        return -1;
    }

    // Prepare the MQTT connection...
    if (connect_mqtt(mqtt_handle, run_state.config)) {
        log_warning("MQTT connection failed!");
        return -1;
    }

    run_state.loop = true;

    while (run_state.loop) {
        // Re-initialize the events we're interested in...
        run_state.fds[FD_EVENTS].fd = event_pipe[0];
        run_state.fds[FD_EVENTS].events = POLLIN;

        run_state.fds[FD_NETLINK].fd = netlink_fd(nl_handle);
        run_state.fds[FD_NETLINK].events = POLLIN;

        run_state.fds[FD_MQTT].fd = mqtt_fd(mqtt_handle);
        run_state.fds[FD_MQTT].events = POLLIN;
        if (mqtt_wants_to_write(mqtt_handle)) {
            run_state.fds[FD_MQTT].events |= POLLOUT;
        }

        int count = poll(run_state.fds, nfds, 100);
        if (count < 0) {
            if (errno == EINTR) {
                log_debug("poll was interrupted by system signal; ignoring...");
            } else {
                log_warning("failed to poll: %m");
                break;
            }
        } else if (count > 0) {
            // There was something of interest; let's look a little closer...
            if (run_state.fds[FD_NETLINK].revents) {
                int16_t revents = run_state.fds[FD_NETLINK].revents;
                if (revents & POLLIN) {
                    log_debug("got netlink data to read...");

                    if (netlink_read_data(nl_handle)) {
                        log_warning("failed to read netlink data!");
                    }
                } else if (revents & (POLLHUP | POLLERR)) {
                    log_warning("netlink connection dropped!");
                }
            } else if (run_state.fds[FD_EVENTS].revents) {
                int16_t revents = run_state.fds[FD_EVENTS].revents;
                if (revents & POLLIN) {
                    log_debug("got event data to read...");

                    uint8_t buf[1] = { 0 };
                    if (read(event_pipe[FD_EVENTS], &buf, sizeof(buf)) != sizeof(buf)) {
                        log_warning("Did not read all event data?!");
                        continue;
                    }

                    switch (buf[0]) {
                    case EVENT_TERM:
                        run_state.loop = false;
                        break;

                    case EVENT_RELOAD:
                        log_debug("Reloading...");
                        config_t *new_config = read_config(conf_file);

                        // Sanity check; make sure we've got a valid configuration at hand...
                        if (new_config == NULL) {
                            run_state.loop = false;
                        } else {
                            // reconnect using the new configuration...
                            disconnect_mqtt(mqtt_handle);

                            dump_config(new_config);

                            free_config(run_state.config);
                            run_state.config = new_config;

                            connect_mqtt(mqtt_handle, run_state.config);
                        }
                        break;

                    case EVENT_DUMP:
                        netlink_dump_data(nl_handle);
                        break;

                    default:
                        log_debug("Unknown event received: %d", buf[0]);
                        break;
                    }
                } else if (revents & (POLLHUP | POLLERR)) {
                    log_warning("Event connection dropped! Terminating...");
                    run_state.loop = false;
                }
            } else if (run_state.fds[FD_MQTT].revents) {
                int16_t revents = run_state.fds[FD_MQTT].revents;
                if (revents & POLLIN) {
                    log_debug("got MQTT data to read...");

                    if (mqtt_read_data(mqtt_handle)) {
                        log_warning("unable to read MQTT data!");
                    }
                } else if (revents & POLLOUT) {
                    log_debug("got MQTT data to write...");

                    if (mqtt_write_data(mqtt_handle)) {
                        log_warning("unable to write MQTT data!");
                    }
                } else if (revents & (POLLHUP | POLLERR)) {
                    log_warning("MQTT connection dropped!");
                }
            }
        }

        // Update MQTTs internal administration...
        mqtt_update_administration(mqtt_handle);

        event_t *event = pop_event_queue();
        if (event != NULL) {
            if (publish_mqtt(mqtt_handle, event) == 0) {
                // Clean up the resources...
                free_event(event);
            }
        }
    }

    log_info(PNAME " terminating.");

cleanup:
    disconnect_netlink(nl_handle);
    disconnect_mqtt(mqtt_handle);

    flush_event_queue();

    // Close our local resources...
    close(event_pipe[0]);
    close(event_pipe[1]);

    destroy_netlink(nl_handle);
    destroy_mqtt(mqtt_handle);
    destroy_logging();

    free_config(run_state.config);

    // best effort; will only succeed if the permissions are set correctly...
    unlink(pid_file);

    free(conf_file);
    free(pid_file);

    return 0;
}
